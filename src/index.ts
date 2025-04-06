#!/usr/bin/env node

/**
 * Firebase MCP Server
 * 
 * This server implements the Model Context Protocol (MCP) for Firebase services.
 * It provides tools for interacting with Firebase Authentication, Firestore, and Storage
 * through a standardized interface that can be used by AI assistants and other MCP clients.
 * 
 * @module firebase-mcp
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { CallToolRequestSchema, ListToolsRequestSchema, ErrorCode, McpError } from '@modelcontextprotocol/sdk/types.js';
import * as admin from 'firebase-admin';
import { logger } from './utils/logger.js';

// Add these interfaces at the top of the file, after the imports
interface FilterCondition {
  field: string;
  operator: admin.firestore.WhereFilterOp;
  value: any;
}

interface OrderByCondition {
  field: string;
  direction?: 'asc' | 'desc';
}

interface ListDocumentsArgs extends Record<string, unknown> {
  collection: string;
  filters?: FilterCondition[];
  orderBy?: OrderByCondition[];
  limit?: number;
  pageToken?: string;
}

interface AddDocumentArgs extends Record<string, unknown> {
  collection: string;
  data: Record<string, any>;
}

// Type guard functions
function isAddDocumentArgs(args: Record<string, unknown>): args is AddDocumentArgs {
  return typeof args.collection === 'string' && 
         typeof args.data === 'object' && 
         args.data !== null;
}

function isListDocumentsArgs(args: Record<string, unknown>): args is ListDocumentsArgs {
  return typeof args.collection === 'string';
}

// Initialize Firebase
function initializeFirebase() {
  logger.info('=== Firebase MCP Server Initialization ===');
  
  // Log all environment variables related to Firebase
  const firebaseEnvVars = {
    USE_FIREBASE_EMULATOR: process.env.USE_FIREBASE_EMULATOR,
    FIRESTORE_EMULATOR_HOST: process.env.FIRESTORE_EMULATOR_HOST,
    FIREBASE_AUTH_EMULATOR_HOST: process.env.FIREBASE_AUTH_EMULATOR_HOST,
    FIREBASE_STORAGE_EMULATOR_HOST: process.env.FIREBASE_STORAGE_EMULATOR_HOST,
    NODE_ENV: process.env.NODE_ENV,
    SERVICE_ACCOUNT_KEY_PATH: process.env.SERVICE_ACCOUNT_KEY_PATH,
    FIREBASE_STORAGE_BUCKET: process.env.FIREBASE_STORAGE_BUCKET
  };
  
  logger.info('Firebase Environment Variables:', firebaseEnvVars);
  
  try {
    const serviceAccountPath = process.env.SERVICE_ACCOUNT_KEY_PATH;
    if (!serviceAccountPath) {
      logger.error('SERVICE_ACCOUNT_KEY_PATH not set');
      return null;
    }
    
    // Enhanced emulator detection
    const useEmulator = process.env.USE_FIREBASE_EMULATOR === 'true';
    const hasEmulatorHosts = !!(process.env.FIRESTORE_EMULATOR_HOST || 
                               process.env.FIREBASE_AUTH_EMULATOR_HOST || 
                               process.env.FIREBASE_STORAGE_EMULATOR_HOST);
    
    logger.info('Emulator Configuration:', {
      USE_FIREBASE_EMULATOR: process.env.USE_FIREBASE_EMULATOR,
      useEmulator: useEmulator,
      hasEmulatorHosts: hasEmulatorHosts,
      emulatorHosts: {
        firestore: process.env.FIRESTORE_EMULATOR_HOST || 'not set',
        auth: process.env.FIREBASE_AUTH_EMULATOR_HOST || 'not set',
        storage: process.env.FIREBASE_STORAGE_EMULATOR_HOST || 'not set'
      }
    });

    if (useEmulator) {
      logger.info('Emulator mode is enabled via USE_FIREBASE_EMULATOR flag');
      if (!hasEmulatorHosts) {
        logger.warn('Emulator mode is enabled but no emulator hosts are configured. Using defaults:');
        // Set default emulator hosts if not set
        if (!process.env.FIRESTORE_EMULATOR_HOST) {
          process.env.FIRESTORE_EMULATOR_HOST = 'localhost:8080';
          logger.info('Set default Firestore emulator host: localhost:8080');
        }
        if (!process.env.FIREBASE_AUTH_EMULATOR_HOST) {
          process.env.FIREBASE_AUTH_EMULATOR_HOST = 'localhost:9099';
          logger.info('Set default Auth emulator host: localhost:9099');
        }
        if (!process.env.FIREBASE_STORAGE_EMULATOR_HOST) {
          process.env.FIREBASE_STORAGE_EMULATOR_HOST = 'localhost:9199';
          logger.info('Set default Storage emulator host: localhost:9199');
        }
      }
    } else if (hasEmulatorHosts) {
      logger.warn('Emulator hosts are set but USE_FIREBASE_EMULATOR is not "true". Emulator mode will not be used.');
    }

    try {
      const existingApp = admin.app();
      if (existingApp) {
        logger.debug('Using existing Firebase app');
        return existingApp;
      }
    } catch (error) {
      logger.debug('No existing Firebase app, initializing new one');
    }

    const serviceAccount = require(serviceAccountPath);
    const storageBucket = process.env.FIREBASE_STORAGE_BUCKET;
    
    // Log initialization details
    logger.info('Initializing Firebase with configuration:', {
      projectId: serviceAccount.project_id,
      clientEmail: serviceAccount.client_email,
      storageBucket: storageBucket,
      emulatorMode: useEmulator,
      environment: process.env.NODE_ENV || 'not set'
    });

    // Configure emulators if enabled
    if (useEmulator) {
      logger.info('Connecting to Firebase emulators:', {
        firestore: process.env.FIRESTORE_EMULATOR_HOST,
        auth: process.env.FIREBASE_AUTH_EMULATOR_HOST,
        storage: process.env.FIREBASE_STORAGE_EMULATOR_HOST
      });
      
      // Enable emulator connection
      process.env.FIREBASE_AUTH_EMULATOR_HOST = process.env.FIREBASE_AUTH_EMULATOR_HOST || 'localhost:9099';
      process.env.FIRESTORE_EMULATOR_HOST = process.env.FIRESTORE_EMULATOR_HOST || 'localhost:8080';
      process.env.FIREBASE_STORAGE_EMULATOR_HOST = process.env.FIREBASE_STORAGE_EMULATOR_HOST || 'localhost:9199';
    }

    const app = admin.initializeApp({
      credential: admin.credential.cert(serviceAccount),
      storageBucket: storageBucket
    });

    logger.info('Firebase initialization complete:', {
      mode: useEmulator ? 'emulator' : 'production',
      projectId: serviceAccount.project_id,
      emulatorHosts: useEmulator ? {
        firestore: process.env.FIRESTORE_EMULATOR_HOST,
        auth: process.env.FIREBASE_AUTH_EMULATOR_HOST,
        storage: process.env.FIREBASE_STORAGE_EMULATOR_HOST
      } : 'not using emulators'
    });

    return app;
  } catch (error) {
    logger.error('Failed to initialize Firebase', {
      error: error instanceof Error ? error.message : error,
      stack: error instanceof Error ? error.stack : undefined,
      envVars: firebaseEnvVars
    });
    return null;
  }
}

// Initialize Firebase
const app = initializeFirebase();

interface McpResponse {
  content: Array<{ type: string, text: string }>;
  isError?: boolean;
}

/**
 * Main server class that implements the MCP protocol for Firebase services.
 * Handles tool registration, request routing, and server lifecycle.
 */
class FirebaseMcpServer {
  /** The MCP server instance */
  private server: Server;

  /**
   * Initializes the Firebase MCP server with configuration and event handlers.
   */
  constructor() {
    this.server = new Server(
      {
        name: 'firebase-mcp',
        version: '0.1.0'
      },
      {
        capabilities: {
          tools: {}
        }
      }
    );

    this.setupToolHandlers();

    // Set up error handling and graceful shutdown
    this.server.onerror = () => {};
    process.on('SIGINT', async () => {
      await this.server.close();
      process.exit(0);
    });
  }

  /**
   * Registers all available Firebase tools with the MCP server.
   * This includes tools for Firestore, Authentication, and Storage operations.
   * @private
   */
  private setupToolHandlers() {
    // Register available tools
    this.server.setRequestHandler(ListToolsRequestSchema, async () => ({
      tools: [
        {
          name: 'firestore_add_document',
          description: 'Add a document to a Firestore collection',
          inputSchema: {
            type: 'object',
            properties: {
              collection: {
                type: 'string',
                description: 'Collection name'
              },
              data: {
                type: 'object',
                description: 'Document data'
              }
            },
            required: ['collection', 'data']
          }
        },
        {
          name: 'firestore_list_documents',
          description: 'List documents from a Firestore collection with filtering and ordering',
          inputSchema: {
            type: 'object',
            properties: {
              collection: {
                type: 'string',
                description: 'Collection name'
              },
              filters: {
                type: 'array',
                description: 'Array of filter conditions',
                items: {
                  type: 'object',
                  properties: {
                    field: {
                      type: 'string',
                      description: 'Field name to filter'
                    },
                    operator: {
                      type: 'string',
                      description: 'Comparison operator (==, >, <, >=, <=, array-contains, in, array-contains-any)'
                    },
                    value: {
                      type: 'string',
                      description: 'Value to compare against (use ISO format for dates)'
                    }
                  },
                  required: ['field', 'operator', 'value']
                }
              },
              limit: {
                type: 'number',
                description: 'Number of documents to return',
                default: 20
              },
              pageToken: {
                type: 'string',
                description: 'Token for pagination to get the next page of results'
              },
              orderBy: {
                type: 'array',
                description: 'Array of fields to order by',
                items: {
                  type: 'object',
                  properties: {
                    field: {
                      type: 'string',
                      description: 'Field name to order by'
                    },
                    direction: {
                      type: 'string',
                      description: 'Sort direction (asc or desc)',
                      enum: ['asc', 'desc'],
                      default: 'asc'
                    }
                  },
                  required: ['field']
                }
              }
            },
            required: ['collection']
          }
        },
        {
          name: 'firestore_get_document',
          description: 'Get a document from a Firestore collection',
          inputSchema: {
            type: 'object',
            properties: {
              collection: {
                type: 'string',
                description: 'Collection name'
              },
              id: {
                type: 'string',
                description: 'Document ID'
              }
            },
            required: ['collection', 'id']
          }
        },
        {
          name: 'firestore_update_document',
          description: 'Update a document in a Firestore collection',
          inputSchema: {
            type: 'object',
            properties: {
              collection: {
                type: 'string',
                description: 'Collection name'
              },
              id: {
                type: 'string',
                description: 'Document ID'
              },
              data: {
                type: 'object',
                description: 'Updated document data'
              }
            },
            required: ['collection', 'id', 'data']
          }
        },
        {
          name: 'firestore_delete_document',
          description: 'Delete a document from a Firestore collection',
          inputSchema: {
            type: 'object',
            properties: {
              collection: {
                type: 'string',
                description: 'Collection name'
              },
              id: {
                type: 'string',
                description: 'Document ID'
              }
            },
            required: ['collection', 'id']
          }
        },
        {
          name: 'auth_get_user',
          description: 'Get a user by ID or email from Firebase Authentication',
          inputSchema: {
            type: 'object',
            properties: {
              identifier: {
                type: 'string',
                description: 'User ID or email address'
              }
            },
            required: ['identifier']
          }
        },
        {
          name: 'storage_list_files',
          description: 'List files in a given path in Firebase Storage',
          inputSchema: {
            type: 'object',
            properties: {
              directoryPath: {
                type: 'string',
                description: 'The optional path to list files from. If not provided, the root is used.'
              }
            },
            required: []
          }
        },
        {
          name: 'storage_get_file_info',
          description: 'Get file information including metadata and download URL',
          inputSchema: {
            type: 'object',
            properties: {
              filePath: {
                type: 'string',
                description: 'The path of the file to get information for'
              }
            },
            required: ['filePath']
          }
        },
        {
          name: 'firestore_list_collections',
          description: 'List root collections in Firestore',
          inputSchema: {
            type: 'object',
            properties: {},
            required: []
          }
        },
        {
          name: 'firestore_query_collection_group',
          description: 'Query documents across all subcollections with the same name (collection group query)',
          inputSchema: {
            type: 'object',
            properties: {
              collectionId: {
                type: 'string',
                description: 'The collection ID to query across all documents (without parent path)'
              },
              filters: {
                type: 'array',
                description: 'Optional filters to apply to the query',
                items: {
                  type: 'object',
                  properties: {
                    field: { 
                      type: 'string',
                      description: 'Field name to filter' 
                    },
                    operator: { 
                      type: 'string', 
                      description: 'Comparison operator (==, !=, <, <=, >, >=, array-contains, array-contains-any, in, not-in)' 
                    },
                    value: { 
                      type: 'string',
                      description: 'Value to compare against' 
                    }
                  },
                  required: ['field', 'operator', 'value']
                }
              },
              orderBy: {
                type: 'array',
                description: 'Optional fields to order results by',
                items: {
                  type: 'object',
                  properties: {
                    field: { 
                      type: 'string',
                      description: 'Field name to order by' 
                    },
                    direction: { 
                      type: 'string', 
                      enum: ['asc', 'desc'],
                      default: 'asc',
                      description: 'Sort direction (asc or desc)'
                    }
                  },
                  required: ['field']
                }
              },
              limit: {
                type: 'number',
                description: 'Maximum number of documents to return (default: 20, max: 100)'
              },
              pageToken: {
                type: 'string',
                description: 'Token for pagination (document path to start after)'
              }
            },
            required: ['collectionId']
          }
        }
      ]
    }));

    // Handle tool execution
    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const { name, arguments: args = {} } = request.params;
      const startTime = Date.now();
      
      logger.info(`=== API Call: ${name} ===`, {
        timestamp: new Date().toISOString(),
        args: args
      });

      try {
        if (!app) {
          logger.error('Firebase not initialized');
          return {
            content: [{
              type: 'text',
              text: JSON.stringify({
                error: 'Firebase initialization failed'
              })
            }]
          };
        }

        switch (name) {
          case 'firestore_add_document': {
            if (!isAddDocumentArgs(args)) {
              throw new Error('Invalid arguments for firestore_add_document');
            }
            
            const { collection, data } = args;
            logger.debug(`Adding document to collection: ${collection}`, {
              dataSize: JSON.stringify(data).length
            });
            
            const docRef = await admin.firestore().collection(collection).add(data);
            const duration = Date.now() - startTime;
            
            logger.info(`Document added successfully`, {
              collection,
              docId: docRef.id,
              duration: `${duration}ms`
            });
            
            return {
              content: [{
                type: 'text',
                text: JSON.stringify({
                  id: docRef.id,
                  path: docRef.path
                })
              }]
            };
          }

          case 'firestore_list_documents': {
            if (!isListDocumentsArgs(args)) {
              throw new Error('Invalid arguments for firestore_list_documents');
            }
            
            const { collection, filters, orderBy, limit: rawLimit, pageToken } = args;
            const limit = Math.min(Math.max(1, rawLimit || 20), 100);
            
            logger.debug(`Listing documents from collection: ${collection}`, {
              limit,
              filters,
              orderBy
            });
            
            let query: admin.firestore.Query = admin.firestore().collection(collection);
            
            if (filters && filters.length > 0) {
              filters.forEach(filter => {
                query = query.where(filter.field, filter.operator, filter.value);
                logger.debug(`Applied filter:`, filter);
              });
            }

            if (orderBy && orderBy.length > 0) {
              orderBy.forEach(order => {
                query = query.orderBy(order.field, order.direction || 'asc');
                logger.debug(`Applied ordering:`, order);
              });
            }

            if (pageToken) {
              const lastDoc = await admin.firestore().doc(pageToken).get();
              if (lastDoc.exists) {
                query = query.startAfter(lastDoc);
                logger.debug(`Applied pagination from token: ${pageToken}`);
              }
            }

            query = query.limit(limit);
            const snapshot = await query.get();
            const duration = Date.now() - startTime;
            
            logger.info(`Documents retrieved successfully`, {
              collection,
              count: snapshot.size,
              duration: `${duration}ms`
            });

            const documents = snapshot.docs.map(doc => {
              const data = doc.data();
              return {
                id: doc.id,
                path: doc.ref.path,
                data
              };
            });

            const totalSize = JSON.stringify(documents).length;
            logger.debug(`Response metrics:`, {
              documentCount: documents.length,
              totalSizeBytes: totalSize,
              averageSizeBytes: Math.round(totalSize / documents.length)
            });

            const lastVisible = snapshot.docs[snapshot.docs.length - 1];
            const nextPageToken = lastVisible ? lastVisible.ref.path : null;

            return {
              content: [{
                type: 'text',
                text: JSON.stringify({
                  documents,
                  nextPageToken
                })
              }]
            };
          }

          case 'firestore_get_document': {
            const collection = args.collection as string;
            const id = args.id as string;
            
            const docRef = admin.firestore().collection(collection).doc(id);
            const doc = await docRef.get();
            
            if (!doc.exists) {
              return {
                content: [{
                  type: 'text',
                  text: JSON.stringify({
                    error: 'Document not found'
                  })
                }]
              };
            }

            const rawData = doc.data();
            // Sanitize data to ensure it's JSON-serializable
            const data = Object.entries(rawData || {}).reduce((acc, [key, value]) => {
              if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean' || value === null) {
                acc[key] = value;
              } else if (value instanceof Date) {
                acc[key] = value.toISOString();
              } else if (Array.isArray(value)) {
                acc[key] = `[${value.join(', ')}]`;
              } else if (typeof value === 'object') {
                acc[key] = '[Object]';
              } else {
                acc[key] = String(value);
              }
              return acc;
            }, {} as Record<string, any>);

            return {
              content: [{
                type: 'text',
                text: JSON.stringify({
                  id: doc.id,
                  path: doc.ref.path,
                  data
                })
              }]
            };
          }

          case 'firestore_update_document': {
            const collection = args.collection as string;
            const id = args.id as string;
            const data = args.data as Record<string, any>;
            
            const docRef = admin.firestore().collection(collection).doc(id);
            await docRef.update(data);
            
            return {
              content: [{
                type: 'text',
                text: JSON.stringify({
                  id,
                  path: docRef.path,
                  updated: true
                })
              }]
            };
          }

          case 'firestore_delete_document': {
            const collection = args.collection as string;
            const id = args.id as string;
            
            const docRef = admin.firestore().collection(collection).doc(id);
            await docRef.delete();
            
            return {
              content: [{
                type: 'text',
                text: JSON.stringify({
                  id,
                  path: docRef.path,
                  deleted: true
                })
              }]
            };
          }

          case 'auth_get_user': {
            const identifier = args.identifier as string;
            
            try {
              let user;
              // Try to get user by email first
              if (identifier.includes('@')) {
                const userByEmail = await admin.auth().getUserByEmail(identifier);
                user = userByEmail;
              } else {
                // If not an email, try by UID
                const userById = await admin.auth().getUser(identifier);
                user = userById;
              }

              // Sanitize user data to ensure it's JSON-serializable
              const sanitizedUser = {
                uid: user.uid,
                email: user.email,
                emailVerified: user.emailVerified,
                displayName: user.displayName,
                photoURL: user.photoURL,
                disabled: user.disabled,
                metadata: {
                  creationTime: user.metadata.creationTime,
                  lastSignInTime: user.metadata.lastSignInTime
                }
              };

              return {
                content: [{
                  type: 'text',
                  text: JSON.stringify({ user: sanitizedUser })
                }]
              };
            } catch (error) {
              return {
                content: [{
                  type: 'text',
                  text: JSON.stringify({
                    error: 'User not found',
                    details: error instanceof Error ? error.message : 'Unknown error'
                  })
                }]
              };
            }
          }

          case 'storage_list_files': {
            const directoryPath = (args.directoryPath as string) || '';
            
            try {
              logger.debug(`Listing files in directory: ${directoryPath}`);
              const bucket = admin.storage().bucket();
              logger.debug(`Got bucket reference: ${bucket.name}`);

              const [files] = await bucket.getFiles({
                prefix: directoryPath,
                delimiter: '/'
              });

              logger.debug(`Found ${files.length} files`);

              const fileList = files.map(file => ({
                name: file.name,
                size: file.metadata.size ? file.metadata.size : '0',
                contentType: file.metadata.contentType || null,
                updated: file.metadata.updated || null,
                md5Hash: file.metadata.md5Hash || null
              }));

              return {
                content: [{
                  type: 'text',
                  text: JSON.stringify({ files: fileList }, null, 2)
                }]
              };
            } catch (error) {
              logger.error('Failed to list files', error);
              return {
                content: [{
                  type: 'text',
                  text: JSON.stringify({
                    error: 'Failed to list files',
                    details: error instanceof Error ? error.message : 'Unknown error'
                  })
                }]
              };
            }
          }

          case 'storage_get_file_info': {
            const filePath = args.filePath as string;
            
            try {
              logger.debug(`Getting info for file: ${filePath}`);
              const bucket = admin.storage().bucket();
              logger.debug(`Got bucket reference: ${bucket.name}`);
              
              const file = bucket.file(filePath);
              const [exists] = await file.exists();
              
              if (!exists) {
                logger.warn(`File not found: ${filePath}`);
                return {
                  content: [{
                    type: 'text',
                    text: JSON.stringify({
                      error: 'File not found'
                    }, null, 2)
                  }]
                };
              }

              logger.debug('File exists, getting metadata and signed URL');
              const [metadata] = await file.getMetadata();
              const [url] = await file.getSignedUrl({
                action: 'read',
                expires: Date.now() + 15 * 60 * 1000 // URL expires in 15 minutes
              });

              const fileInfo = {
                name: file.name,
                bucket: file.bucket.name,
                size: metadata.size || '0',
                contentType: metadata.contentType || null,
                updated: metadata.updated || null,
                md5Hash: metadata.md5Hash || null,
                downloadUrl: url
              };

              return {
                content: [{
                  type: 'text',
                  text: JSON.stringify(fileInfo, null, 2)
                }]
              };
            } catch (error) {
              logger.error('Failed to get file info', error);
              return {
                content: [{
                  type: 'text',
                  text: JSON.stringify({
                    error: 'Failed to get file info',
                    details: error instanceof Error ? error.message : 'Unknown error'
                  })
                }]
              };
            }
          }

          case 'firestore_list_collections':
            const collections = await admin.firestore().listCollections();
            const collectionList = collections.map(collection => ({
              id: collection.id,
              path: collection.path
            }));
            
            return {
              content: [{
                type: 'text',
                text: JSON.stringify({ collections: collectionList })
              }]
            };

          case 'firestore_query_collection_group': {
            const collectionId = args.collectionId as string;
            const limit = Math.min(Math.max(1, (args.limit as number) || 20), 100); // Default 20, max 100
            
            try {
              // Use the collectionGroup API directly here instead of importing
              let query: any = admin.firestore().collectionGroup(collectionId);

              // Apply filters if provided
              const filters = args.filters as Array<{
                field: string;
                operator: admin.firestore.WhereFilterOp;
                value: any;
              }> | undefined;

              if (filters && filters.length > 0) {
                filters.forEach(filter => {
                  query = query.where(filter.field, filter.operator, filter.value);
                });
              }

              // Apply ordering if provided
              const orderBy = args.orderBy as Array<{
                field: string;
                direction?: 'asc' | 'desc';
              }> | undefined;

              if (orderBy && orderBy.length > 0) {
                orderBy.forEach(order => {
                  query = query.orderBy(order.field, order.direction || 'asc');
                });
              }

              // Apply pagination if pageToken is provided
              const pageToken = args.pageToken as string | undefined;
              if (pageToken) {
                const lastDoc = await admin.firestore().doc(pageToken).get();
                if (lastDoc.exists) {
                  query = query.startAfter(lastDoc);
                }
              }
              
              // Apply limit
              query = query.limit(limit);
              
              const snapshot = await query.get();
              
              const documents = snapshot.docs.map((doc: FirebaseFirestore.QueryDocumentSnapshot) => {
                const rawData = doc.data();
                // Sanitize data to ensure it's JSON-serializable
                const data = Object.entries(rawData).reduce((acc, [key, value]) => {
                  // Handle basic types directly
                  if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean' || value === null) {
                    acc[key] = value;
                  }
                  // Convert Date objects to ISO strings
                  else if (value instanceof Date) {
                    acc[key] = value.toISOString();
                  }
                  // Convert arrays to strings
                  else if (Array.isArray(value)) {
                    acc[key] = `[${value.join(', ')}]`;
                  }
                  // Convert other objects to string representation
                  else if (typeof value === 'object') {
                    acc[key] = '[Object]';
                  }
                  // Convert other types to strings
                  else {
                    acc[key] = String(value);
                  }
                  return acc;
                }, {} as Record<string, any>);

                return {
                  id: doc.id,
                  path: doc.ref.path,
                  data
                };
              });

              // Get the last document for pagination
              const lastVisible = snapshot.docs[snapshot.docs.length - 1];
              const nextPageToken = lastVisible ? lastVisible.ref.path : null;
              
              return {
                content: [{
                  type: 'text',
                  text: JSON.stringify({
                    documents,
                    nextPageToken
                  })
                }]
              };
            } catch (error) {
              logger.error('Error in collection group query:', error);
              
              // Special handling for Firebase index errors
              const errorMessage = error instanceof Error ? error.message : 'Unknown error';
              if (errorMessage.includes('FAILED_PRECONDITION') && errorMessage.includes('requires an index')) {
                const indexUrl = errorMessage.match(/https:\/\/console\.firebase\.google\.com[^\s]*/)?.[0];
                return {
                  content: [{
                    type: 'text',
                    text: JSON.stringify({
                      error: 'This query requires a composite index.',
                      details: 'When ordering by multiple fields or combining filters with ordering, you need to create a composite index.',
                      indexUrl: indexUrl || null,
                      message: errorMessage
                    })
                  }]
                };
              }
              
              return {
                content: [{
                  type: 'text',
                  text: JSON.stringify({
                    error: errorMessage
                  })
                }]
              };
            }
          }

          default:
            logger.error(`Unknown tool: ${name}`);
            throw new McpError(ErrorCode.MethodNotFound, `Unknown tool: ${name}`);
        }
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : 'Unknown error';
        const duration = Date.now() - startTime;
        
        logger.error(`API call failed: ${name}`, {
          error: errorMessage,
          duration: `${duration}ms`,
          args: args
        });

        if (errorMessage.includes('FAILED_PRECONDITION') && errorMessage.includes('requires an index')) {
          const indexUrl = errorMessage.match(/https:\/\/console\.firebase\.google\.com[^\s]*/)?.[0];
          return {
            content: [{
              type: 'text',
              text: JSON.stringify({
                error: 'This query requires a composite index.',
                details: 'When ordering by multiple fields or combining filters with ordering, you need to create a composite index.',
                indexUrl: indexUrl || null
              })
            }]
          };
        }

        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              error: errorMessage
            })
          }]
        };
      }
    });
  }

  /**
   * Starts the MCP server using stdio transport.
   * This method connects the server to stdin/stdout for communication with MCP clients.
   */
  async run() {
    const transport = new StdioServerTransport();
    await this.server.connect(transport);
  }
}

// Create and start the server
const server = new FirebaseMcpServer();
server.run();
