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
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  ErrorCode,
  McpError,
} from '@modelcontextprotocol/sdk/types.js';
import * as admin from 'firebase-admin';
import {getFirestore} from 'firebase-admin/firestore';
import { logger } from './utils/logger.js';
import { Timestamp } from 'firebase-admin/firestore';

// Initialize Firebase
function initializeFirebase() {
  try {
    const serviceAccountPath = process.env.SERVICE_ACCOUNT_KEY_PATH;
    if (!serviceAccountPath) {
      logger.error('SERVICE_ACCOUNT_KEY_PATH not set');
      return null;
    }

    try {
      const existingApp = admin.app();
      if (existingApp) {
        logger.debug('Using existing Firebase app');
        return existingApp;
      }
    } catch (_error) {
      // No existing app, continue with initialization
      logger.debug('No existing Firebase app, initializing new one');
    }

    // Using require for dynamic import based on environment variable
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const serviceAccount = require(serviceAccountPath);
    const storageBucket = process.env.FIREBASE_STORAGE_BUCKET;
    logger.debug(`Initializing Firebase with storage bucket: ${storageBucket}`);

    return admin.initializeApp({
      credential: admin.credential.cert(serviceAccount),
      storageBucket: storageBucket,
    });
  } catch (error) {
    logger.error('Failed to initialize Firebase', error);
    return null;
  }
}

// Initialize Firebase
const app = initializeFirebase();

// Specify database
const databaseId = process.env.FIREBASE_DATABASE_ID || '(default)';
const db = getFirestore(databaseId);

// Response interface used throughout the codebase
// eslint-disable-next-line @typescript-eslint/no-unused-vars
interface McpResponse {
  content: Array<{ type: string; text: string }>;
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
        version: '1.3.3',
      },
      {
        capabilities: {
          tools: {},
        },
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
                description: 'Collection name',
              },
              data: {
                type: 'object',
                description: 'Document data',
              },
            },
            required: ['collection', 'data'],
          },
        },
        {
          name: 'firestore_list_documents',
          description: 'List documents from a Firestore collection with filtering and ordering',
          inputSchema: {
            type: 'object',
            properties: {
              collection: {
                type: 'string',
                description: 'Collection name',
              },
              filters: {
                type: 'array',
                description: 'Array of filter conditions',
                items: {
                  type: 'object',
                  properties: {
                    field: {
                      type: 'string',
                      description: 'Field name to filter',
                    },
                    operator: {
                      type: 'string',
                      description:
                        'Comparison operator (==, >, <, >=, <=, array-contains, in, array-contains-any)',
                    },
                    value: {
                      type: 'string',
                      description: 'Value to compare against (use ISO format for dates)',
                    },
                  },
                  required: ['field', 'operator', 'value'],
                },
              },
              limit: {
                type: 'number',
                description: 'Number of documents to return',
                default: 20,
              },
              pageToken: {
                type: 'string',
                description: 'Token for pagination to get the next page of results',
              },
              orderBy: {
                type: 'array',
                description: 'Array of fields to order by',
                items: {
                  type: 'object',
                  properties: {
                    field: {
                      type: 'string',
                      description: 'Field name to order by',
                    },
                    direction: {
                      type: 'string',
                      description: 'Sort direction (asc or desc)',
                      enum: ['asc', 'desc'],
                      default: 'asc',
                    },
                  },
                  required: ['field'],
                },
              },
            },
            required: ['collection'],
          },
        },
        {
          name: 'firestore_get_document',
          description: 'Get a document from a Firestore collection',
          inputSchema: {
            type: 'object',
            properties: {
              collection: {
                type: 'string',
                description: 'Collection name',
              },
              id: {
                type: 'string',
                description: 'Document ID',
              },
            },
            required: ['collection', 'id'],
          },
        },
        {
          name: 'firestore_update_document',
          description: 'Update a document in a Firestore collection',
          inputSchema: {
            type: 'object',
            properties: {
              collection: {
                type: 'string',
                description: 'Collection name',
              },
              id: {
                type: 'string',
                description: 'Document ID',
              },
              data: {
                type: 'object',
                description: 'Updated document data',
              },
            },
            required: ['collection', 'id', 'data'],
          },
        },
        {
          name: 'firestore_delete_document',
          description: 'Delete a document from a Firestore collection',
          inputSchema: {
            type: 'object',
            properties: {
              collection: {
                type: 'string',
                description: 'Collection name',
              },
              id: {
                type: 'string',
                description: 'Document ID',
              },
            },
            required: ['collection', 'id'],
          },
        },
        {
          name: 'auth_get_user',
          description: 'Get a user by ID or email from Firebase Authentication',
          inputSchema: {
            type: 'object',
            properties: {
              identifier: {
                type: 'string',
                description: 'User ID or email address',
              },
            },
            required: ['identifier'],
          },
        },
        {
          name: 'storage_list_files',
          description: 'List files in a given path in Firebase Storage',
          inputSchema: {
            type: 'object',
            properties: {
              directoryPath: {
                type: 'string',
                description:
                  'The optional path to list files from. If not provided, the root is used.',
              },
            },
            required: [],
          },
        },
        {
          name: 'storage_get_file_info',
          description: 'Get file information including metadata and download URL',
          inputSchema: {
            type: 'object',
            properties: {
              filePath: {
                type: 'string',
                description: 'The path of the file to get information for',
              },
            },
            required: ['filePath'],
          },
        },
        {
          name: 'storage_upload',
          description:
            'Upload a file to Firebase Storage. Supports local file paths (preferred for binary files), base64 data, or plain text.',
          inputSchema: {
            type: 'object',
            properties: {
              filePath: {
                type: 'string',
                description:
                  'The destination path in Firebase Storage (e.g., "images/logo.png"). If necessary, rename files for optimal URL compatibility (e.g., "my-document.pdf" rather than "My Document.pdf").',
              },
              content: {
                type: 'string',
                description:
                  'Can be: 1) A local file path (e.g., "/path/to/file.pdf") - RECOMMENDED for all file types, especially binary files like PDFs and images, 2) A data URL (e.g., "data:image/png;base64,...") - may have issues with large files, or 3) Plain text content. Note: Document references are not directly accessible - always use the actual file path instead.',
              },
              contentType: {
                type: 'string',
                description:
                  'Optional MIME type. If not provided, it will be automatically detected',
              },
              metadata: {
                type: 'object',
                description: 'Optional additional metadata',
              },
            },
            required: ['filePath', 'content'],
          },
          responseFormatting: {
            template:
              '## File Successfully Uploaded! 📁\n\nYour file has been uploaded to Firebase Storage:\n\n**File Details:**\n- **Name:** {{name}}\n- **Size:** {{size}} bytes\n- **Type:** {{contentType}}\n- **Last Updated:** {{updated}}\n- **Bucket:** {{bucket}}\n\n**[Click here to download your file]({{downloadUrl}})**\n\nThis is a permanent URL that will not expire.',
            fields: ['name', 'size', 'contentType', 'updated', 'bucket', 'downloadUrl'],
          },
        },
        {
          name: 'storage_upload_from_url',
          description:
            'Upload a file to Firebase Storage from an external URL. Perfect for images, documents, or any file accessible via URL.',
          inputSchema: {
            type: 'object',
            properties: {
              filePath: {
                type: 'string',
                description:
                  'The destination path in Firebase Storage (e.g., "images/photo.jpg"). If necessary, rename files for optimal URL compatibility (e.g., "my-document.pdf" rather than "My Document.pdf").',
              },
              url: {
                type: 'string',
                description:
                  'The source URL to download from (e.g., "https://example.com/image.jpg"). For GitHub files, use the raw URL (add ?raw=true)',
              },
              contentType: {
                type: 'string',
                description:
                  'Optional MIME type. If not provided, it will be automatically detected from the URL or response headers',
              },
              metadata: {
                type: 'object',
                description: 'Optional additional metadata',
              },
            },
            required: ['filePath', 'url'],
          },
          responseFormatting: {
            template:
              '## File Successfully Uploaded from URL! 📁\n\nYour file has been uploaded to Firebase Storage:\n\n**File Details:**\n- **Name:** {{name}}\n- **Size:** {{size}} bytes\n- **Type:** {{contentType}}\n- **Last Updated:** {{updated}}\n- **Source URL:** {{sourceUrl}}\n- **Bucket:** {{bucket}}\n\n**[Click here to download your file]({{downloadUrl}})**\n\nThis is a permanent URL that will not expire.',
            fields: [
              'name',
              'size',
              'contentType',
              'updated',
              'sourceUrl',
              'bucket',
              'downloadUrl',
            ],
          },
        },
        {
          name: 'firestore_list_collections',
          description: 'List root collections in Firestore',
          inputSchema: {
            type: 'object',
            properties: {},
            required: [],
          },
        },
        {
          name: 'firestore_query_collection_group',
          description:
            'Query documents across all subcollections with the same name (collection group query)',
          inputSchema: {
            type: 'object',
            properties: {
              collectionId: {
                type: 'string',
                description:
                  'The collection ID to query across all documents (without parent path)',
              },
              filters: {
                type: 'array',
                description: 'Optional filters to apply to the query',
                items: {
                  type: 'object',
                  properties: {
                    field: {
                      type: 'string',
                      description: 'Field name to filter',
                    },
                    operator: {
                      type: 'string',
                      description:
                        'Comparison operator (==, !=, <, <=, >, >=, array-contains, array-contains-any, in, not-in)',
                    },
                    value: {
                      type: 'string',
                      description: 'Value to compare against',
                    },
                  },
                  required: ['field', 'operator', 'value'],
                },
              },
              orderBy: {
                type: 'array',
                description: 'Optional fields to order results by',
                items: {
                  type: 'object',
                  properties: {
                    field: {
                      type: 'string',
                      description: 'Field name to order by',
                    },
                    direction: {
                      type: 'string',
                      enum: ['asc', 'desc'],
                      default: 'asc',
                      description: 'Sort direction (asc or desc)',
                    },
                  },
                  required: ['field'],
                },
              },
              limit: {
                type: 'number',
                description: 'Maximum number of documents to return (default: 20, max: 100)',
              },
              pageToken: {
                type: 'string',
                description: 'Token for pagination (document path to start after)',
              },
            },
            required: ['collectionId'],
          },
        },
      ],
    }));

    // Handle tool execution
    this.server.setRequestHandler(CallToolRequestSchema, async request => {
      const { name, arguments: args = {} } = request.params;

      try {
        if (!app) {
          return {
            content: [
              {
                type: 'text',
                text: JSON.stringify({
                  error: 'Firebase initialization failed',
                }),
              },
            ],
          };
        }

        switch (name) {
          case 'firestore_add_document': {
            const collection = args.collection as string;
            const data = args.data as Record<string, any>;

            // Process server timestamps and convert ISO date strings to Timestamps
            const processedData = Object.entries(data).reduce(
              (acc, [key, value]) => {
                // Check if this is a server timestamp request
                if (value && typeof value === 'object' && '__serverTimestamp' in value) {
                  acc[key] = admin.firestore.FieldValue.serverTimestamp();
                }
                // Check if this is an ISO date string that should be converted to a Timestamp
                else if (
                  typeof value === 'string' &&
                  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/.test(value)
                ) {
                  try {
                    // Convert ISO string to Timestamp for Firestore
                    acc[key] = admin.firestore.Timestamp.fromDate(new Date(value));
                    logger.debug(`Converted string date to Timestamp: ${value}`);
                  } catch (e) {
                    // If conversion fails, use the original value
                    logger.warn(`Failed to convert date string to Timestamp: ${value}`);
                    acc[key] = value;
                  }
                } else {
                  acc[key] = value;
                }
                return acc;
              },
              {} as Record<string, any>
            );

            const docRef = await db.collection(collection).add(processedData);

            return {
              content: [
                {
                  type: 'text',
                  text: JSON.stringify({
                    id: docRef.id,
                    path: docRef.path,
                  }),
                },
              ],
            };
          }

          case 'firestore_list_documents': {
            const collection = args.collection as string;
            const limit = Math.min(Math.max(1, (args.limit as number) || 20), 100); // Default 20, max 100

            let query: admin.firestore.Query = db.collection(collection);

            // Apply filters if provided
            const filters = args.filters as
              | Array<{
                  field: string;
                  operator: admin.firestore.WhereFilterOp;
                  value: any;
                }>
              | undefined;

            if (filters && filters.length > 0) {
              filters.forEach(filter => {
                let filterValue = filter.value;

                // Check if this might be a timestamp value in ISO format
                if (
                  typeof filterValue === 'string' &&
                  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/.test(filterValue)
                ) {
                  try {
                    // Convert ISO string to Timestamp for Firestore queries
                    filterValue = admin.firestore.Timestamp.fromDate(new Date(filterValue));
                  } catch (e) {
                    // If conversion fails, use the original value
                    logger.warn(`Failed to convert timestamp string to Timestamp: ${filterValue}`);
                  }
                }

                query = query.where(filter.field, filter.operator, filterValue);
              });
            }

            // Apply ordering if provided
            const orderBy = args.orderBy as
              | Array<{
                  field: string;
                  direction?: 'asc' | 'desc';
                }>
              | undefined;

            if (orderBy && orderBy.length > 0) {
              orderBy.forEach(order => {
                query = query.orderBy(order.field, order.direction || 'asc');
              });
            }

            // Apply pagination if pageToken is provided
            const pageToken = args.pageToken as string | undefined;
            if (pageToken) {
              const lastDoc = await db.doc(pageToken).get();
              if (lastDoc.exists) {
                query = query.startAfter(lastDoc);
              }
            }

            // Apply limit
            query = query.limit(limit);

            const snapshot = await query.get();
            const documents = snapshot.docs.map(doc => {
              const rawData = doc.data();
              // Sanitize data to ensure it's JSON-serializable
              const data = Object.entries(rawData).reduce(
                (acc, [key, value]) => {
                  // Handle basic types directly
                  if (
                    typeof value === 'string' ||
                    typeof value === 'number' ||
                    typeof value === 'boolean' ||
                    value === null
                  ) {
                    acc[key] = value;
                  }
                  // Convert Date objects to ISO strings
                  else if (value instanceof Date) {
                    acc[key] = value.toISOString();
                  }
                  // Handle Firestore Timestamp objects properly
                  else if (value instanceof Timestamp) {
                    acc[key] = value.toDate().toISOString();
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
                },
                {} as Record<string, any>
              );

              return {
                id: doc.id,
                path: doc.ref.path,
                data,
              };
            });

            // Get the last document for pagination
            const lastVisible = snapshot.docs[snapshot.docs.length - 1];
            const nextPageToken = lastVisible ? lastVisible.ref.path : null;

            return {
              content: [
                {
                  type: 'text',
                  text: JSON.stringify({
                    documents,
                    nextPageToken,
                  }),
                },
              ],
            };
          }

          case 'firestore_get_document': {
            const collection = args.collection as string;
            const id = args.id as string;

            const docRef = db.collection(collection).doc(id);
            const doc = await docRef.get();

            if (!doc.exists) {
              return {
                content: [
                  {
                    type: 'text',
                    text: JSON.stringify({
                      error: 'Document not found',
                    }),
                  },
                ],
              };
            }

            const rawData = doc.data();
            // Sanitize data to ensure it's JSON-serializable
            const data = Object.entries(rawData || {}).reduce(
              (acc, [key, value]) => {
                if (
                  typeof value === 'string' ||
                  typeof value === 'number' ||
                  typeof value === 'boolean' ||
                  value === null
                ) {
                  acc[key] = value;
                } else if (value instanceof Date) {
                  acc[key] = value.toISOString();
                } else if (value instanceof Timestamp) {
                  acc[key] = value.toDate().toISOString();
                } else if (Array.isArray(value)) {
                  acc[key] = `[${value.join(', ')}]`;
                } else if (typeof value === 'object') {
                  acc[key] = '[Object]';
                } else {
                  acc[key] = String(value);
                }
                return acc;
              },
              {} as Record<string, any>
            );

            return {
              content: [
                {
                  type: 'text',
                  text: JSON.stringify({
                    id: doc.id,
                    path: doc.ref.path,
                    data,
                  }),
                },
              ],
            };
          }

          case 'firestore_update_document': {
            const collection = args.collection as string;
            const id = args.id as string;
            const data = args.data as Record<string, any>;

            // Process server timestamps and convert ISO date strings to Timestamps
            const processedData = Object.entries(data).reduce(
              (acc, [key, value]) => {
                // Check if this is a server timestamp request
                if (value && typeof value === 'object' && '__serverTimestamp' in value) {
                  acc[key] = admin.firestore.FieldValue.serverTimestamp();
                }
                // Check if this is an ISO date string that should be converted to a Timestamp
                else if (
                  typeof value === 'string' &&
                  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/.test(value)
                ) {
                  try {
                    // Convert ISO string to Timestamp for Firestore
                    acc[key] = admin.firestore.Timestamp.fromDate(new Date(value));
                    logger.debug(`Converted string date to Timestamp: ${value}`);
                  } catch (e) {
                    // If conversion fails, use the original value
                    logger.warn(`Failed to convert date string to Timestamp: ${value}`);
                    acc[key] = value;
                  }
                } else {
                  acc[key] = value;
                }
                return acc;
              },
              {} as Record<string, any>
            );

            const docRef = db.collection(collection).doc(id);
            await docRef.update(processedData);

            return {
              content: [
                {
                  type: 'text',
                  text: JSON.stringify({
                    id,
                    path: docRef.path,
                    updated: true,
                  }),
                },
              ],
            };
          }

          case 'firestore_delete_document': {
            const collection = args.collection as string;
            const id = args.id as string;

            const docRef = db.collection(collection).doc(id);
            await docRef.delete();

            return {
              content: [
                {
                  type: 'text',
                  text: JSON.stringify({
                    id,
                    path: docRef.path,
                    deleted: true,
                  }),
                },
              ],
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
                  lastSignInTime: user.metadata.lastSignInTime,
                },
              };

              return {
                content: [
                  {
                    type: 'text',
                    text: JSON.stringify({ user: sanitizedUser }),
                  },
                ],
              };
            } catch (error) {
              return {
                content: [
                  {
                    type: 'text',
                    text: JSON.stringify({
                      error: 'User not found',
                      details: error instanceof Error ? error.message : 'Unknown error',
                    }),
                  },
                ],
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
                delimiter: '/',
              });

              logger.debug(`Found ${files.length} files`);

              const fileList = files.map(file => ({
                name: file.name,
                size: file.metadata.size ? file.metadata.size : '0',
                contentType: file.metadata.contentType || null,
                updated: file.metadata.updated || null,
                md5Hash: file.metadata.md5Hash || null,
              }));

              return {
                content: [
                  {
                    type: 'text',
                    text: JSON.stringify({ files: fileList }, null, 2),
                  },
                ],
              };
            } catch (error) {
              logger.error('Failed to list files', error);
              return {
                content: [
                  {
                    type: 'text',
                    text: JSON.stringify({
                      error: 'Failed to list files',
                      details: error instanceof Error ? error.message : 'Unknown error',
                    }),
                  },
                ],
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
                  content: [
                    {
                      type: 'text',
                      text: JSON.stringify(
                        {
                          error: 'File not found',
                        },
                        null,
                        2
                      ),
                    },
                  ],
                };
              }

              logger.debug('File exists, getting metadata and signed URL');
              const [metadata] = await file.getMetadata();
              const [url] = await file.getSignedUrl({
                action: 'read',
                expires: Date.now() + 15 * 60 * 1000, // URL expires in 15 minutes
              });

              const fileInfo = {
                name: file.name,
                bucket: file.bucket.name,
                size: metadata.size || '0',
                contentType: metadata.contentType || null,
                updated: metadata.updated || null,
                md5Hash: metadata.md5Hash || null,
                downloadUrl: url,
              };

              return {
                content: [
                  {
                    type: 'text',
                    text: JSON.stringify(fileInfo, null, 2),
                  },
                ],
              };
            } catch (error) {
              logger.error('Failed to get file info', error);
              return {
                content: [
                  {
                    type: 'text',
                    text: JSON.stringify({
                      error: 'Failed to get file info',
                      details: error instanceof Error ? error.message : 'Unknown error',
                    }),
                  },
                ],
              };
            }
          }

          case 'storage_upload': {
            const { filePath, content, contentType, metadata } = args;

            try {
              logger.debug(`Uploading file to: ${filePath}`);
              const storageClient = await import('./lib/firebase/storageClient.js');
              const uploadFile = storageClient.uploadFile;
              const result = await uploadFile(
                filePath as string,
                content as string,
                contentType as string | undefined,
                metadata as Record<string, any> | undefined
              );

              // Check if there's an error
              if (result.isError) {
                return {
                  content: [
                    {
                      type: 'text',
                      text: result.content[0].text,
                    },
                  ],
                  error: true,
                };
              }

              // Extract the file info from the JSON response
              try {
                const fileInfo = JSON.parse(result.content[0].text);

                return {
                  content: [
                    {
                      type: 'text',
                      text: JSON.stringify(fileInfo, null, 2),
                    },
                  ],
                };
              } catch (error) {
                // If parsing fails, return the original text
                return {
                  content: [
                    {
                      type: 'text',
                      text: result.content[0].text,
                    },
                  ],
                };
              }
            } catch (error) {
              logger.error('Failed to upload file', error);
              return {
                content: [
                  {
                    type: 'text',
                    text: JSON.stringify({
                      error: 'Failed to upload file',
                      details: error instanceof Error ? error.message : 'Unknown error',
                    }),
                  },
                ],
              };
            }
          }

          case 'storage_upload_from_url': {
            const { filePath, url, contentType, metadata } = args;

            try {
              logger.debug(`Uploading file from URL: ${url} to: ${filePath}`);
              const storageClient = await import('./lib/firebase/storageClient.js');
              const uploadFileFromUrl = storageClient.uploadFileFromUrl;
              const result = await uploadFileFromUrl(
                filePath as string,
                url as string,
                contentType as string | undefined,
                metadata as Record<string, any> | undefined
              );

              // Check if there's an error
              if (result.isError) {
                return {
                  content: [
                    {
                      type: 'text',
                      text: result.content[0].text,
                    },
                  ],
                  error: true,
                };
              }

              // Extract the file info from the JSON response
              try {
                const fileInfo = JSON.parse(result.content[0].text);

                return {
                  content: [
                    {
                      type: 'text',
                      text: JSON.stringify(fileInfo, null, 2),
                    },
                  ],
                };
              } catch (error) {
                // If parsing fails, return the original text
                return {
                  content: [
                    {
                      type: 'text',
                      text: result.content[0].text,
                    },
                  ],
                };
              }
            } catch (error) {
              logger.error('Failed to upload file from URL', error);
              return {
                content: [
                  {
                    type: 'text',
                    text: JSON.stringify({
                      error: 'Failed to upload file from URL',
                      details: error instanceof Error ? error.message : 'Unknown error',
                    }),
                  },
                ],
              };
            }
          }

          case 'firestore_list_collections':
            const collections = await db.listCollections();
            const collectionList = collections.map(collection => ({
              id: collection.id,
              path: collection.path,
            }));

            return {
              content: [
                {
                  type: 'text',
                  text: JSON.stringify({ collections: collectionList }),
                },
              ],
            };

          case 'firestore_query_collection_group': {
            const collectionId = args.collectionId as string;
            const limit = Math.min(Math.max(1, (args.limit as number) || 20), 100); // Default 20, max 100

            try {
              // Use the collectionGroup API directly here instead of importing
              let query: any = db.collectionGroup(collectionId);

              // Apply filters if provided
              const filters = args.filters as
                | Array<{
                    field: string;
                    operator: admin.firestore.WhereFilterOp;
                    value: any;
                  }>
                | undefined;

              if (filters && filters.length > 0) {
                filters.forEach(filter => {
                  let filterValue = filter.value;

                  // Check if this might be a timestamp value in ISO format
                  if (
                    typeof filterValue === 'string' &&
                    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/.test(filterValue)
                  ) {
                    try {
                      // Convert ISO string to Timestamp for Firestore queries
                      filterValue = admin.firestore.Timestamp.fromDate(new Date(filterValue));
                    } catch (e) {
                      // If conversion fails, use the original value
                      logger.warn(
                        `Failed to convert timestamp string to Timestamp: ${filterValue}`
                      );
                    }
                  }

                  query = query.where(filter.field, filter.operator, filterValue);
                });
              }

              // Apply ordering if provided
              const orderBy = args.orderBy as
                | Array<{
                    field: string;
                    direction?: 'asc' | 'desc';
                  }>
                | undefined;

              if (orderBy && orderBy.length > 0) {
                orderBy.forEach(order => {
                  query = query.orderBy(order.field, order.direction || 'asc');
                });
              }

              // Apply pagination if pageToken is provided
              const pageToken = args.pageToken as string | undefined;
              if (pageToken) {
                const lastDoc = await db.doc(pageToken).get();
                if (lastDoc.exists) {
                  query = query.startAfter(lastDoc);
                }
              }

              // Apply limit
              query = query.limit(limit);

              const snapshot = await query.get();

              const documents = snapshot.docs.map(
                (doc: FirebaseFirestore.QueryDocumentSnapshot) => {
                  const rawData = doc.data();
                  // Sanitize data to ensure it's JSON-serializable
                  const data = Object.entries(rawData).reduce(
                    (acc, [key, value]) => {
                      // Handle basic types directly
                      if (
                        typeof value === 'string' ||
                        typeof value === 'number' ||
                        typeof value === 'boolean' ||
                        value === null
                      ) {
                        acc[key] = value;
                      }
                      // Convert Date objects to ISO strings
                      else if (value instanceof Date) {
                        acc[key] = value.toISOString();
                      }
                      // Handle Firestore Timestamp objects properly
                      else if (value instanceof Timestamp) {
                        acc[key] = value.toDate().toISOString();
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
                    },
                    {} as Record<string, any>
                  );

                  return {
                    id: doc.id,
                    path: doc.ref.path,
                    data,
                  };
                }
              );

              // Get the last document for pagination
              const lastVisible = snapshot.docs[snapshot.docs.length - 1];
              const nextPageToken = lastVisible ? lastVisible.ref.path : null;

              return {
                content: [
                  {
                    type: 'text',
                    text: JSON.stringify({
                      documents,
                      nextPageToken,
                    }),
                  },
                ],
              };
            } catch (error) {
              logger.error('Error in collection group query:', error);

              // Special handling for Firebase index errors
              const errorMessage = error instanceof Error ? error.message : 'Unknown error';
              if (
                errorMessage.includes('FAILED_PRECONDITION') &&
                errorMessage.includes('requires an index')
              ) {
                const indexUrl = errorMessage.match(
                  /https:\/\/console\.firebase\.google\.com[^\s]*/
                )?.[0];
                return {
                  content: [
                    {
                      type: 'text',
                      text: JSON.stringify({
                        error: 'This query requires a composite index.',
                        details:
                          'When ordering by multiple fields or combining filters with ordering, you need to create a composite index.',
                        indexUrl: indexUrl || null,
                        message: errorMessage,
                      }),
                    },
                  ],
                };
              }

              return {
                content: [
                  {
                    type: 'text',
                    text: JSON.stringify({
                      error: errorMessage,
                    }),
                  },
                ],
              };
            }
          }

          default:
            throw new McpError(ErrorCode.MethodNotFound, `Unknown tool: ${name}`);
        }
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : 'Unknown error';

        // Check if it's an index error and extract the index creation URL
        if (
          errorMessage.includes('FAILED_PRECONDITION') &&
          errorMessage.includes('requires an index')
        ) {
          const indexUrl = errorMessage.match(
            /https:\/\/console\.firebase\.google\.com[^\s]*/
          )?.[0];
          return {
            content: [
              {
                type: 'text',
                text: JSON.stringify({
                  error: 'This query requires a composite index.',
                  details:
                    'When ordering by multiple fields or combining filters with ordering, you need to create a composite index.',
                  indexUrl: indexUrl || null,
                }),
              },
            ],
          };
        }

        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify({
                error: errorMessage,
              }),
            },
          ],
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
