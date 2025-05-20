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
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  ErrorCode,
  McpError,
} from '@modelcontextprotocol/sdk/types.js';
import admin from 'firebase-admin';
import { logger } from './utils/logger.js';
import { Timestamp, getFirestore } from 'firebase-admin/firestore';
import config from './config.js';
import { initializeTransport } from './transports/index.js';
import * as fs from 'fs';

// Initialize Firebase
async function initializeFirebase(): Promise<admin.app.App | null> {
  try {
    const serviceAccountPath = config.serviceAccountKeyPath;
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
    } catch {
      // No existing app, continue with initialization
      logger.debug('No existing Firebase app, initializing new one');
    }

    // Read the service account key file
    try {
      const serviceAccountContent = fs.readFileSync(serviceAccountPath, 'utf8');
      logger.debug(`Service account file read successfully: ${serviceAccountPath}`);

      const serviceAccount = JSON.parse(serviceAccountContent);
      logger.debug(
        `Service account parsed successfully: ${Object.keys(serviceAccount).join(', ')}`
      );

      const storageBucket = config.storageBucket || undefined;
      logger.debug(`Initializing Firebase with storage bucket: ${storageBucket}`);

      // Initialize Firebase with the service account
      return admin.initializeApp({
        credential: admin.credential.cert(serviceAccount),
        storageBucket: storageBucket,
      });
    } catch (error) {
      logger.error(
        `Error initializing Firebase: ${error instanceof Error ? error.message : 'Unknown error'}`
      );
      return null;
    }
  } catch (error) {
    logger.error('Failed to initialize Firebase', error);
    return null;
  }
}

// Initialize Firebase (will be set asynchronously)
let app: admin.app.App | null = null;

// Initialize the app asynchronously
(async () => {
  app = await initializeFirebase();
})();

// Specify database
const databaseId = process.env.FIREBASE_DATABASE_ID || '(default)';
const db = getFirestore(databaseId);

// This interface was previously used but is now handled by the SDK
// Keeping it commented for reference
// interface FirebaseToolResponse {
//   content: Array<{ type: string; text: string }>;
//   isError?: boolean;
// }

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
        name: config.name,
        version: config.version,
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
  private setupToolHandlers(): void {
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
            const data = args.data as Record<string, unknown>;

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
                  } catch {
                    // If conversion fails, use the original value
                    logger.warn(`Failed to convert date string to Timestamp: ${value}`);
                    acc[key] = value;
                  }
                } else {
                  acc[key] = value;
                }
                return acc;
              },
              {} as Record<string, unknown>
            );

            const docRef = await db.collection(collection).add(processedData);

            // Ensure clean JSON by parsing and re-stringifying
            const sanitizedJson = JSON.stringify({
              id: docRef.id,
              path: docRef.path,
            });

            // Log the response for debugging
            const response = {
              content: [
                {
                  type: 'text',
                  text: sanitizedJson,
                },
              ],
            };
            logger.debug('firestore_add_document response:', JSON.stringify(response));
            return response;
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
                  value: unknown;
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
                  } catch {
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
                {} as Record<string, unknown>
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

            // Ensure clean JSON by parsing and re-stringifying
            const sanitizedJson = JSON.stringify({
              documents,
              nextPageToken,
            });

            // Log the response for debugging
            const response = {
              content: [
                {
                  type: 'text',
                  text: sanitizedJson,
                },
              ],
            };
            logger.debug('firestore_list_documents response:', JSON.stringify(response));
            return response;
          }

          case 'firestore_get_document': {
            const collection = args.collection as string;
            const id = args.id as string;

            const docRef = db.collection(collection).doc(id);
            const doc = await docRef.get();

            if (!doc.exists) {
              // Ensure clean JSON by parsing and re-stringifying
              const sanitizedJson = JSON.stringify({
                error: 'Document not found',
              });

              // Log the response for debugging
              const response = {
                content: [
                  {
                    type: 'text',
                    text: sanitizedJson,
                  },
                ],
              };
              logger.debug('firestore_get_document error response:', JSON.stringify(response));
              return response;
            }

            const rawData = doc.data();
            // Sanitize data to ensure it's JSON-serializable
            const data = Object.entries(rawData || {}).reduce(
              (acc, [key, value]) => {
                if (value instanceof Date) {
                  acc[key] = value.toISOString();
                } else if (value instanceof Timestamp) {
                  acc[key] = value.toDate().toISOString();
                } else {
                  acc[key] = value;
                }
                return acc;
              },
              {} as Record<string, unknown>
            );

            // Ensure clean JSON by parsing and re-stringifying
            const sanitizedJson = JSON.stringify({
              id: doc.id,
              path: doc.ref.path,
              data,
            });

            // Log the response for debugging
            const response = {
              content: [
                {
                  type: 'text',
                  text: sanitizedJson,
                },
              ],
            };
            logger.debug('firestore_get_document response:', JSON.stringify(response));
            return response;
          }

          case 'firestore_update_document': {
            const collection = args.collection as string;
            const id = args.id as string;
            const data = args.data as Record<string, unknown>;

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
                  } catch {
                    // If conversion fails, use the original value
                    logger.warn(`Failed to convert date string to Timestamp: ${value}`);
                    acc[key] = value;
                  }
                } else {
                  acc[key] = value;
                }
                return acc;
              },
              {} as Record<string, unknown>
            );

            const docRef = db.collection(collection).doc(id);
            await docRef.update(processedData);

            // Ensure clean JSON by parsing and re-stringifying
            const sanitizedJson = JSON.stringify({
              id,
              path: docRef.path,
              updated: true,
            });

            // Log the response for debugging
            const response = {
              content: [
                {
                  type: 'text',
                  text: sanitizedJson,
                },
              ],
            };
            logger.debug('firestore_update_document response:', JSON.stringify(response));
            return response;
          }

          case 'firestore_delete_document': {
            const collection = args.collection as string;
            const id = args.id as string;

            const docRef = db.collection(collection).doc(id);
            await docRef.delete();

            // Ensure clean JSON by parsing and re-stringifying
            const sanitizedJson = JSON.stringify({
              id,
              path: docRef.path,
              deleted: true,
            });

            // Log the response for debugging
            const response = {
              content: [
                {
                  type: 'text',
                  text: sanitizedJson,
                },
              ],
            };
            logger.debug('firestore_delete_document response:', JSON.stringify(response));
            return response;
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

              // Ensure clean JSON by parsing and re-stringifying
              const sanitizedJson = JSON.stringify({ user: sanitizedUser });

              // Log the response for debugging
              const response = {
                content: [
                  {
                    type: 'text',
                    text: sanitizedJson,
                  },
                ],
              };
              logger.debug('auth_get_user response:', JSON.stringify(response));
              return response;
            } catch (error) {
              // Ensure clean JSON by parsing and re-stringifying
              const sanitizedJson = JSON.stringify({
                error: 'User not found',
                details: error instanceof Error ? error.message : 'Unknown error',
              });

              // Log the response for debugging
              const response = {
                content: [
                  {
                    type: 'text',
                    text: sanitizedJson,
                  },
                ],
              };
              logger.debug('auth_get_user error response:', JSON.stringify(response));
              return response;
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

              // Ensure clean JSON by parsing and re-stringifying
              const sanitizedJson = JSON.stringify({ files: fileList });

              // Log the response for debugging
              const response = {
                content: [
                  {
                    type: 'text',
                    text: sanitizedJson,
                  },
                ],
              };
              logger.debug('storage_list_files response:', JSON.stringify(response));
              return response;
            } catch (error) {
              logger.error('Failed to list files', error);
              // Ensure clean JSON by parsing and re-stringifying
              const sanitizedJson = JSON.stringify({
                error: 'Failed to list files',
                details: error instanceof Error ? error.message : 'Unknown error',
              });

              // Log the response for debugging
              const response = {
                content: [
                  {
                    type: 'text',
                    text: sanitizedJson,
                  },
                ],
              };
              logger.debug('storage_list_files error response:', JSON.stringify(response));
              return response;
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
                // Ensure clean JSON by parsing and re-stringifying
                const sanitizedJson = JSON.stringify({
                  error: 'File not found',
                });

                // Log the response for debugging
                const response = {
                  content: [
                    {
                      type: 'text',
                      text: sanitizedJson,
                    },
                  ],
                };
                logger.debug('storage_get_file_info error response:', JSON.stringify(response));
                return response;
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

              // Ensure clean JSON by parsing and re-stringifying
              const sanitizedJson = JSON.stringify(fileInfo);

              // Log the response for debugging
              const response = {
                content: [
                  {
                    type: 'text',
                    text: sanitizedJson,
                  },
                ],
              };
              logger.debug('storage_get_file_info response:', JSON.stringify(response));
              return response;
            } catch (error) {
              logger.error('Failed to get file info', error);
              // Ensure clean JSON by parsing and re-stringifying
              const sanitizedJson = JSON.stringify({
                error: 'Failed to get file info',
                details: error instanceof Error ? error.message : 'Unknown error',
              });

              // Log the response for debugging
              const response = {
                content: [
                  {
                    type: 'text',
                    text: sanitizedJson,
                  },
                ],
              };
              logger.debug('storage_get_file_info error response:', JSON.stringify(response));
              return response;
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
                metadata as Record<string, unknown> | undefined
              );

              // Check if there's an error
              if (result.isError) {
                // Log the response for debugging
                const response = {
                  content: [
                    {
                      type: 'text',
                      text: result.content[0].text,
                    },
                  ],
                  error: true,
                };
                logger.debug('storage_upload error response:', JSON.stringify(response));
                return response;
              }

              // Extract the file info from the JSON response
              try {
                const fileInfo = JSON.parse(result.content[0].text);

                // Ensure clean JSON by parsing and re-stringifying
                const sanitizedJson = JSON.stringify(fileInfo);

                // Log the response for debugging
                const response = {
                  content: [
                    {
                      type: 'text',
                      text: sanitizedJson,
                    },
                  ],
                };
                logger.debug('storage_upload success response:', JSON.stringify(response));
                return response;
              } catch {
                // If parsing fails, return the original text
                // Log the response for debugging
                const response = {
                  content: [
                    {
                      type: 'text',
                      text: result.content[0].text,
                    },
                  ],
                };
                logger.debug('storage_upload fallback response:', JSON.stringify(response));
                return response;
              }
            } catch (error) {
              logger.error('Failed to upload file', error);
              // Ensure clean JSON by parsing and re-stringifying
              const sanitizedJson = JSON.stringify({
                error: 'Failed to upload file',
                details: error instanceof Error ? error.message : 'Unknown error',
              });

              // Log the response for debugging
              const response = {
                content: [
                  {
                    type: 'text',
                    text: sanitizedJson,
                  },
                ],
              };
              logger.debug('storage_upload catch error response:', JSON.stringify(response));
              return response;
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
                metadata as Record<string, unknown> | undefined
              );

              // Check if there's an error
              if (result.isError) {
                // Log the response for debugging
                const response = {
                  content: [
                    {
                      type: 'text',
                      text: result.content[0].text,
                    },
                  ],
                  error: true,
                };
                logger.debug('storage_upload_from_url error response:', JSON.stringify(response));
                return response;
              }

              // Extract the file info from the JSON response
              try {
                const fileInfo = JSON.parse(result.content[0].text);

                // Ensure clean JSON by parsing and re-stringifying
                const sanitizedJson = JSON.stringify(fileInfo);

                // Log the response for debugging
                const response = {
                  content: [
                    {
                      type: 'text',
                      text: sanitizedJson,
                    },
                  ],
                };
                logger.debug('storage_upload_from_url success response:', JSON.stringify(response));
                return response;
              } catch {
                // If parsing fails, return the original text
                // Log the response for debugging
                const response = {
                  content: [
                    {
                      type: 'text',
                      text: result.content[0].text,
                    },
                  ],
                };
                logger.debug(
                  'storage_upload_from_url fallback response:',
                  JSON.stringify(response)
                );
                return response;
              }
            } catch (error) {
              logger.error('Failed to upload file from URL', error);
              // Ensure clean JSON by parsing and re-stringifying
              const sanitizedJson = JSON.stringify({
                error: 'Failed to upload file from URL',
                details: error instanceof Error ? error.message : 'Unknown error',
              });

              // Log the response for debugging
              const response = {
                content: [
                  {
                    type: 'text',
                    text: sanitizedJson,
                  },
                ],
              };
              logger.debug(
                'storage_upload_from_url catch error response:',
                JSON.stringify(response)
              );
              return response;
            }
          }

          case 'firestore_list_collections': {
            try {
              logger.debug('Listing Firestore collections');

              // Get document path parameter if provided
              const documentPath = args.documentPath as string | undefined;

              // Make sure admin is properly initialized
              if (!app) {
                logger.error('Firebase app is not initialized');
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

              // Import the standardized implementation from firestoreClient
              const firestoreClient = await import('./lib/firebase/firestoreClient.js');

              // Call the standardized implementation with the document path and admin instance
              const result = await firestoreClient.list_collections(
                documentPath,
                undefined,
                undefined,
                admin
              );

              // Log the response for debugging
              logger.debug(`Found collections in response`);

              // Return the response directly without additional parsing
              // This avoids any potential issues with double parsing
              return {
                content: [
                  {
                    type: 'text',
                    text: result.content[0].text,
                  },
                ],
              };
            } catch (error) {
              logger.error('Error listing Firestore collections:', error);

              // Create a clean error response
              return {
                content: [
                  {
                    type: 'text',
                    text: JSON.stringify({
                      error: 'Failed to list Firestore collections',
                      message: error instanceof Error ? error.message : 'Unknown error',
                    }),
                  },
                ],
              };
            }
          }

          case 'firestore_query_collection_group': {
            try {
              logger.debug('Querying Firestore collection group');

              // Make sure admin is properly initialized
              if (!app) {
                logger.error('Firebase app is not initialized');
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

              const collectionId = args.collectionId as string;
              const limit = Math.min(Math.max(1, (args.limit as number) || 20), 100); // Default 20, max 100
              const filters = args.filters as
                | Array<{
                    field: string;
                    operator: FirebaseFirestore.WhereFilterOp;
                    value: unknown;
                  }>
                | undefined;
              const orderBy = args.orderBy as
                | Array<{ field: string; direction?: 'asc' | 'desc' }>
                | undefined;
              const pageToken = args.pageToken as string | undefined;

              // Use the Firestore instance directly
              let query: FirebaseFirestore.Query = db.collectionGroup(collectionId);

              // Apply filters if provided
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
                    } catch {
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
              if (orderBy && orderBy.length > 0) {
                orderBy.forEach(order => {
                  query = query.orderBy(order.field, order.direction || 'asc');
                });
              }

              // Apply pagination if pageToken is provided
              if (pageToken) {
                try {
                  const lastDoc = await db.doc(pageToken).get();
                  if (lastDoc.exists) {
                    query = query.startAfter(lastDoc);
                  }
                } catch (error) {
                  logger.error('Invalid pagination token:', error);
                  return {
                    content: [
                      {
                        type: 'text',
                        text: JSON.stringify({
                          error: `Invalid pagination token: ${error instanceof Error ? error.message : 'Unknown error'}`,
                        }),
                      },
                    ],
                  };
                }
              }

              // Apply limit
              query = query.limit(limit);

              // Execute the query
              const snapshot = await query.get();

              // Process the results
              const documents = snapshot.docs.map(doc => {
                // For collection groups, we need to use the full path for the URL
                const fullPath = doc.ref.path;

                // Handle Timestamp and other Firestore types
                const data = Object.entries(doc.data()).reduce(
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
                      acc[key] = value;
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
                  {} as Record<string, unknown>
                );

                return {
                  id: doc.id,
                  path: fullPath,
                  data,
                };
              });

              // Get the last document for pagination
              const lastVisible = snapshot.docs[snapshot.docs.length - 1];
              const nextPageToken = lastVisible ? lastVisible.ref.path : null;

              // Create the result object
              const result = {
                documents,
                nextPageToken,
              };

              // Log the response for debugging
              logger.debug(
                `Found ${documents.length} documents in collection group ${collectionId}`
              );

              // Ensure we're returning a properly formatted response
              return {
                content: [
                  {
                    type: 'text',
                    text: JSON.stringify(result),
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
                // Ensure clean JSON by parsing and re-stringifying
                const sanitizedJson = JSON.stringify({
                  error: 'This query requires a composite index.',
                  details:
                    'When ordering by multiple fields or combining filters with ordering, you need to create a composite index.',
                  indexUrl: indexUrl || null,
                  message: errorMessage,
                });

                // Log the response for debugging
                const response = {
                  content: [
                    {
                      type: 'text',
                      text: sanitizedJson,
                    },
                  ],
                };
                logger.debug(
                  'firestore_query_collection_group index error response:',
                  JSON.stringify(response)
                );
                return response;
              }

              // Ensure clean JSON by parsing and re-stringifying
              const sanitizedJson = JSON.stringify({
                error: errorMessage,
              });

              // Log the response for debugging
              const response = {
                content: [
                  {
                    type: 'text',
                    text: sanitizedJson,
                  },
                ],
              };
              logger.debug(
                'firestore_query_collection_group error response:',
                JSON.stringify(response)
              );
              return response;
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
          // Ensure clean JSON by parsing and re-stringifying
          const sanitizedJson = JSON.stringify({
            error: 'This query requires a composite index.',
            details:
              'When ordering by multiple fields or combining filters with ordering, you need to create a composite index.',
            indexUrl: indexUrl || null,
          });

          // Log the response for debugging
          const response = {
            content: [
              {
                type: 'text',
                text: sanitizedJson,
              },
            ],
          };
          logger.debug('global index error response:', JSON.stringify(response));
          return response;
        }

        // Ensure clean JSON by parsing and re-stringifying
        const sanitizedJson = JSON.stringify({
          error: errorMessage,
        });

        // Log the response for debugging
        const response = {
          content: [
            {
              type: 'text',
              text: sanitizedJson,
            },
          ],
        };
        logger.debug('global error response:', JSON.stringify(response));
        return response;
      }
    });
  }

  /**
   * Starts the MCP server using the configured transport.
   * This method initializes the appropriate transport based on configuration.
   */
  async run(): Promise<void> {
    // Wait for Firebase to initialize
    if (!app) {
      logger.info('Waiting for Firebase to initialize...');
      await new Promise<void>(resolve => {
        const checkInterval = setInterval(() => {
          if (app) {
            clearInterval(checkInterval);
            resolve();
          }
        }, 100);
      });
    }

    logger.info(
      `Starting Firebase MCP server v${config.version} with ${config.transport} transport`
    );
    await initializeTransport(this.server, config);
  }
}

// Create and start the server
const server = new FirebaseMcpServer();
server.run();
