/**
 * Firebase MCP Server with Security Enhancements
 *
 * This module implements a secure Firebase MCP server with enhanced security features.
 * It integrates authentication, access control, rate limiting, and audit logging.
 *
 * @module firebase-mcp/server
 */

import express, { Application, json } from "express";
import { Server } from "@modelcontextprotocol/sdk/server";
import { HttpServerTransport } from "@modelcontextprotocol/sdk/server/http";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  ErrorCode,
  McpError,
} from "@modelcontextprotocol/sdk/types";
import * as firestore from "./firebase/firestoreClient";
import * as storage from "./firebase/storageClient";
import * as auth from "./firebase/authClient";
import { applySecurityMiddleware } from "./security";
import path from "path";
import fs from "fs";
import adminRouter from "../routes/adminApi";

// Available transports
export type TransportType = "stdio" | "http";

/**
 * Server configuration options
 */
export interface ServerOptions {
  name: string;
  version: string;
  port: number;
  transport: TransportType;
  enableSecurity: boolean;
  adminApiKey?: string;
  corsOrigins?: string | string[];
}

/**
 * Default server options
 */
const DEFAULT_OPTIONS: ServerOptions = {
  name: "firebase-mcp",
  version: "0.7.0",
  port: parseInt(process.env.PORT || "3000", 10),
  transport: (process.env.TRANSPORT || "stdio") as TransportType,
  enableSecurity: process.env.ENABLE_SECURITY !== "false",
  adminApiKey: process.env.ADMIN_API_KEY,
  corsOrigins: process.env.CORS_ORIGINS
    ? process.env.CORS_ORIGINS.split(",")
    : "*",
};

/**
 * Enhanced Firebase MCP server class
 */
export class FirebaseMcpServer {
  private server: Server;
  private expressApp: Application | null = null;
  private options: ServerOptions;

  /**
   * Initialize the Firebase MCP server
   * @param options Server configuration options
   */
  constructor(options: Partial<ServerOptions> = {}) {
    this.options = { ...DEFAULT_OPTIONS, ...options };

    // Create the MCP server
    this.server = new Server(
      {
        name: this.options.name,
        version: this.options.version,
      },
      {
        capabilities: {
          tools: {},
        },
      }
    );

    this.setupToolHandlers();
    this.setupErrorHandling();
  }

  /**
   * Set up the tool handlers for Firebase operations
   */
  private setupToolHandlers(): void {
    // Register available tools
    this.server.setRequestHandler(ListToolsRequestSchema, async () => ({
      tools: [
        {
          name: "firestore_add_document",
          description: "Add a document to a Firestore collection",
          inputSchema: {
            type: "object",
            properties: {
              collection: {
                type: "string",
                description: "Collection name",
              },
              data: {
                type: "object",
                description: "Document data",
              },
            },
            required: ["collection", "data"],
          },
        },
        {
          name: "firestore_list_collections",
          description:
            "List collections in Firestore. If documentPath is provided, returns subcollections under that document; otherwise returns root collections.",
          inputSchema: {
            type: "object",
            properties: {
              documentPath: {
                type: "string",
                description: "Optional parent document path",
              },
              limit: {
                type: "number",
                description: "Number of collections to return",
                default: 20,
              },
              pageToken: {
                type: "string",
                description:
                  "Token for pagination to get the next page of results",
              },
            },
            required: [],
          },
        },
        {
          name: "firestore_list_documents",
          description:
            "List documents from a Firestore collection with optional filtering",
          inputSchema: {
            type: "object",
            properties: {
              collection: {
                type: "string",
                description: "Collection name",
              },
              filters: {
                type: "array",
                description: "Array of filter conditions",
                items: {
                  type: "object",
                  properties: {
                    field: {
                      type: "string",
                      description: "Field name to filter",
                    },
                    operator: {
                      type: "string",
                      description: "Comparison operator",
                    },
                    value: {
                      type: "any",
                      description:
                        "Value to compare against (use ISO format for dates)",
                    },
                  },
                  required: ["field", "operator", "value"],
                },
              },
              limit: {
                type: "number",
                description: "Number of documents to return",
                default: 20,
              },
              pageToken: {
                type: "string",
                description:
                  "Token for pagination to get the next page of results",
              },
            },
            required: ["collection"],
          },
        },
        {
          name: "firestore_get_document",
          description: "Get a document from a Firestore collection",
          inputSchema: {
            type: "object",
            properties: {
              collection: {
                type: "string",
                description: "Collection name",
              },
              id: {
                type: "string",
                description: "Document ID",
              },
            },
            required: ["collection", "id"],
          },
        },
        {
          name: "firestore_update_document",
          description: "Update a document in a Firestore collection",
          inputSchema: {
            type: "object",
            properties: {
              collection: {
                type: "string",
                description: "Collection name",
              },
              id: {
                type: "string",
                description: "Document ID",
              },
              data: {
                type: "object",
                description: "Updated document data",
              },
            },
            required: ["collection", "id", "data"],
          },
        },
        {
          name: "firestore_delete_document",
          description: "Delete a document from a Firestore collection",
          inputSchema: {
            type: "object",
            properties: {
              collection: {
                type: "string",
                description: "Collection name",
              },
              id: {
                type: "string",
                description: "Document ID",
              },
            },
            required: ["collection", "id"],
          },
        },
        {
          name: "auth_get_user",
          description: "Get a user by ID or email from Firebase Authentication",
          inputSchema: {
            type: "object",
            properties: {
              identifier: {
                type: "string",
                description: "User ID or email address",
              },
            },
            required: ["identifier"],
          },
        },
        {
          name: "storage_list_files",
          description: "List files in a given path in Firebase Storage",
          inputSchema: {
            type: "object",
            properties: {
              directoryPath: {
                type: "string",
                description:
                  "The optional path to list files from. If not provided, the root is used.",
              },
            },
            required: [],
          },
        },
        {
          name: "storage_get_file_info",
          description:
            "Get file information including metadata and download URL",
          inputSchema: {
            type: "object",
            properties: {
              filePath: {
                type: "string",
                description: "The path of the file to get information for",
              },
            },
            required: ["filePath"],
          },
        },
      ],
    }));

    // Handle tool execution
    this.server.setRequestHandler(
      CallToolRequestSchema,
      async (request: any) => {
        const { name, arguments: args = {} } = request.params;

        switch (name) {
          case "firestore_add_document":
            return firestore.addDocument(
              args.collection as string,
              args.data as object
            );

          case "firestore_list_documents":
            return firestore.listDocuments(
              args.collection as string,
              args.filters as Array<{
                field: string;
                operator: any;
                value: any;
              }>,
              args.limit as number,
              args.pageToken as string | undefined
            );

          case "firestore_get_document":
            return firestore.getDocument(
              args.collection as string,
              args.id as string
            );

          case "firestore_update_document":
            return firestore.updateDocument(
              args.collection as string,
              args.id as string,
              args.data as object
            );

          case "firestore_delete_document":
            return firestore.deleteDocument(
              args.collection as string,
              args.id as string
            );

          case "firestore_list_collections":
            return firestore.list_collections(
              args.documentPath as string | undefined,
              args.limit as number | undefined,
              args.pageToken as string | undefined
            );

          case "auth_get_user":
            return auth.getUserByIdOrEmail(args.identifier as string);

          case "storage_list_files":
            return storage.listDirectoryFiles(
              args.directoryPath as string | undefined,
              args.pageSize as number | undefined,
              args.pageToken as string | undefined
            );

          case "storage_get_file_info":
            return storage.getFileInfo(args.filePath as string);

          default:
            throw new McpError(
              ErrorCode.MethodNotFound,
              `Unknown tool: ${name}`
            );
        }
      }
    );
  }

  /**
   * Set up error handling for the server
   */
  private setupErrorHandling(): void {
    // Handle errors
    this.server.onerror = (error: any) => {
      const errorMessage =
        error instanceof Error ? error.message : "Unknown error";
      console.error("[MCP Error]", errorMessage);
    };

    // Handle graceful shutdown
    process.on("SIGINT", async () => {
      await this.stop();
      process.exit(0);
    });
  }

  /**
   * Initialize the first admin client if none exists
   * This ensures there's always at least one client that can access the server
   */
  private initializeAdminClient(): void {
    const security = require("./security");
    const clientsConfigPath = path.join(process.cwd(), "clients.json");

    try {
      if (fs.existsSync(clientsConfigPath)) {
        const clientsData = JSON.parse(
          fs.readFileSync(clientsConfigPath, "utf8")
        );
        if (Array.isArray(clientsData) && clientsData.length > 0) {
          return; // Already have clients, no need to create admin
        }
      }

      // Create admin client with provided or generated API key
      const apiKey = this.options.adminApiKey || security.generateApiKey();
      const client = security.addClient("admin", "Administrator account");

      // Add full access to all resources
      security.addAccessRule("admin", "*", ["*"]);

      // Set generous rate limits for admin
      security.setRateLimit("admin", "*", 600, 100);

      console.error(`Created admin client with API key: ${client.apiKey}`);
      console.error("IMPORTANT: Save this API key in a secure location!");

      // Save the API key to a file for reference
      const apiKeyPath = path.join(process.cwd(), "admin-api-key.txt");
      fs.writeFileSync(apiKeyPath, client.apiKey);
      console.error(`API key saved to: ${apiKeyPath}`);
    } catch (error) {
      const errorMessage =
        error instanceof Error ? error.message : "Unknown error";
      console.error(`Failed to initialize admin client: ${errorMessage}`);
    }
  }

  /**
   * Start the server with the configured transport
   */
  public async start(): Promise<void> {
    try {
      let transport;

      if (this.options.transport === "http") {
        // Create Express app
        this.expressApp = express();

        // Set up JSON body parsing
        this.expressApp.use(json());

        // Apply security middleware if enabled
        if (this.options.enableSecurity) {
          applySecurityMiddleware(this.expressApp);
          this.initializeAdminClient();

          // Mount admin API routes
          this.expressApp.use("/admin", adminRouter);
        }

        // Set up transport with Express app
        transport = new HttpServerTransport({
          app: this.expressApp,
          cors: {
            origin: this.options.corsOrigins || "*",
          },
        });

        // Connect server to transport
        await this.server.connect(transport);

        // Start listening on port
        const httpServer = this.expressApp.listen(this.options.port, () => {
          console.error(
            `Firebase MCP server running on HTTP at port ${this.options.port}`
          );
          console.error(
            `Security is ${
              this.options.enableSecurity ? "enabled" : "disabled"
            }`
          );
        });
      } else {
        // Use stdio transport
        transport = new StdioServerTransport();
        await this.server.connect(transport);
        console.error("Firebase MCP server running on stdio");
        console.error(
          `Security is ${this.options.enableSecurity ? "enabled" : "disabled"}`
        );
      }
    } catch (error) {
      const errorMessage =
        error instanceof Error ? error.message : "Unknown error";
      console.error(`Failed to start server: ${errorMessage}`);
      throw error;
    }
  }

  /**
   * Stop the server
   */
  public async stop(): Promise<void> {
    try {
      await this.server.close();
      console.error("Server stopped");
    } catch (error) {
      const errorMessage =
        error instanceof Error ? error.message : "Unknown error";
      console.error(`Error stopping server: ${errorMessage}`);
    }
  }
}

// Export the server class
export default FirebaseMcpServer;
