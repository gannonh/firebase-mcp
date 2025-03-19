/**
 * Firebase MCP Server Entry Point
 *
 * This is the main entry point for the Firebase MCP server with security enhancements.
 * It initializes and starts the server with the configured options.
 */

import FirebaseMcpServer from "./lib/server";
import dotenv from "dotenv";

// Load environment variables
dotenv.config();

async function main() {
  try {
    console.error("Starting Firebase MCP server...");

    // Create server instance with options from environment variables
    const server = new FirebaseMcpServer({
      name: process.env.SERVER_NAME,
      version: process.env.SERVER_VERSION,
      port: process.env.PORT ? parseInt(process.env.PORT, 10) : undefined,
      transport: process.env.TRANSPORT as "http" | "stdio",
      enableSecurity: process.env.ENABLE_SECURITY !== "false",
      adminApiKey: process.env.ADMIN_API_KEY,
      corsOrigins: process.env.CORS_ORIGINS
        ? process.env.CORS_ORIGINS.split(",")
        : undefined,
    });

    // Start the server
    await server.start();

    console.error("Server started successfully");
  } catch (error) {
    console.error("Failed to start server:", error);
    process.exit(1);
  }
}

// Run the main function
main();
