/**
 * Configuration Module
 *
 * This module centralizes configuration settings for the Firebase MCP server.
 * It handles environment variable parsing and provides default values for various settings.
 *
 * Environment variables:
 * - SERVICE_ACCOUNT_KEY_PATH: Path to Firebase service account key (required)
 * - FIREBASE_STORAGE_BUCKET: Firebase Storage bucket name (optional)
 * - FIRESTORE_DATABASE_ID: Firestore database ID (optional, defaults to '(default)')
 * - MCP_TRANSPORT: Transport type to use (stdio, http) (default: stdio)
 * - MCP_HTTP_PORT: Port for HTTP transport (default: 3000)
 * - MCP_HTTP_HOST: Host for HTTP transport (default: localhost)
 * - MCP_HTTP_PATH: Path for HTTP transport (default: /mcp)
 *
 * @module firebase-mcp/config
 */

// Load environment variables from .env file
import dotenv from 'dotenv';
import { logger } from './utils/logger.js';

// Load .env file
dotenv.config();

/**
 * Transport types supported by the server
 */
export enum TransportType {
  STDIO = 'stdio',
  HTTP = 'http',
}

/**
 * Server configuration interface
 */
export interface ServerConfig {
  /** Firebase service account key path */
  serviceAccountKeyPath: string | null;
  /** Firebase storage bucket name */
  storageBucket: string | null;
  /** Firestore database ID (defaults to '(default)') */
  firestoreDatabaseId: string | null;
  /** Transport type (stdio, http) */
  transport: TransportType;
  /** HTTP transport configuration */
  http: {
    /** HTTP port */
    port: number;
    /** HTTP host */
    host: string;
    /** HTTP path */
    path: string;
  };
  /** Server version */
  version: string;
  /** Server name */
  name: string;
}

/**
 * Detect if we're being run in a stdio context
 * @returns True if running in a stdio context
 */
export function isStdioContext(): boolean {
  return (
    !process.env.FORCE_HTTP_TRANSPORT &&
    process.stdin.isTTY === false &&
    process.stdout.isTTY === false
  );
}

/**
 * Check if an HTTP server is already running on the specified host and port
 * @param host Host to check
 * @param port Port to check
 * @returns Promise that resolves to true if a server is running
 */
export async function isHttpServerRunning(host: string, port: number): Promise<boolean> {
  try {
    // Use fetch to check if server is running
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 500);

    await fetch(`http://${host}:${port}`, {
      method: 'HEAD',
      signal: controller.signal,
    });

    clearTimeout(timeoutId);
    return true;
  } catch {
    return false;
  }
}

/**
 * Get configuration from environment variables
 * @returns Server configuration object
 */
export function getConfig(): ServerConfig {
  // Determine transport type based on context
  let transportStr = process.env.MCP_TRANSPORT || TransportType.STDIO;

  // If we're in a stdio context, force stdio transport
  if (isStdioContext()) {
    logger.debug('Detected stdio context, using stdio transport');
    transportStr = TransportType.STDIO;
  }

  // Validate transport type
  const transport = Object.values(TransportType).includes(transportStr as TransportType)
    ? (transportStr as TransportType)
    : TransportType.STDIO;

  // Log transport configuration
  logger.debug(`Using transport: ${transport}`);

  // Parse HTTP configuration if using HTTP transport
  if (transport === TransportType.HTTP) {
    logger.debug('Configuring HTTP transport');
  }

  // Create configuration object
  const config: ServerConfig = {
    // Client-provided environment variables take precedence over .env
    serviceAccountKeyPath: process.env.SERVICE_ACCOUNT_KEY_PATH || null,
    storageBucket: process.env.FIREBASE_STORAGE_BUCKET || null,
    firestoreDatabaseId: process.env.FIRESTORE_DATABASE_ID || null,
    transport,
    http: {
      port: parseInt(process.env.MCP_HTTP_PORT || '3000', 10),
      host: process.env.MCP_HTTP_HOST || 'localhost',
      path: process.env.MCP_HTTP_PATH || '/mcp',
    },
    version: process.env.npm_package_version || '1.3.5',
    name: 'firebase-mcp',
  };

  return config;
}

// Export default configuration
export default getConfig();
