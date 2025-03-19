/**
 * Authentication Module
 *
 * This module provides authentication and client management functionality for the Firebase MCP server.
 *
 * @module firebase-mcp/security/auth
 */

import fs from "fs";
import path from "path";
import crypto from "crypto";

export interface Client {
  clientId: string;
  apiKey: string;
  description?: string;
  created: string;
  lastAccess?: string;
  status: "active" | "disabled";
}

export interface AuthOptions {
  clientsConfigPath: string;
  apiKeyLength: number;
}

const DEFAULT_OPTIONS: AuthOptions = {
  clientsConfigPath:
    process.env.CLIENTS_CONFIG_PATH || path.join(process.cwd(), "clients.json"),
  apiKeyLength: 32,
};

/**
 * Auth manager class that handles client authentication
 */
export class AuthManager {
  private options: AuthOptions;
  private clients: Map<string, Client> = new Map();
  private apiKeys: Map<string, string> = new Map(); // Maps API key to client ID

  /**
   * Creates a new auth manager instance
   * @param options Authentication configuration options
   */
  constructor(options: Partial<AuthOptions> = {}) {
    this.options = { ...DEFAULT_OPTIONS, ...options };
    this.loadClients();
  }

  /**
   * Load clients from the JSON file
   */
  private loadClients(): void {
    try {
      if (fs.existsSync(this.options.clientsConfigPath)) {
        const clientsData = JSON.parse(
          fs.readFileSync(this.options.clientsConfigPath, "utf8")
        );

        if (Array.isArray(clientsData)) {
          clientsData.forEach((client) => {
            if (client.clientId && client.apiKey) {
              this.clients.set(client.clientId, client as Client);
              this.apiKeys.set(client.apiKey, client.clientId);
            }
          });
          console.error(`Loaded ${this.clients.size} clients`);
        }
      } else {
        // Create empty clients file if it doesn't exist
        fs.writeFileSync(
          this.options.clientsConfigPath,
          JSON.stringify([], null, 2)
        );
        console.error(
          `Created empty clients file at ${this.options.clientsConfigPath}`
        );
      }
    } catch (error) {
      const errorMessage =
        error instanceof Error ? error.message : "Unknown error";
      console.error(`Failed to load clients: ${errorMessage}`);
    }
  }

  /**
   * Save clients to the JSON file
   */
  private saveClients(): void {
    try {
      const clientsData = Array.from(this.clients.values());
      fs.writeFileSync(
        this.options.clientsConfigPath,
        JSON.stringify(clientsData, null, 2)
      );
    } catch (error) {
      const errorMessage =
        error instanceof Error ? error.message : "Unknown error";
      console.error(`Failed to save clients: ${errorMessage}`);
    }
  }

  /**
   * Generate a secure API key
   * @returns New API key
   */
  public generateApiKey(): string {
    return crypto
      .randomBytes(this.options.apiKeyLength)
      .toString("base64")
      .replace(/[+/=]/g, "")
      .substring(0, this.options.apiKeyLength);
  }

  /**
   * Add a new client
   * @param clientId Client identifier
   * @param description Optional client description
   * @returns The created client
   */
  public addClient(clientId: string, description?: string): Client {
    // Check if client already exists
    if (this.clients.has(clientId)) {
      throw new Error(`Client with ID '${clientId}' already exists`);
    }

    // Generate API key for the client
    const apiKey = this.generateApiKey();

    // Create the client record
    const client: Client = {
      clientId,
      apiKey,
      description,
      created: new Date().toISOString(),
      status: "active",
    };

    // Add client to maps
    this.clients.set(clientId, client);
    this.apiKeys.set(apiKey, clientId);

    // Save changes
    this.saveClients();

    return client;
  }

  /**
   * Get a client by ID
   * @param clientId Client identifier
   * @returns Client object or undefined if not found
   */
  public getClient(clientId: string): Client | undefined {
    return this.clients.get(clientId);
  }

  /**
   * Get a client by API key
   * @param apiKey API key
   * @returns Client object or undefined if not found
   */
  public getClientByApiKey(apiKey: string): Client | undefined {
    const clientId = this.apiKeys.get(apiKey);
    if (clientId) {
      return this.clients.get(clientId);
    }
    return undefined;
  }

  /**
   * Validate an API key
   * @param apiKey API key to validate
   * @returns Client ID if valid, undefined otherwise
   */
  public validateApiKey(apiKey: string): string | undefined {
    const clientId = this.apiKeys.get(apiKey);

    if (clientId) {
      const client = this.clients.get(clientId);

      if (client && client.status === "active") {
        // Update last access time
        client.lastAccess = new Date().toISOString();
        return clientId;
      }
    }

    return undefined;
  }

  /**
   * Get all clients
   * @returns Array of all clients
   */
  public getClients(): Client[] {
    return Array.from(this.clients.values());
  }

  /**
   * Disable a client
   * @param clientId Client identifier
   * @returns True if client was disabled, false if not found
   */
  public disableClient(clientId: string): boolean {
    const client = this.clients.get(clientId);

    if (client) {
      client.status = "disabled";
      this.saveClients();
      return true;
    }

    return false;
  }

  /**
   * Enable a client
   * @param clientId Client identifier
   * @returns True if client was enabled, false if not found
   */
  public enableClient(clientId: string): boolean {
    const client = this.clients.get(clientId);

    if (client) {
      client.status = "active";
      this.saveClients();
      return true;
    }

    return false;
  }

  /**
   * Regenerate API key for a client
   * @param clientId Client identifier
   * @returns New API key or undefined if client not found
   */
  public regenerateApiKey(clientId: string): string | undefined {
    const client = this.clients.get(clientId);

    if (client) {
      // Remove old API key mapping
      this.apiKeys.delete(client.apiKey);

      // Generate new API key
      const newApiKey = this.generateApiKey();

      // Update client and mappings
      client.apiKey = newApiKey;
      this.apiKeys.set(newApiKey, clientId);

      // Save changes
      this.saveClients();

      return newApiKey;
    }

    return undefined;
  }
}

// Create singleton instance
const authManager = new AuthManager();

/**
 * Generate a new API key
 * @returns New API key
 */
export function generateApiKey(): string {
  return authManager.generateApiKey();
}

/**
 * Add a new client
 * @param clientId Client identifier
 * @param description Optional client description
 * @returns The created client
 */
export function addClient(clientId: string, description?: string): Client {
  return authManager.addClient(clientId, description);
}

/**
 * Get all clients
 * @returns Array of all clients
 */
export function getClients(): Client[] {
  return authManager.getClients();
}

/**
 * Validate an API key
 * @param apiKey API key to validate
 * @returns Client ID if valid, undefined otherwise
 */
export function validateApiKey(apiKey: string): string | undefined {
  return authManager.validateApiKey(apiKey);
}

export default authManager;
