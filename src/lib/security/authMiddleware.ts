/**
 * Authentication Middleware Module
 *
 * This module provides client authentication for the Firebase MCP server.
 * It verifies API keys and manages authentication tokens for client requests.
 *
 * @module firebase-mcp/security/auth
 */

import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";
import * as crypto from "crypto";
import { McpError, ErrorCode } from "../../lib/types";
import fs from "fs";
import path from "path";

// Interfaces for authentication data types
export interface Client {
  clientId: string;
  apiKey: string; // Stored as hash
  description: string;
  createdAt: number;
  updatedAt: number;
  status: "active" | "disabled";
}

export interface Session {
  sessionId: string;
  clientId: string;
  token: string;
  createdAt: number;
  expiresAt: number;
  lastUsed: number;
}

export interface AuthOptions {
  apiKeyHeader: string;
  tokenHeader: string;
  sessionHeader: string;
  jwtSecret: string;
  tokenExpirationMinutes: number;
  clientsConfigPath: string;
}

const DEFAULT_OPTIONS: AuthOptions = {
  apiKeyHeader: "x-api-key",
  tokenHeader: "x-auth-token",
  sessionHeader: "x-session-id",
  jwtSecret: process.env.JWT_SECRET || crypto.randomBytes(64).toString("hex"),
  tokenExpirationMinutes: 60, // 1 hour by default
  clientsConfigPath:
    process.env.CLIENTS_CONFIG_PATH || path.join(process.cwd(), "clients.json"),
};

/**
 * Authentication middleware class that handles client authentication
 */
export class AuthMiddleware {
  private options: AuthOptions;
  private clients: Map<string, Client> = new Map();
  private sessions: Map<string, Session> = new Map();
  private failedAttempts: Map<string, { count: number; lastAttempt: number }> =
    new Map();

  /**
   * Creates a new authentication middleware instance
   * @param options Authentication configuration options
   */
  constructor(options: Partial<AuthOptions> = {}) {
    this.options = { ...DEFAULT_OPTIONS, ...options };
    this.loadClients();

    // Log but don't break if JWT_SECRET isn't set in production
    if (!process.env.JWT_SECRET && process.env.NODE_ENV === "production") {
      console.warn(
        "WARNING: JWT_SECRET not set in production environment. Using random secret."
      );
    }
  }

  /**
   * Load client configurations from the JSON file
   */
  private loadClients(): void {
    try {
      if (fs.existsSync(this.options.clientsConfigPath)) {
        const clientsData = JSON.parse(
          fs.readFileSync(this.options.clientsConfigPath, "utf8")
        );

        if (Array.isArray(clientsData)) {
          clientsData.forEach((client) => {
            if (client.clientId && client.apiKey && client.status) {
              this.clients.set(client.clientId, client as Client);
            }
          });
          console.error(`Loaded ${this.clients.size} client configurations`);
        }
      } else {
        // Create empty clients file if it doesn't exist
        fs.writeFileSync(
          this.options.clientsConfigPath,
          JSON.stringify([], null, 2)
        );
        console.error(
          `Created empty clients configuration file at ${this.options.clientsConfigPath}`
        );
      }
    } catch (error) {
      const errorMessage =
        error instanceof Error ? error.message : "Unknown error";
      console.error(`Failed to load client configurations: ${errorMessage}`);
    }
  }

  /**
   * Save client configurations to the JSON file
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
      console.error(`Failed to save client configurations: ${errorMessage}`);
    }
  }

  /**
   * Add a new client with the given API key
   * @param clientId Client identifier
   * @param apiKey API key for the client
   * @param description Optional description of the client
   * @returns The created client object (with hashed API key)
   */
  public addClient(
    clientId: string,
    apiKey: string,
    description: string = ""
  ): Client {
    if (this.clients.has(clientId)) {
      throw new Error(`Client with ID ${clientId} already exists`);
    }

    const client: Client = {
      clientId,
      apiKey: this.hashApiKey(apiKey),
      description,
      createdAt: Date.now(),
      updatedAt: Date.now(),
      status: "active",
    };

    this.clients.set(clientId, client);
    this.saveClients();
    return client;
  }

  /**
   * Validate the client API key
   * @param clientId Client identifier
   * @param apiKey API key to validate
   * @returns True if the API key is valid, false otherwise
   */
  private validateApiKey(clientId: string, apiKey: string): boolean {
    const client = this.clients.get(clientId);
    if (!client || client.status !== "active") {
      return false;
    }

    // Compare the hash of the provided API key with the stored hash
    return this.hashApiKey(apiKey) === client.apiKey;
  }

  /**
   * Hash an API key for secure storage
   * @param apiKey API key to hash
   * @returns Hashed API key
   */
  private hashApiKey(apiKey: string): string {
    return crypto.createHash("sha256").update(apiKey).digest("hex");
  }

  /**
   * Generate a JWT token for the client
   * @param clientId Client identifier
   * @returns JWT token string
   */
  private generateToken(clientId: string): string {
    const expiresIn = this.options.tokenExpirationMinutes * 60;
    return jwt.sign({ clientId }, this.options.jwtSecret, { expiresIn });
  }

  /**
   * Verify a JWT token
   * @param token JWT token to verify
   * @returns Payload with client ID if valid, null otherwise
   */
  private verifyToken(token: string): { clientId: string } | null {
    try {
      return jwt.verify(token, this.options.jwtSecret) as { clientId: string };
    } catch (error) {
      return null;
    }
  }

  /**
   * Create a new session for a client
   * @param clientId Client identifier
   * @returns Session object
   */
  private createSession(clientId: string): Session {
    const sessionId = crypto.randomBytes(16).toString("hex");
    const token = this.generateToken(clientId);
    const now = Date.now();

    const session: Session = {
      sessionId,
      clientId,
      token,
      createdAt: now,
      expiresAt: now + this.options.tokenExpirationMinutes * 60 * 1000,
      lastUsed: now,
    };

    this.sessions.set(sessionId, session);
    return session;
  }

  /**
   * Express middleware to authenticate requests
   * @param req Express request object
   * @param res Express response object
   * @param next Express next function
   */
  public authenticate(req: any, res: Response, next: NextFunction): void {
    try {
      const clientId = req.headers["x-client-id"] as string;
      const apiKey = req.headers[
        this.options.apiKeyHeader.toLowerCase()
      ] as string;
      const sessionId = req.headers[
        this.options.sessionHeader.toLowerCase()
      ] as string;
      const token = req.headers[
        this.options.tokenHeader.toLowerCase()
      ] as string;

      // Check rate limiting for failed attempts
      const clientIp = req.ip || "unknown";
      const ipKey = `${clientIp}:${clientId || "anonymous"}`;

      if (this.failedAttempts.has(ipKey)) {
        const attempts = this.failedAttempts.get(ipKey)!;

        // Reset after 15 minutes
        if (Date.now() - attempts.lastAttempt > 15 * 60 * 1000) {
          this.failedAttempts.delete(ipKey);
        }
        // If more than 5 failed attempts in the last 15 minutes, reject
        else if (attempts.count >= 5) {
          throw new McpError(
            ErrorCode.MethodNotFound,
            "Too many failed authentication attempts. Try again later."
          );
        }
      }

      // Case 1: Session ID provided - validate existing session
      if (sessionId) {
        const session = this.sessions.get(sessionId);

        if (!session) {
          this.recordFailedAttempt(ipKey);
          throw new McpError(ErrorCode.MethodNotFound, "Invalid session");
        }

        if (session.expiresAt < Date.now()) {
          this.sessions.delete(sessionId);
          this.recordFailedAttempt(ipKey);
          throw new McpError(ErrorCode.MethodNotFound, "Session expired");
        }

        // Update last used timestamp
        session.lastUsed = Date.now();

        // Add authentication context to request
        req.auth = { clientId: session.clientId, sessionId };
        return next();
      }

      // Case 2: API key provided - validate and create new session
      if (clientId && apiKey) {
        if (!this.validateApiKey(clientId, apiKey)) {
          this.recordFailedAttempt(ipKey);
          throw new McpError(ErrorCode.MethodNotFound, "Invalid API key");
        }

        // Create new session and add to request
        const session = this.createSession(clientId);

        // Add session headers to response
        res.setHeader(this.options.sessionHeader, session.sessionId);
        res.setHeader(this.options.tokenHeader, session.token);

        // Add authentication context to request
        req.auth = { clientId, sessionId: session.sessionId };
        return next();
      }

      // Case 3: Token provided - validate and create session if needed
      if (token) {
        const payload = this.verifyToken(token);

        if (!payload) {
          this.recordFailedAttempt(ipKey);
          throw new McpError(ErrorCode.MethodNotFound, "Invalid token");
        }

        // Create new session and add to request
        const session = this.createSession(payload.clientId);

        // Add session headers to response
        res.setHeader(this.options.sessionHeader, session.sessionId);

        // Add authentication context to request
        req.auth = { clientId: payload.clientId, sessionId: session.sessionId };
        return next();
      }

      // No authentication provided
      this.recordFailedAttempt(ipKey);
      throw new McpError(ErrorCode.MethodNotFound, "Authentication required");
    } catch (error) {
      // Pass MCP errors through
      if (error instanceof McpError) {
        return next(error);
      }

      // Convert other errors to MCP errors
      const errorMessage =
        error instanceof Error ? error.message : "Unknown authentication error";
      return next(new McpError(ErrorCode.MethodNotFound, errorMessage));
    }
  }

  /**
   * Record a failed authentication attempt
   * @param ipKey IP and client ID combination key
   */
  private recordFailedAttempt(ipKey: string): void {
    const now = Date.now();

    if (this.failedAttempts.has(ipKey)) {
      const attempts = this.failedAttempts.get(ipKey)!;
      attempts.count += 1;
      attempts.lastAttempt = now;
    } else {
      this.failedAttempts.set(ipKey, { count: 1, lastAttempt: now });
    }
  }

  /**
   * Clean up expired sessions
   */
  public cleanupSessions(): void {
    const now = Date.now();

    // Remove expired sessions
    for (const [sessionId, session] of this.sessions.entries()) {
      if (session.expiresAt < now) {
        this.sessions.delete(sessionId);
      }
    }
  }
}

// Create an authentication middleware instance with default options
const authMiddleware = new AuthMiddleware();

export { authMiddleware };
