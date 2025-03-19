/**
 * Security Module Integration
 *
 * This module integrates all security components for the Firebase MCP server.
 * It exports middleware functions and utility methods for security features.
 *
 * @module firebase-mcp/security
 */

import express from "express";
import { authMiddleware } from "./authMiddleware";
import { accessControl } from "./accessControl";
import { rateLimiter } from "./rateLimiter";
import { auditLogger } from "./auditLogger";

/**
 * Apply all security middleware to an Express application
 * @param app Express application instance
 */
export function applySecurityMiddleware(app: express.Application): void {
  // Apply security middleware in the correct order

  // 1. Authentication - Must come first to establish identity
  app.use(authMiddleware.authenticate.bind(authMiddleware));

  // 2. Access Control - After authentication to check permissions
  app.use(accessControl.checkAccessMiddleware.bind(accessControl));

  // 3. Rate Limiting - After authentication and access control
  app.use(rateLimiter.rateLimitMiddleware.bind(rateLimiter));

  // 4. Audit Logging - Last to capture all request details
  app.use(auditLogger.auditMiddleware.bind(auditLogger));

  // Set up periodic tasks
  setInterval(() => {
    authMiddleware.cleanupSessions();
  }, 60 * 60 * 1000); // Clean up sessions every hour

  console.error("Security middleware applied");
}

// Re-export all security components
export { authMiddleware, accessControl, rateLimiter, auditLogger };

// Export utility functions
export function generateApiKey(): string {
  const crypto = require("crypto");
  return crypto.randomBytes(32).toString("hex");
}

export function addClient(
  clientId: string,
  description: string = ""
): { clientId: string; apiKey: string } {
  const apiKey = generateApiKey();
  const client = authMiddleware.addClient(clientId, apiKey, description);

  return {
    clientId: client.clientId,
    apiKey, // Return the unhashed API key to the caller
  };
}

export function addAccessRule(
  clientId: string,
  resource: string,
  actions: string[]
): void {
  accessControl.addRule({
    clientId,
    resource,
    actions,
  });
}

export function setRateLimit(
  clientId: string,
  operation: string,
  requestsPerMinute: number,
  burstCapacity: number
): void {
  rateLimiter.setRateLimit(clientId, operation, {
    requestsPerMinute,
    burstCapacity,
  });
}

export async function queryAuditLogs(
  criteria: any,
  limit?: number,
  offset?: number
): Promise<any[]> {
  return auditLogger.queryLogs(criteria, limit, offset);
}
