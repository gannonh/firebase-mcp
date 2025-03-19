/**
 * Admin API Routes
 *
 * This module provides REST API routes for administrative operations such as
 * managing clients, access rules, rate limits, and querying audit logs.
 */

import { Router, Request, Response, NextFunction } from "express";
import { generateApiKey, addClient, getClients } from "../lib/security/auth";
import { addAccessRule, getAccessRules } from "../lib/security/accessControl";
import { setRateLimit, getRateLimits } from "../lib/security/rateLimiter";
import { queryAuditLogs } from "../lib/security/auditLogger";

// Admin API router
const adminRouter = Router();

// Middleware to verify admin API key
const verifyAdminApiKey = (req: Request, res: Response, next: NextFunction) => {
  const apiKey = req.headers["x-api-key"];

  // Check if API key is provided
  if (!apiKey) {
    return res.status(401).json({ error: "API key is required" });
  }

  // Get admin API key from environment variable
  const adminApiKey = process.env.ADMIN_API_KEY;

  // Verify that the API key matches the admin API key
  if (apiKey !== adminApiKey) {
    return res.status(403).json({ error: "Invalid API key" });
  }

  // Admin authentication successful
  next();
};

// Apply admin authentication middleware to all routes
adminRouter.use(verifyAdminApiKey);

// Get all clients
adminRouter.get("/clients", (req: Request, res: Response) => {
  try {
    const clients = getClients();
    res.json(clients);
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unknown error";
    res.status(500).json({ error: message });
  }
});

// Add a new client
adminRouter.post("/clients", (req: Request, res: Response) => {
  try {
    const { clientId, description } = req.body;

    // Validate input
    if (!clientId) {
      return res.status(400).json({ error: "Client ID is required" });
    }

    // Add the client
    const client = addClient(clientId, description);
    res.status(201).json(client);
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unknown error";
    res.status(500).json({ error: message });
  }
});

// Generate a new API key
adminRouter.post("/generate-api-key", (req: Request, res: Response) => {
  try {
    const apiKey = generateApiKey();
    res.json({ apiKey });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unknown error";
    res.status(500).json({ error: message });
  }
});

// Get all access rules
adminRouter.get("/access-rules", (req: Request, res: Response) => {
  try {
    const rules = getAccessRules();
    res.json(rules);
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unknown error";
    res.status(500).json({ error: message });
  }
});

// Add a new access rule
adminRouter.post("/access-rules", (req: Request, res: Response) => {
  try {
    const { clientId, resource, operations } = req.body;

    // Validate input
    if (!clientId || !resource || !operations) {
      return res
        .status(400)
        .json({ error: "Client ID, resource, and operations are required" });
    }

    // Add the access rule
    const rule = addAccessRule(clientId, resource, operations);
    res.status(201).json(rule);
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unknown error";
    res.status(500).json({ error: message });
  }
});

// Get all rate limits
adminRouter.get("/rate-limits", (req: Request, res: Response) => {
  try {
    const limits = getRateLimits();
    res.json(limits);
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unknown error";
    res.status(500).json({ error: message });
  }
});

// Set a rate limit
adminRouter.post("/rate-limits", (req: Request, res: Response) => {
  try {
    const { clientId, resource, windowSeconds, maxRequests } = req.body;

    // Validate input
    if (!clientId || !resource || !windowSeconds || !maxRequests) {
      return res.status(400).json({
        error:
          "Client ID, resource, window seconds, and max requests are required",
      });
    }

    // Set the rate limit
    const limit = setRateLimit(clientId, resource, windowSeconds, maxRequests);
    res.status(201).json(limit);
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unknown error";
    res.status(500).json({ error: message });
  }
});

// Query audit logs
adminRouter.get("/audit-logs", (req: Request, res: Response) => {
  try {
    const { clientId, operation, resource, status, startTime, endTime, limit } =
      req.query;

    // Query the audit logs
    const logs = queryAuditLogs({
      clientId: clientId as string,
      operation: operation as string,
      resource: resource as string,
      status: status as string,
      startTime: startTime as string,
      endTime: endTime as string,
      limit: limit ? parseInt(limit as string) : undefined,
    });

    res.json(logs);
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unknown error";
    res.status(500).json({ error: message });
  }
});

export default adminRouter;
