/**
 * Access Control Middleware Module
 *
 * This module provides resource-level access control for the Firebase MCP server.
 * It manages permissions for different clients to access Firebase resources.
 *
 * @module firebase-mcp/security/access-control
 */

import { Request, Response, NextFunction } from "express";
import { McpError, ErrorCode } from "../../lib/types";
import fs from "fs";
import path from "path";

export interface AccessRule {
  clientId: string;
  resource: string; // Resource pattern, e.g. "firestore/collection/{name}"
  actions: string[]; // Allowed actions, e.g. ["read", "write"]
  conditions?: {
    fields?: Record<string, any>; // Required field values
    custom?: string; // Custom condition expression
  };
}

export interface AccessControlOptions {
  rulesConfigPath: string;
  defaultDeny: boolean; // Whether to deny by default
}

const DEFAULT_OPTIONS: AccessControlOptions = {
  rulesConfigPath:
    process.env.ACCESS_RULES_PATH ||
    path.join(process.cwd(), "access-rules.json"),
  defaultDeny: true,
};

/**
 * Access control middleware class that manages resource permissions
 */
export class AccessControl {
  private options: AccessControlOptions;
  private rules: AccessRule[] = [];

  /**
   * Creates a new access control middleware instance
   * @param options Access control configuration options
   */
  constructor(options: Partial<AccessControlOptions> = {}) {
    this.options = { ...DEFAULT_OPTIONS, ...options };
    this.loadRules();
  }

  /**
   * Load access rules from the JSON file
   */
  private loadRules(): void {
    try {
      if (fs.existsSync(this.options.rulesConfigPath)) {
        const rulesData = JSON.parse(
          fs.readFileSync(this.options.rulesConfigPath, "utf8")
        );

        if (Array.isArray(rulesData)) {
          this.rules = rulesData.filter(
            (rule) =>
              rule.clientId && rule.resource && Array.isArray(rule.actions)
          );
          console.error(`Loaded ${this.rules.length} access rules`);
        }
      } else {
        // Create empty rules file if it doesn't exist
        fs.writeFileSync(
          this.options.rulesConfigPath,
          JSON.stringify([], null, 2)
        );
        console.error(
          `Created empty access rules file at ${this.options.rulesConfigPath}`
        );
      }
    } catch (error) {
      const errorMessage =
        error instanceof Error ? error.message : "Unknown error";
      console.error(`Failed to load access rules: ${errorMessage}`);
    }
  }

  /**
   * Save access rules to the JSON file
   */
  private saveRules(): void {
    try {
      fs.writeFileSync(
        this.options.rulesConfigPath,
        JSON.stringify(this.rules, null, 2)
      );
    } catch (error) {
      const errorMessage =
        error instanceof Error ? error.message : "Unknown error";
      console.error(`Failed to save access rules: ${errorMessage}`);
    }
  }

  /**
   * Add a new access rule
   * @param rule The access rule to add
   */
  public addRule(rule: AccessRule): void {
    // Validate rule fields
    if (
      !rule.clientId ||
      !rule.resource ||
      !Array.isArray(rule.actions) ||
      rule.actions.length === 0
    ) {
      throw new Error(
        "Invalid access rule: clientId, resource, and actions are required"
      );
    }

    // Check if rule already exists
    const existingIndex = this.rules.findIndex(
      (r) => r.clientId === rule.clientId && r.resource === rule.resource
    );

    if (existingIndex >= 0) {
      this.rules[existingIndex] = rule;
    } else {
      this.rules.push(rule);
    }

    this.saveRules();
  }

  /**
   * Remove an access rule
   * @param clientId Client identifier
   * @param resource Resource pattern
   */
  public removeRule(clientId: string, resource: string): void {
    const initialLength = this.rules.length;

    this.rules = this.rules.filter(
      (rule) => !(rule.clientId === clientId && rule.resource === resource)
    );

    if (this.rules.length !== initialLength) {
      this.saveRules();
    }
  }

  /**
   * Check if a pattern matches a resource string
   * @param pattern The pattern with possible wildcards
   * @param resource The actual resource string
   * @returns True if the pattern matches the resource
   */
  private matchPattern(pattern: string, resource: string): boolean {
    // Convert pattern to regex
    // - Replace wildcards with regex patterns
    // - Escape special regex characters
    // - Convert {param} placeholders to regex groups

    const regexPattern = pattern
      .replace(/[-\/\\^$*+?.()|[\]{}]/g, "\\$&") // Escape regex special chars
      .replace(/\\\*/g, ".*") // Replace * with .*
      .replace(/\\\{([^\\}]+)\\\}/g, "([^/]+)"); // Replace {param} with ([^/]+)

    const regex = new RegExp(`^${regexPattern}$`);
    return regex.test(resource);
  }

  /**
   * Check if a client has access to a resource for a specific action
   * @param clientId Client identifier
   * @param resource Resource string
   * @param action Action to perform
   * @param context Additional context for condition evaluation
   * @returns True if the client has access, false otherwise
   */
  public checkAccess(
    clientId: string,
    resource: string,
    action: string,
    context: Record<string, any> = {}
  ): boolean {
    // Find matching rules for the client
    const matchingRules = this.rules.filter(
      (rule) =>
        rule.clientId === clientId &&
        this.matchPattern(rule.resource, resource) &&
        rule.actions.includes(action)
    );

    if (matchingRules.length === 0) {
      return !this.options.defaultDeny;
    }

    // Check if any rule with conditions match
    for (const rule of matchingRules) {
      if (!rule.conditions) {
        return true; // No conditions means automatic access
      }

      // Check field conditions
      if (rule.conditions.fields) {
        let fieldsMatch = true;

        for (const [field, value] of Object.entries(rule.conditions.fields)) {
          if (!context[field] || context[field] !== value) {
            fieldsMatch = false;
            break;
          }
        }

        if (fieldsMatch) {
          return true;
        }
      }

      // TODO: Implement custom condition evaluation if needed
    }

    return false;
  }

  /**
   * Express middleware to check access for requests
   * @param req Express request object
   * @param res Express response object
   * @param next Express next function
   */
  public checkAccessMiddleware(
    req: any,
    res: Response,
    next: NextFunction
  ): void {
    // If auth context is not available, deny access
    if (!req.auth || !req.auth.clientId) {
      return next(
        new McpError(
          ErrorCode.MethodNotFound,
          "Authentication required for access control"
        )
      );
    }

    const clientId = req.auth.clientId;

    // Extract operation details - this will be customized based on application needs
    // Here we use a convention: operation name maps to action, and params.collection or params.path maps to resource
    const toolName = req.body?.method || "";
    let action = "unknown";
    let resource = "";

    // Map tool name to action and extract resource
    if (toolName.startsWith("firestore_")) {
      const params = req.body?.params?.arguments || {};
      action = toolName.replace("firestore_", "");
      resource = `firestore/collection/${params.collection || "*"}`;

      if (params.id) {
        resource += `/document/${params.id}`;
      }
    } else if (toolName.startsWith("storage_")) {
      const params = req.body?.params?.arguments || {};
      action = toolName.replace("storage_", "");
      resource = `storage/${params.filePath || params.directoryPath || "*"}`;
    } else if (toolName.startsWith("auth_")) {
      const params = req.body?.params?.arguments || {};
      action = toolName.replace("auth_", "");
      resource = `auth/${params.identifier || "*"}`;
    }

    // Check access
    if (
      !this.checkAccess(clientId, resource, action, req.body?.params?.arguments)
    ) {
      return next(
        new McpError(
          ErrorCode.MethodNotFound,
          `Access denied for ${clientId} to ${resource} with action ${action}`
        )
      );
    }

    // If access is granted, continue
    next();
  }

  /**
   * Get all access rules
   * @returns Array of all access rules
   */
  public getRules(): AccessRule[] {
    return this.rules;
  }
}

// Create singleton instance
const accessControl = new AccessControl();

/**
 * Add a new access rule
 * @param clientId Client identifier
 * @param resource Resource pattern
 * @param operations Array of allowed operations
 * @returns The added access rule
 */
export function addAccessRule(
  clientId: string,
  resource: string,
  operations: string[]
): AccessRule {
  const rule: AccessRule = {
    clientId,
    resource,
    actions: operations,
  };
  accessControl.addRule(rule);
  return rule;
}

/**
 * Get all access rules
 * @returns Array of all access rules
 */
export function getAccessRules(): AccessRule[] {
  // This function needs implementation in the AccessControl class
  return accessControl.getRules ? accessControl.getRules() : [];
}

export default accessControl;
