/**
 * Audit Logging Module
 *
 * This module provides audit logging for the Firebase MCP server.
 * It logs all operations for security monitoring and troubleshooting.
 *
 * @module firebase-mcp/security/audit-logger
 */

import { Request, Response, NextFunction } from "express";
import { McpError, ErrorCode } from "../../lib/types";
import fs from "fs";
import path from "path";
import zlib from "zlib";
import util from "util";

export interface AuditLog {
  id: string;
  timestamp: string;
  clientId: string;
  sessionId?: string;
  operation: string;
  resource: string;
  status: "success" | "error";
  errorMessage?: string;
  responseTime?: number;
  metadata: Record<string, any>;
}

export interface AuditLoggerOptions {
  logDir: string;
  retentionDays: number;
  logRotationFrequency: "daily" | "hourly";
  enableConsoleLogging: boolean;
  compress: boolean;
  sensitiveFields: string[];
  maxLogFileSizeMB: number;
}

const DEFAULT_OPTIONS: AuditLoggerOptions = {
  logDir: process.env.AUDIT_LOG_DIR || path.join(process.cwd(), "logs"),
  retentionDays: 30,
  logRotationFrequency: "daily",
  enableConsoleLogging: process.env.NODE_ENV !== "production",
  compress: true,
  sensitiveFields: ["password", "token", "apiKey", "secret", "credential"],
  maxLogFileSizeMB: 10,
};

/**
 * Audit logger class that handles operation logging
 */
export class AuditLogger {
  private options: AuditLoggerOptions;
  private currentLogFile: string = "";
  private currentLogStream: fs.WriteStream | null = null;
  private logQueue: AuditLog[] = [];
  private isProcessingQueue: boolean = false;
  private logCount: number = 0;

  /**
   * Creates a new audit logger instance
   * @param options Audit logger configuration options
   */
  constructor(options: Partial<AuditLoggerOptions> = {}) {
    this.options = { ...DEFAULT_OPTIONS, ...options };
    this.initLogDirectory();
    this.setupLogRotation();
    this.setupCleanupTask();

    // Process logs on exit
    process.on("exit", () => {
      this.flushLogs(true);
    });
  }

  /**
   * Initialize log directory
   */
  private initLogDirectory(): void {
    try {
      if (!fs.existsSync(this.options.logDir)) {
        fs.mkdirSync(this.options.logDir, { recursive: true });
      }
    } catch (error) {
      const errorMessage =
        error instanceof Error ? error.message : "Unknown error";
      console.error(`Failed to create log directory: ${errorMessage}`);
    }
  }

  /**
   * Setup log rotation based on configuration
   */
  private setupLogRotation(): void {
    // Determine rotation interval
    const interval =
      this.options.logRotationFrequency === "hourly"
        ? 60 * 60 * 1000
        : 24 * 60 * 60 * 1000;

    // Schedule log rotation
    setInterval(() => {
      this.rotateLog();
    }, interval);

    // Rotate log immediately
    this.rotateLog();
  }

  /**
   * Setup cleanup task for old log files
   */
  private setupCleanupTask(): void {
    // Run daily cleanup
    setInterval(() => {
      this.cleanupOldLogs();
    }, 24 * 60 * 60 * 1000);

    // Run cleanup on start
    this.cleanupOldLogs();
  }

  /**
   * Rotate log file to a new one
   */
  private rotateLog(): void {
    try {
      // Close current stream if it exists
      if (this.currentLogStream) {
        this.currentLogStream.end();
        this.currentLogStream = null;
      }

      // Create new log file name based on current date/time
      const now = new Date();
      const dateString = now.toISOString().split("T")[0]; // YYYY-MM-DD
      const timeString =
        this.options.logRotationFrequency === "hourly"
          ? now.toISOString().split("T")[1].substring(0, 2) // HH
          : "00";

      this.currentLogFile = path.join(
        this.options.logDir,
        `audit-${dateString}-${timeString}.log`
      );

      // Reset log count
      this.logCount = 0;
    } catch (error) {
      const errorMessage =
        error instanceof Error ? error.message : "Unknown error";
      console.error(`Failed to rotate log: ${errorMessage}`);
    }
  }

  /**
   * Clean up old log files based on retention policy
   */
  private cleanupOldLogs(): void {
    try {
      const files = fs.readdirSync(this.options.logDir);
      const now = new Date();
      const cutoffTime =
        now.getTime() - this.options.retentionDays * 24 * 60 * 60 * 1000;

      for (const file of files) {
        if (
          file.startsWith("audit-") &&
          (file.endsWith(".log") || file.endsWith(".log.gz"))
        ) {
          // Extract date from filename
          const dateMatch = file.match(/audit-(\d{4}-\d{2}-\d{2})-/);

          if (dateMatch && dateMatch[1]) {
            const fileDate = new Date(dateMatch[1]);

            if (fileDate.getTime() < cutoffTime) {
              const filePath = path.join(this.options.logDir, file);
              fs.unlinkSync(filePath);
              console.error(`Deleted old log file: ${file}`);
            }
          }
        }
      }
    } catch (error) {
      const errorMessage =
        error instanceof Error ? error.message : "Unknown error";
      console.error(`Failed to clean up old logs: ${errorMessage}`);
    }
  }

  /**
   * Sanitize sensitive data from log objects
   * @param obj Object to sanitize
   * @returns Sanitized object
   */
  private sanitizeObject(obj: any): any {
    if (obj === null || obj === undefined || typeof obj !== "object") {
      return obj;
    }

    const result: any = Array.isArray(obj) ? [] : {};

    for (const [key, value] of Object.entries(obj)) {
      // Check if key is in sensitive fields list
      if (
        this.options.sensitiveFields.some((field) =>
          key.toLowerCase().includes(field.toLowerCase())
        )
      ) {
        result[key] =
          typeof value === "string" ? "[REDACTED]" : "[REDACTED OBJECT]";
      }
      // Recursively sanitize objects
      else if (typeof value === "object" && value !== null) {
        result[key] = this.sanitizeObject(value);
      }
      // Copy non-sensitive values
      else {
        result[key] = value;
      }
    }

    return result;
  }

  /**
   * Write a log entry to the current log file
   * @param log Audit log entry
   */
  private writeLog(log: AuditLog): void {
    try {
      // Sanitize sensitive data
      const sanitizedLog = this.sanitizeObject(log);

      // Format log as JSON string
      const logString = JSON.stringify(sanitizedLog) + "\n";

      // Log to console if enabled
      if (this.options.enableConsoleLogging) {
        console.error(`AUDIT: ${logString.trim()}`);
      }

      // Ensure log stream is open
      if (!this.currentLogStream) {
        this.currentLogStream = fs.createWriteStream(this.currentLogFile, {
          flags: "a",
        });
      }

      // Write to log file
      this.currentLogStream.write(logString);

      // Increment log count
      this.logCount++;

      // Check if we need to rotate based on file size
      if (this.logCount > 1000) {
        // Check size every 1000 logs for performance
        try {
          const stats = fs.statSync(this.currentLogFile);
          const fileSizeMB = stats.size / (1024 * 1024);

          if (fileSizeMB >= this.options.maxLogFileSizeMB) {
            this.rotateLog();

            // Compress the old log file if enabled
            if (this.options.compress) {
              this.compressLogFile(this.currentLogFile);
            }
          }
        } catch (error) {
          // Ignore file stat errors
        }

        this.logCount = 0;
      }
    } catch (error) {
      const errorMessage =
        error instanceof Error ? error.message : "Unknown error";
      console.error(`Failed to write log: ${errorMessage}`);
    }
  }

  /**
   * Compress a log file using gzip
   * @param filePath Path to the log file
   */
  private compressLogFile(filePath: string): void {
    try {
      const gzip = zlib.createGzip();
      const source = fs.createReadStream(filePath);
      const destination = fs.createWriteStream(`${filePath}.gz`);

      source.pipe(gzip).pipe(destination);

      destination.on("finish", () => {
        // Delete the original file
        fs.unlinkSync(filePath);
      });
    } catch (error) {
      const errorMessage =
        error instanceof Error ? error.message : "Unknown error";
      console.error(`Failed to compress log file: ${errorMessage}`);
    }
  }

  /**
   * Add a log entry to the queue
   * @param log Audit log entry
   */
  public log(log: Partial<AuditLog>): void {
    // Create a complete log entry with defaults
    const completeLog: AuditLog = {
      id: this.generateLogId(),
      timestamp: new Date().toISOString(),
      clientId: log.clientId || "unknown",
      operation: log.operation || "unknown",
      resource: log.resource || "unknown",
      status: log.status || "success",
      metadata: log.metadata || {},
      ...log,
    };

    // Add to queue
    this.logQueue.push(completeLog);

    // Process queue if not already processing
    if (!this.isProcessingQueue) {
      this.processLogQueue();
    }
  }

  /**
   * Process log queue asynchronously
   */
  private async processLogQueue(): Promise<void> {
    if (this.isProcessingQueue || this.logQueue.length === 0) {
      return;
    }

    this.isProcessingQueue = true;

    try {
      // Process logs in batches
      while (this.logQueue.length > 0) {
        const batch = this.logQueue.splice(
          0,
          Math.min(100, this.logQueue.length)
        );

        for (const log of batch) {
          this.writeLog(log);
        }

        // Allow event loop to continue
        await new Promise((resolve) => setTimeout(resolve, 0));
      }
    } finally {
      this.isProcessingQueue = false;
    }
  }

  /**
   * Flush all logs immediately
   * @param sync Whether to flush synchronously
   */
  public flushLogs(sync: boolean = false): void {
    if (sync) {
      // Process all logs synchronously
      while (this.logQueue.length > 0) {
        const log = this.logQueue.shift();
        if (log) {
          this.writeLog(log);
        }
      }

      // Close the stream
      if (this.currentLogStream) {
        this.currentLogStream.end();
        this.currentLogStream = null;
      }
    } else {
      // Process asynchronously
      this.processLogQueue();
    }
  }

  /**
   * Generate a unique log ID
   * @returns Unique log ID
   */
  private generateLogId(): string {
    return (
      Math.random().toString(36).substring(2, 15) +
      Math.random().toString(36).substring(2, 15)
    );
  }

  /**
   * Query logs based on criteria
   * @param criteria Search criteria
   * @param limit Maximum number of results
   * @param offset Offset for pagination
   * @returns Matching log entries
   */
  public async queryLogs(
    criteria: Partial<AuditLog>,
    limit: number = 100,
    offset: number = 0
  ): Promise<AuditLog[]> {
    try {
      // Get list of log files sorted by date (newest first)
      const files = fs
        .readdirSync(this.options.logDir)
        .filter(
          (file) =>
            file.startsWith("audit-") &&
            (file.endsWith(".log") || file.endsWith(".log.gz"))
        )
        .sort()
        .reverse();

      const results: AuditLog[] = [];
      let count = 0;
      let skipped = 0;

      // Process each file until we reach the limit
      for (const file of files) {
        if (results.length >= limit) {
          break;
        }

        const filePath = path.join(this.options.logDir, file);
        let fileContent: string;

        // Read and decompress if needed
        if (file.endsWith(".log.gz")) {
          const compressed = fs.readFileSync(filePath);
          fileContent = zlib.gunzipSync(compressed).toString("utf8");
        } else {
          fileContent = fs.readFileSync(filePath, "utf8");
        }

        // Process each line
        const lines = fileContent
          .split("\n")
          .filter((line) => line.trim() !== "");

        for (const line of lines) {
          try {
            const log = JSON.parse(line) as AuditLog;
            let matches = true;

            // Check if log matches criteria
            for (const [key, value] of Object.entries(criteria)) {
              if (log[key as keyof AuditLog] !== value) {
                matches = false;
                break;
              }
            }

            if (matches) {
              count++;

              // Skip entries for pagination
              if (count > offset) {
                results.push(log);

                if (results.length >= limit) {
                  break;
                }
              } else {
                skipped++;
              }
            }
          } catch (error) {
            // Skip invalid log entries
          }
        }
      }

      return results;
    } catch (error) {
      const errorMessage =
        error instanceof Error ? error.message : "Unknown error";
      console.error(`Failed to query logs: ${errorMessage}`);
      return [];
    }
  }

  /**
   * Express middleware to log requests and responses
   * @param req Express request object
   * @param res Express response object
   * @param next Express next function
   */
  public auditMiddleware(req: any, res: any, next: NextFunction): void {
    // Record start time
    const startTime = Date.now();

    // Create a copy of the original response methods
    const originalSend = res.send;
    const originalJson = res.json;
    const originalEnd = res.end;

    // Get client ID and session ID from auth context
    const clientId = req.auth?.clientId || "anonymous";
    const sessionId = req.auth?.sessionId;

    // Extract operation details
    const toolName = req.body?.method || "unknown";
    let resource = "unknown";

    // Determine resource from request
    if (toolName.startsWith("firestore_")) {
      const params = req.body?.params?.arguments || {};
      resource = `firestore/collection/${params.collection || "*"}`;

      if (params.id) {
        resource += `/document/${params.id}`;
      }
    } else if (toolName.startsWith("storage_")) {
      const params = req.body?.params?.arguments || {};
      resource = `storage/${params.filePath || params.directoryPath || "*"}`;
    } else if (toolName.startsWith("auth_")) {
      const params = req.body?.params?.arguments || {};
      resource = `auth/${params.identifier || "*"}`;
    }

    // Override response methods to capture data
    res.send = function (body: any): any {
      // Log the response
      const responseTime = Date.now() - startTime;

      auditLogger.log({
        clientId,
        sessionId,
        operation: toolName,
        resource,
        status: res.statusCode >= 400 ? "error" : "success",
        errorMessage: res.statusCode >= 400 ? this.statusMessage : undefined,
        responseTime,
        metadata: {
          method: req.method,
          path: req.path,
          query: req.query,
          params: req.params,
          ip: req.ip,
          userAgent: req.headers["user-agent"],
          contentLength: body ? body.length : 0,
          statusCode: res.statusCode,
        },
      });

      // Call original method
      return originalSend.call(this, body);
    };

    res.json = function (body: any): any {
      // Log the response
      const responseTime = Date.now() - startTime;

      auditLogger.log({
        clientId,
        sessionId,
        operation: toolName,
        resource,
        status: res.statusCode >= 400 ? "error" : "success",
        errorMessage: res.statusCode >= 400 ? this.statusMessage : undefined,
        responseTime,
        metadata: {
          method: req.method,
          path: req.path,
          query: req.query,
          params: req.params,
          ip: req.ip,
          userAgent: req.headers["user-agent"],
          requestBody: req.body,
          responseType: "json",
          statusCode: res.statusCode,
        },
      });

      // Call original method
      return originalJson.call(this, body);
    };

    // For res.end, we're only logging the response
    res.on("finish", () => {
      auditLogger.log({
        clientId,
        sessionId,
        operation: toolName,
        resource,
        status: res.statusCode >= 400 ? "error" : "success",
        errorMessage: res.statusCode >= 400 ? res.statusMessage : undefined,
        responseTime: Date.now() - startTime,
        metadata: {
          method: req.method,
          path: req.path,
          query: req.query,
          params: req.params,
          ip: req.ip,
          userAgent: req.headers["user-agent"],
          statusCode: res.statusCode,
        },
      });
    });

    // Continue with request
    next();
  }
}

// Create an audit logger instance with default options
const auditLogger = new AuditLogger();

/**
 * Query interface for audit logs
 */
export interface AuditLogQuery {
  clientId?: string;
  operation?: string;
  resource?: string;
  status?: string;
  startTime?: string;
  endTime?: string;
  limit?: number;
}

/**
 * Query audit logs based on criteria
 * @param query Query parameters
 * @returns Array of matching audit logs
 */
export function queryAuditLogs(query: AuditLogQuery): Promise<AuditLog[]> {
  return auditLogger.queryLogs(
    {
      clientId: query.clientId,
      operation: query.operation,
      resource: query.resource,
      status: query.status as any,
    },
    query.limit,
    0
  );
}

export default auditLogger;
