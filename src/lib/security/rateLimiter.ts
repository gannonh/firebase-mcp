/**
 * Rate Limiter Middleware Module
 *
 * This module provides request rate limiting for the Firebase MCP server.
 * It implements a token bucket algorithm to limit client request rates.
 *
 * @module firebase-mcp/security/rate-limiter
 */

import { Request, Response, NextFunction } from "express";
import { McpError, ErrorCode } from "../../lib/types";
import fs from "fs";
import path from "path";

export interface RateLimitConfig {
  requestsPerMinute: number;
  burstCapacity: number;
}

export interface ClientRateLimit {
  clientId: string;
  operations: Record<string, RateLimitConfig>;
  global: RateLimitConfig;
}

export interface RateLimiterOptions {
  limitsConfigPath: string;
  defaultLimits: RateLimitConfig;
  checkInterval: number; // milliseconds
}

const DEFAULT_OPTIONS: RateLimiterOptions = {
  limitsConfigPath:
    process.env.RATE_LIMITS_PATH ||
    path.join(process.cwd(), "rate-limits.json"),
  defaultLimits: {
    requestsPerMinute: 60,
    burstCapacity: 10,
  },
  checkInterval: 1000, // 1 second
};

/**
 * Represents a token bucket for rate limiting
 */
interface TokenBucket {
  tokens: number;
  lastRefill: number;
  capacity: number;
  refillRate: number; // tokens per millisecond
}

/**
 * Rate limiter middleware class that manages request rate limits
 */
export class RateLimiter {
  private options: RateLimiterOptions;
  private clientLimits: Map<string, ClientRateLimit> = new Map();
  private buckets: Map<string, TokenBucket> = new Map();

  /**
   * Creates a new rate limiter middleware instance
   * @param options Rate limiter configuration options
   */
  constructor(options: Partial<RateLimiterOptions> = {}) {
    this.options = { ...DEFAULT_OPTIONS, ...options };
    this.loadLimits();

    // Set up periodic cleanup of unused buckets
    setInterval(() => {
      this.cleanupBuckets();
    }, this.options.checkInterval * 60); // Cleanup every minute
  }

  /**
   * Load rate limits from the JSON file
   */
  private loadLimits(): void {
    try {
      if (fs.existsSync(this.options.limitsConfigPath)) {
        const limitsData = JSON.parse(
          fs.readFileSync(this.options.limitsConfigPath, "utf8")
        );

        if (Array.isArray(limitsData)) {
          limitsData.forEach((limit) => {
            if (limit.clientId && limit.global) {
              this.clientLimits.set(limit.clientId, limit as ClientRateLimit);
            }
          });
          console.error(
            `Loaded rate limits for ${this.clientLimits.size} clients`
          );
        }
      } else {
        // Create empty limits file if it doesn't exist
        fs.writeFileSync(
          this.options.limitsConfigPath,
          JSON.stringify([], null, 2)
        );
        console.error(
          `Created empty rate limits file at ${this.options.limitsConfigPath}`
        );
      }
    } catch (error) {
      const errorMessage =
        error instanceof Error ? error.message : "Unknown error";
      console.error(`Failed to load rate limits: ${errorMessage}`);
    }
  }

  /**
   * Save rate limits to the JSON file
   */
  private saveLimits(): void {
    try {
      const limitsData = Array.from(this.clientLimits.values());
      fs.writeFileSync(
        this.options.limitsConfigPath,
        JSON.stringify(limitsData, null, 2)
      );
    } catch (error) {
      const errorMessage =
        error instanceof Error ? error.message : "Unknown error";
      console.error(`Failed to save rate limits: ${errorMessage}`);
    }
  }

  /**
   * Set the rate limit for a client
   * @param clientId Client identifier
   * @param operation Operation name, or '*' for global limit
   * @param config Rate limit configuration
   */
  public setRateLimit(
    clientId: string,
    operation: string,
    config: RateLimitConfig
  ): void {
    let clientLimit = this.clientLimits.get(clientId);

    if (!clientLimit) {
      clientLimit = {
        clientId,
        operations: {},
        global: { ...this.options.defaultLimits },
      };
      this.clientLimits.set(clientId, clientLimit);
    }

    if (operation === "*") {
      clientLimit.global = { ...config };
    } else {
      clientLimit.operations[operation] = { ...config };
    }

    this.saveLimits();
  }

  /**
   * Get the rate limit config for a client and operation
   * @param clientId Client identifier
   * @param operation Operation name
   * @returns Rate limit configuration
   */
  private getRateLimitConfig(
    clientId: string,
    operation: string
  ): RateLimitConfig {
    const clientLimit = this.clientLimits.get(clientId);

    if (!clientLimit) {
      return this.options.defaultLimits;
    }

    return clientLimit.operations[operation] || clientLimit.global;
  }

  /**
   * Get or create a token bucket for a client and operation
   * @param clientId Client identifier
   * @param operation Operation name
   * @returns Token bucket
   */
  private getBucket(clientId: string, operation: string): TokenBucket {
    const bucketKey = `${clientId}:${operation}`;

    if (!this.buckets.has(bucketKey)) {
      const config = this.getRateLimitConfig(clientId, operation);

      // Create a new bucket
      this.buckets.set(bucketKey, {
        tokens: config.burstCapacity,
        lastRefill: Date.now(),
        capacity: config.burstCapacity,
        refillRate: config.requestsPerMinute / 60000, // Convert to tokens per millisecond
      });
    }

    return this.buckets.get(bucketKey)!;
  }

  /**
   * Refill tokens in a bucket based on time elapsed since last refill
   * @param bucket Token bucket to refill
   */
  private refillBucket(bucket: TokenBucket): void {
    const now = Date.now();
    const timeElapsed = now - bucket.lastRefill;

    if (timeElapsed > 0) {
      // Calculate tokens to add based on time elapsed and refill rate
      const tokensToAdd = timeElapsed * bucket.refillRate;

      // Add tokens up to capacity
      bucket.tokens = Math.min(bucket.capacity, bucket.tokens + tokensToAdd);
      bucket.lastRefill = now;
    }
  }

  /**
   * Check if a request is within rate limits
   * @param clientId Client identifier
   * @param operation Operation name
   * @returns True if within limits, false if rate limited
   */
  public checkLimit(clientId: string, operation: string): boolean {
    // Get and refill the bucket
    const bucket = this.getBucket(clientId, operation);
    this.refillBucket(bucket);

    // Check if we have enough tokens
    if (bucket.tokens >= 1) {
      // Consume a token
      bucket.tokens -= 1;
      return true;
    }

    return false;
  }

  /**
   * Get the time to wait (in seconds) until next request is allowed
   * @param clientId Client identifier
   * @param operation Operation name
   * @returns Time to wait in seconds
   */
  public getWaitTime(clientId: string, operation: string): number {
    const bucket = this.getBucket(clientId, operation);

    // If we have tokens, no need to wait
    if (bucket.tokens >= 1) {
      return 0;
    }

    // Calculate time until we have 1 token
    const tokensNeeded = 1 - bucket.tokens;
    const timeToWait = tokensNeeded / bucket.refillRate; // milliseconds

    return Math.ceil(timeToWait / 1000); // seconds
  }

  /**
   * Cleanup unused buckets to prevent memory leaks
   */
  private cleanupBuckets(): void {
    const now = Date.now();

    // Remove buckets that haven't been used for over 10 minutes
    for (const [key, bucket] of this.buckets.entries()) {
      if (now - bucket.lastRefill > 10 * 60 * 1000) {
        this.buckets.delete(key);
      }
    }
  }

  /**
   * Rate limiter middleware function
   * @param req Express request object
   * @param res Express response object
   * @param next Express next function
   */
  public rateLimitMiddleware(req: any, res: any, next: NextFunction): void {
    // If auth context is not available, skip rate limiting
    if (!req.auth || !req.auth.clientId) {
      return next();
    }

    // Extract client ID and operation
    const clientId = req.auth.clientId;
    const operation = req.operation || "*";

    // Check rate limit
    if (!this.checkLimit(clientId, operation)) {
      const waitTime = this.getWaitTime(clientId, operation);

      // Set retry-after header
      res.setHeader("Retry-After", Math.ceil(waitTime).toString());

      // Return rate limit error
      return next(
        new McpError(
          ErrorCode.RateLimitExceeded,
          `Rate limit exceeded. Please try again in ${Math.ceil(
            waitTime
          )} seconds.`
        )
      );
    }

    // Rate limit not exceeded, continue
    next();
  }

  /**
   * Get all rate limits
   * @returns Array of all client rate limits
   */
  public getLimits(): ClientRateLimit[] {
    return Array.from(this.clientLimits.values());
  }
}

// Create singleton instance
const rateLimiter = new RateLimiter();

/**
 * Set a rate limit for a client and resource
 * @param clientId Client identifier
 * @param resource Resource name or pattern
 * @param windowSeconds Time window in seconds
 * @param maxRequests Maximum requests in the window
 * @returns The applied rate limit configuration
 */
export function setRateLimit(
  clientId: string,
  resource: string,
  windowSeconds: number,
  maxRequests: number
): RateLimitConfig {
  const config: RateLimitConfig = {
    requestsPerMinute: (maxRequests * 60) / windowSeconds,
    burstCapacity: Math.max(1, Math.floor(maxRequests / 10)),
  };

  rateLimiter.setRateLimit(clientId, resource, config);

  return config;
}

/**
 * Get all rate limits
 * @returns Map of client rate limits
 */
export function getRateLimits(): ClientRateLimit[] {
  return rateLimiter.getLimits();
}

export default rateLimiter;
