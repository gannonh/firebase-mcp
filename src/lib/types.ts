/**
 * Common type definitions for the Firebase MCP server.
 */

export enum ErrorCode {
  InvalidRequest = "invalid_request",
  Unauthorized = "unauthorized",
  Forbidden = "forbidden",
  NotFound = "not_found",
  MethodNotFound = "method_not_found",
  RateLimitExceeded = "rate_limit_exceeded",
  InternalError = "internal_error",
}

export class McpError extends Error {
  code: ErrorCode;

  constructor(code: ErrorCode, message: string) {
    super(message);
    this.code = code;
    this.name = "McpError";
  }
}
