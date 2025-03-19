/**
 * Type declarations for the Model Context Protocol SDK
 */

declare module "@modelcontextprotocol/sdk/server" {
  export class Server {
    constructor(metadata: any, options: any);
    setRequestHandler(schema: any, handler: Function): void;
    connect(transport: any): Promise<void>;
    close(): Promise<void>;
    onerror: (error: any) => void;
  }
}

declare module "@modelcontextprotocol/sdk/server/http" {
  import { Application } from "express";

  export interface HttpServerTransportOptions {
    app: Application;
    cors?: {
      origin: string | string[];
    };
  }

  export class HttpServerTransport {
    constructor(options: HttpServerTransportOptions);
  }
}

declare module "@modelcontextprotocol/sdk/server/stdio" {
  export class StdioServerTransport {
    constructor();
  }
}

declare module "@modelcontextprotocol/sdk/types" {
  export const CallToolRequestSchema: any;
  export const ListToolsRequestSchema: any;

  export enum ErrorCode {
    InternalError = "internal_error",
    InvalidRequest = "invalid_request",
    MethodNotFound = "method_not_found",
    InvalidParams = "invalid_params",
    ResourceNotFound = "resource_not_found",
    Unauthorized = "unauthorized",
    Forbidden = "forbidden",
    RateLimited = "rate_limited",
    NotImplemented = "not_implemented",
  }

  export class McpError extends Error {
    constructor(code: ErrorCode, message: string, data?: any);
    readonly code: ErrorCode;
    readonly data?: any;
  }
}
