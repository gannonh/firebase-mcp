/**
 * Type declarations for Express
 */

declare module "express" {
  import { Server } from "http";

  export interface Application {
    use: Function;
    listen: (port: number, callback?: Function) => Server;
  }

  export interface Request {
    headers: Record<string, any>;
    body: any;
    query: Record<string, any>;
    ip?: string;
    auth?: {
      clientId: string;
      sessionId: string;
    };
  }

  export interface Response {
    status: (code: number) => Response;
    json: (data: any) => void;
    setHeader: (name: string, value: string | number) => void;
    end: Function;
  }

  export interface NextFunction {
    (err?: any): void;
  }

  export interface Router {
    use: Function;
    get: Function;
    post: Function;
    put: Function;
    delete: Function;
  }

  export function Router(): Router;
  export function json(): Function;

  export default function createApplication(): Application;
}
