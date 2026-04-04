import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

// Mock logger
vi.mock('../utils/logger.js', () => ({
  logger: {
    debug: vi.fn(),
    error: vi.fn(),
    info: vi.fn(),
  },
}));

// Save original process properties to restore later
const originalStdinIsTTY = process.stdin.isTTY;
const originalStdoutIsTTY = process.stdout.isTTY;
const originalEnv = { ...process.env };

describe('Config Module', () => {
  beforeEach(() => {
    vi.resetModules();
    vi.clearAllMocks();

    // Reset process properties
    process.stdin.isTTY = originalStdinIsTTY;
    process.stdout.isTTY = originalStdoutIsTTY;
    process.env = { ...originalEnv };

    // Clear any environment variables that might affect tests
    delete process.env.FORCE_HTTP_TRANSPORT;
    delete process.env.MCP_TRANSPORT;
    delete process.env.SERVICE_ACCOUNT_KEY_PATH;
    delete process.env.FIREBASE_STORAGE_BUCKET;
    delete process.env.MCP_HTTP_PORT;
    delete process.env.MCP_HTTP_HOST;
    delete process.env.MCP_HTTP_PATH;
    delete process.env.FIRESTORE_DATABASE_ID;
  });

  afterEach(() => {
    // Restore original process properties
    process.stdin.isTTY = originalStdinIsTTY;
    process.stdout.isTTY = originalStdoutIsTTY;
    process.env = { ...originalEnv };
  });

  describe('isStdioContext', () => {
    it('should return true when in stdio context', async () => {
      // Set up stdio context
      process.stdin.isTTY = false;
      process.stdout.isTTY = false;
      delete process.env.FORCE_HTTP_TRANSPORT;

      // Import the module after setting up the context
      const { isStdioContext } = await import('../config');

      // Test the function
      expect(isStdioContext()).toBe(true);
    });

    it('should return false when not in stdio context', async () => {
      // Set up non-stdio context
      process.stdin.isTTY = true;
      process.stdout.isTTY = false;

      // Import the module after setting up the context
      const { isStdioContext } = await import('../config');

      // Test the function
      expect(isStdioContext()).toBe(false);

      // Test with different TTY configuration
      process.stdin.isTTY = false;
      process.stdout.isTTY = true;
      expect(isStdioContext()).toBe(false);

      // Test with both TTYs true
      process.stdin.isTTY = true;
      process.stdout.isTTY = true;
      expect(isStdioContext()).toBe(false);
    });

    it('should return false when FORCE_HTTP_TRANSPORT is set', async () => {
      // Set up stdio context but with FORCE_HTTP_TRANSPORT
      process.stdin.isTTY = false;
      process.stdout.isTTY = false;
      process.env.FORCE_HTTP_TRANSPORT = 'true';

      // Import the module after setting up the context
      const { isStdioContext } = await import('../config');

      // Test the function
      expect(isStdioContext()).toBe(false);
    });
  });

  describe('isHttpServerRunning', () => {
    it('should return true when server is running', async () => {
      // Mock successful fetch
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
      });

      // Import the module after setting up the mock
      const { isHttpServerRunning } = await import('../config');

      // Test the function
      const result = await isHttpServerRunning('localhost', 3000);
      expect(result).toBe(true);

      // Verify fetch was called with correct URL
      expect(global.fetch).toHaveBeenCalledWith('http://localhost:3000', expect.any(Object));
    });

    it('should return false when server is not running', async () => {
      // Mock failed fetch
      global.fetch = vi.fn().mockRejectedValue(new Error('Connection refused'));

      // Import the module after setting up the mock
      const { isHttpServerRunning } = await import('../config');

      // Test the function
      const result = await isHttpServerRunning('localhost', 3000);
      expect(result).toBe(false);
    });

    it('should return false when fetch times out', async () => {
      // Mock fetch that times out (AbortController will abort it)
      global.fetch = vi.fn().mockImplementation(() => {
        throw new Error('AbortError');
      });

      // Import the module after setting up the mock
      const { isHttpServerRunning } = await import('../config');

      // Test the function
      const result = await isHttpServerRunning('localhost', 3000);
      expect(result).toBe(false);
    });
  });

  describe('getConfig', () => {
    it('should return default configuration when no environment variables are set', async () => {
      // Save original environment variables
      const originalEnv = { ...process.env };

      // Clear environment variables that might affect the test
      delete process.env.SERVICE_ACCOUNT_KEY_PATH;
      delete process.env.FIREBASE_STORAGE_BUCKET;

      try {
        // Import the module
        const { getConfig, TransportType } = await import('../config');

        // Test the function
        const config = getConfig();

        // Verify default values
        expect(config).toMatchObject({
          transport: TransportType.STDIO,
          http: {
            port: 3000,
            host: 'localhost',
            path: '/mcp',
          },
          name: 'firebase-mcp',
        });

        // Verify version is a string
        expect(typeof config.version).toBe('string');
      } finally {
        // Restore original environment variables
        process.env = { ...originalEnv };
      }
    });

    it('should use environment variables when set', async () => {
      // Set environment variables
      process.env.SERVICE_ACCOUNT_KEY_PATH = '/path/to/service-account.json';
      process.env.FIREBASE_STORAGE_BUCKET = 'test-bucket';
      process.env.MCP_TRANSPORT = 'http';
      process.env.MCP_HTTP_PORT = '4000';
      process.env.MCP_HTTP_HOST = '127.0.0.1';
      process.env.MCP_HTTP_PATH = '/api/mcp';

      // Import the module
      const { getConfig, TransportType } = await import('../config');

      // Test the function
      const config = getConfig();

      // Verify values from environment variables
      expect(config).toEqual({
        serviceAccountKeyPath: '/path/to/service-account.json',
        storageBucket: 'test-bucket',
        firestoreDatabaseId: null,
        transport: TransportType.HTTP,
        http: {
          port: 4000,
          host: '127.0.0.1',
          path: '/api/mcp',
        },
        version: expect.any(String),
        name: 'firebase-mcp',
      });
    });

    it('should force stdio transport when in stdio context', async () => {
      // Set up stdio context
      process.stdin.isTTY = false;
      process.stdout.isTTY = false;
      process.env.MCP_TRANSPORT = 'http'; // This should be overridden

      // Import the module
      const { getConfig, TransportType } = await import('../config');

      // Get the logger to verify debug calls
      const { logger } = await import('../utils/logger.js');

      // Test the function
      const config = getConfig();

      // Verify stdio transport was forced
      expect(config.transport).toBe(TransportType.STDIO);

      // Verify debug message was logged
      expect(logger.debug).toHaveBeenCalledWith('Detected stdio context, using stdio transport');
    });

    it('should default to stdio transport for invalid transport type', async () => {
      // Set invalid transport
      process.env.MCP_TRANSPORT = 'invalid';

      // Import the module
      const { getConfig, TransportType } = await import('../config');

      // Test the function
      const config = getConfig();

      // Verify default to stdio
      expect(config.transport).toBe(TransportType.STDIO);
    });

    it('should read FIRESTORE_DATABASE_ID env var into firestoreDatabaseId', async () => {
      process.env.FIRESTORE_DATABASE_ID = 'my-named-db';

      const { getConfig } = await import('../config');
      const config = getConfig();

      expect(config.firestoreDatabaseId).toBe('my-named-db');
    });

    it('should default firestoreDatabaseId to null when FIRESTORE_DATABASE_ID not set', async () => {
      delete process.env.FIRESTORE_DATABASE_ID;

      const { getConfig } = await import('../config');
      const config = getConfig();

      expect(config.firestoreDatabaseId).toBeNull();
    });

    it('should log debug message when using HTTP transport', async () => {
      // Set HTTP transport and non-stdio context
      process.env.MCP_TRANSPORT = 'http';
      process.stdin.isTTY = true; // Not stdio context

      // Import the module
      const { getConfig, TransportType } = await import('../config');

      // Get the logger to verify debug calls
      const { logger } = await import('../utils/logger.js');

      // Test the function
      const config = getConfig();

      // Verify HTTP transport was used
      expect(config.transport).toBe(TransportType.HTTP);

      // Verify debug messages were logged
      expect(logger.debug).toHaveBeenCalledWith('Using transport: http');
      expect(logger.debug).toHaveBeenCalledWith('Configuring HTTP transport');
    });
  });
});
