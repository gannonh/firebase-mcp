# Basic Usage Examples

This document provides examples of how to use the Secure Firebase MCP Server with various clients.

## Prerequisites

1. Make sure you have set up the Firebase project and configured the environment variables
2. Start the server using `npm start`

## Example 1: Authentication and Authorization

```javascript
// Client code example (Node.js)
const axios = require("axios");

// Replace with your API key
const API_KEY = "your-api-key";

// Function to call an MCP tool
async function callTool(name, args) {
  try {
    const response = await axios.post(
      "http://localhost:3000/call",
      {
        jsonrpc: "2.0",
        id: "1",
        method: "call_tool",
        params: {
          name,
          arguments: args,
        },
      },
      {
        headers: {
          "x-api-key": API_KEY,
        },
      }
    );

    return response.data.result;
  } catch (error) {
    console.error(
      "Error calling tool:",
      error.response ? error.response.data : error.message
    );
    throw error;
  }
}

// Example: Add a document to Firestore
async function addDocument() {
  const result = await callTool("firestore_add_document", {
    collection: "users",
    data: {
      name: "John Doe",
      email: "john@example.com",
      createdAt: new Date().toISOString(),
    },
  });

  console.log("Document added:", result);
}

// Example: Get a document from Firestore
async function getDocument(id) {
  const result = await callTool("firestore_get_document", {
    collection: "users",
    id,
  });

  console.log("Document retrieved:", result);
}

// Run examples
async function run() {
  try {
    const addResult = await addDocument();
    const id = addResult.id;
    await getDocument(id);
  } catch (error) {
    console.error("Example failed:", error);
  }
}

run();
```

## Example 2: Using with an MCP Client

For AI assistants or other MCP clients, you can register the server in their configuration:

### Claude Desktop Configuration

```json
{
  "servers": {
    "firebase-mcp-secure": {
      "command": "node",
      "args": ["/path/to/secure-firebase-mcp/dist/index.js"],
      "env": {
        "PORT": "3000",
        "TRANSPORT": "stdio",
        "ENABLE_SECURITY": "false",
        "FIREBASE_PROJECT_ID": "your-project-id",
        "FIREBASE_CLIENT_EMAIL": "your-client-email",
        "FIREBASE_PRIVATE_KEY": "your-private-key"
      }
    }
  }
}
```

### Cursor Configuration

```json
{
  "firebase-mcp-secure": {
    "command": "node",
    "args": ["/path/to/secure-firebase-mcp/dist/index.js"],
    "env": {
      "PORT": "3000",
      "TRANSPORT": "stdio",
      "ENABLE_SECURITY": "false",
      "FIREBASE_PROJECT_ID": "your-project-id",
      "FIREBASE_CLIENT_EMAIL": "your-client-email",
      "FIREBASE_PRIVATE_KEY": "your-private-key"
    }
  }
}
```

## Example 3: Using the Admin API

To manage clients, access rules, and rate limits, you can use the admin API:

```javascript
// Admin operations example (Node.js)
const axios = require("axios");

// Replace with your admin API key from admin-api-key.txt
const ADMIN_API_KEY = "your-admin-api-key";

// Base URL for the API
const API_URL = "http://localhost:3000";

// Function to make authenticated API calls
async function callApi(endpoint, method = "GET", data = null) {
  try {
    const response = await axios({
      method,
      url: `${API_URL}${endpoint}`,
      headers: {
        "x-api-key": ADMIN_API_KEY,
      },
      data,
    });

    return response.data;
  } catch (error) {
    console.error(
      "API Error:",
      error.response ? error.response.data : error.message
    );
    throw error;
  }
}

// Add a new client
async function addClient(clientId, description) {
  return callApi("/admin/clients", "POST", {
    clientId,
    description,
  });
}

// Add access rule for a client
async function addAccessRule(clientId, resource, operations) {
  return callApi("/admin/access-rules", "POST", {
    clientId,
    resource,
    operations,
  });
}

// Set rate limit for a client
async function setRateLimit(clientId, resource, windowSeconds, maxRequests) {
  return callApi("/admin/rate-limits", "POST", {
    clientId,
    resource,
    windowSeconds,
    maxRequests,
  });
}

// Query audit logs
async function queryAuditLogs(filters) {
  return callApi("/admin/audit-logs", "GET", filters);
}

// Example usage
async function run() {
  try {
    // Add a new client
    const clientResult = await addClient(
      "example-client",
      "Example client for testing"
    );
    console.log("Client added:", clientResult);

    // Add access rules for the client
    await addAccessRule("example-client", "users", ["read"]);
    await addAccessRule("example-client", "posts", ["read", "create"]);
    console.log("Access rules added");

    // Set rate limits for the client
    await setRateLimit("example-client", "users", 60, 10); // 10 requests per minute for users
    await setRateLimit("example-client", "posts", 60, 5); // 5 requests per minute for posts
    console.log("Rate limits set");

    // Query audit logs
    const yesterday = new Date();
    yesterday.setDate(yesterday.getDate() - 1);

    const logs = await queryAuditLogs({
      clientId: "example-client",
      startTime: yesterday.toISOString(),
      endTime: new Date().toISOString(),
    });

    console.log("Audit logs:", logs);
  } catch (error) {
    console.error("Admin operations failed:", error);
  }
}

run();
```
