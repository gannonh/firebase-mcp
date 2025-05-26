[![MseeP.ai Security Assessment Badge](https://mseep.net/pr/gannonh-firebase-mcp-badge.png)](https://mseep.ai/app/gannonh-firebase-mcp)

# Firebase MCP


![Project Logo](./assets/logo.png)

<a href="https://glama.ai/mcp/servers/x4i8z2xmrq">
  <img width="380" height="200" src="https://glama.ai/mcp/servers/x4i8z2xmrq/badge" alt="Firebase MCP server" />
</a>

[![Firebase Tests CI](https://github.com/gannonh/firebase-mcp/actions/workflows/tests.yml/badge.svg)](https://github.com/gannonh/firebase-mcp/actions/workflows/tests.yml)

## Overview

**Firebase MCP** enables AI assistants to work directly with Firebase services, including:

- **Firestore**: Document database operations
- **Storage**: File management with robust upload capabilities
- **Authentication**: User management and verification

The server works with MCP client applicatios such as [Claude Desktop](https://claude.ai/download), [Augment Code](https://docs.augmentcode.com/setup-augment/mcp), [VS Code](https://code.visualstudio.com/docs/copilot/chat/mcp-servers), and [Cursor](https://www.cursor.com/).

> ⚠️ **Known Issue**: The `firestore_list_collections` tool may return a Zod validation error in the client logs. This is an erroneous validation error in the MCP SDK, as our investigation confirmed no boolean values are present in the response. Despite the error message, the query still works correctly and returns the proper collection data. This is a log-level error that doesn't affect functionality.

## ⚡ Quick Start

### Prerequisites
- Firebase project with service account credentials
- Node.js environment

### 1. Install MCP Server

Add the server configuration to your MCP settings file:

- Claude Desktop: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Augment: `~/Library/Application Support/Code/User/settings.json`
- Cursor: `[project root]/.cursor/mcp.json`

MCP Servers can be installed manually or at runtime via npx (recommended). How you install determines your configuration:

#### Configure for npx (recommended)

   ```json
   {
     "firebase-mcp": {
       "command": "npx",
       "args": [
         "-y",
         "@gannonh/firebase-mcp"
       ],
       "env": {
         "SERVICE_ACCOUNT_KEY_PATH": "/absolute/path/to/serviceAccountKey.json",
         "FIREBASE_STORAGE_BUCKET": "your-project-id.firebasestorage.app"
       }
     }
   }
   ```

#### Configure for local installation

   ```json
   {
     "firebase-mcp": {
       "command": "node",
       "args": [
         "/absolute/path/to/firebase-mcp/dist/index.js"
       ],
       "env": {
         "SERVICE_ACCOUNT_KEY_PATH": "/absolute/path/to/serviceAccountKey.json",
         "FIREBASE_STORAGE_BUCKET": "your-project-id.firebasestorage.app"
       }
     }
   }
```


### 2. Test the Installation

Ask your AI client: "Please test all Firebase MCP tools."

## 🛠️ Setup & Configuration

### 1. Firebase Configuration

1. Go to [Firebase Console](https://console.firebase.google.com) → Project Settings → Service Accounts
2. Click "Generate new private key"
3. Save the JSON file securely

### 2. Environment Variables

#### Required
- `SERVICE_ACCOUNT_KEY_PATH`: Path to your Firebase service account key JSON (required)

#### Optional
- `FIREBASE_STORAGE_BUCKET`: Bucket name for Firebase Storage (defaults to `[projectId].appspot.com`)
- `MCP_TRANSPORT`: Transport type to use (`stdio` or `http`) (defaults to `stdio`)
- `MCP_HTTP_PORT`: Port for HTTP transport (defaults to `3000`)
- `MCP_HTTP_HOST`: Host for HTTP transport (defaults to `localhost`)
- `MCP_HTTP_PATH`: Path for HTTP transport (defaults to `/mcp`)
- `DEBUG_LOG_FILE`: Enable file logging:
  - Set to `true` to log to `~/.firebase-mcp/debug.log`
  - Set to a file path to log to a custom location

### 3. Client Integration

#### Claude Desktop
Edit: `~/Library/Application Support/Claude/claude_desktop_config.json`

#### VS Code / Augment
Edit: `~/Library/Application Support/Code/User/settings.json`

#### Cursor
Edit: `[project root]/.cursor/mcp.json`

## 📚 API Reference

### Firestore Tools

| Tool                               | Description                    | Required Parameters        |
| ---------------------------------- | ------------------------------ | -------------------------- |
| `firestore_add_document`           | Add a document to a collection | `collection`, `data`       |
| `firestore_list_documents`         | List documents with filtering  | `collection`               |
| `firestore_get_document`           | Get a specific document        | `collection`, `id`         |
| `firestore_update_document`        | Update an existing document    | `collection`, `id`, `data` |
| `firestore_delete_document`        | Delete a document              | `collection`, `id`         |
| `firestore_list_collections`       | List root collections          | None                       |
| `firestore_query_collection_group` | Query across subcollections    | `collectionId`             |

### Storage Tools

| Tool                      | Description               | Required Parameters              |
| ------------------------- | ------------------------- | -------------------------------- |
| `storage_list_files`      | List files in a directory | None (optional: `directoryPath`) |
| `storage_get_file_info`   | Get file metadata and URL | `filePath`                       |
| `storage_upload`          | Upload file from content  | `filePath`, `content`            |
| `storage_upload_from_url` | Upload file from URL      | `filePath`, `url`                |

### Authentication Tools

| Tool            | Description             | Required Parameters |
| --------------- | ----------------------- | ------------------- |
| `auth_get_user` | Get user by ID or email | `identifier`        |

## 💻 Developer Guide

### Installation & Building

```bash
git clone https://github.com/gannonh/firebase-mcp
cd firebase-mcp
npm install
npm run build
```

### Running Tests

First, install and start Firebase emulators:
```bash
npm install -g firebase-tools
firebase init emulators
firebase emulators:start
```

Then run tests:
```bash
# Run tests with emulator
npm run test:emulator

# Run tests with coverage
npm run test:coverage:emulator
```

### Project Structure

```bash
src/
├── index.ts                  # Server entry point
├── utils/                    # Utility functions
└── lib/
    └── firebase/              # Firebase service clients
        ├── authClient.ts     # Authentication operations
        ├── firebaseConfig.ts   # Firebase configuration
        ├── firestoreClient.ts # Firestore operations
        └── storageClient.ts  # Storage operations
```

## 🌐 HTTP Transport

Firebase MCP now supports HTTP transport in addition to the default stdio transport. This allows you to run the server as a standalone HTTP service that can be accessed by multiple clients.

### Running with HTTP Transport

To run the server with HTTP transport:

```bash
# Using environment variables
MCP_TRANSPORT=http MCP_HTTP_PORT=3000 node dist/index.js

# Or with npx
MCP_TRANSPORT=http MCP_HTTP_PORT=3000 npx @gannonh/firebase-mcp
```

### Client Configuration for HTTP

When using HTTP transport, configure your MCP client to connect to the HTTP endpoint:

```json
{
  "firebase-mcp": {
    "url": "http://localhost:3000/mcp"
  }
}
```

### Session Management

The HTTP transport supports session management, allowing multiple clients to connect to the same server instance. Each client receives a unique session ID that is used to maintain state between requests.

## 🔍 Troubleshooting

### Common Issues

#### Storage Bucket Not Found
If you see "The specified bucket does not exist" error:
1. Verify your bucket name in Firebase Console → Storage
2. Set the correct bucket name in `FIREBASE_STORAGE_BUCKET` environment variable

#### Firebase Initialization Failed
If you see "Firebase is not initialized" error:
1. Check that your service account key path is correct and absolute
2. Ensure the service account has proper permissions for Firebase services

#### Composite Index Required
If you receive "This query requires a composite index" error:
1. Look for the provided URL in the error message
2. Follow the link to create the required index in Firebase Console
3. Retry your query after the index is created (may take a few minutes)

#### Zod Validation Error with `firestore_list_collections`
If you see a Zod validation error with message "Expected object, received boolean" when using the `firestore_list_collections` tool:

> ⚠️ **Known Issue**: The `firestore_list_collections` tool may return a Zod validation error in the client logs. This is an erroneous validation error in the MCP SDK, as our investigation confirmed no boolean values are present in the response. Despite the error message, the query still works correctly and returns the proper collection data. This is a log-level error that doesn't affect functionality.

### Debugging

#### Enable File Logging
To help diagnose issues, you can enable file logging:

```bash
# Log to default location (~/.firebase-mcp/debug.log)
DEBUG_LOG_FILE=true npx @gannonh/firebase-mcp

# Log to a custom location
DEBUG_LOG_FILE=/path/to/custom/debug.log npx @gannonh/firebase-mcp
```

You can also enable logging in your MCP client configuration:

```json
{
  "firebase-mcp": {
    "command": "npx",
    "args": ["-y", "@gannonh/firebase-mcp"],
    "env": {
      "SERVICE_ACCOUNT_KEY_PATH": "/path/to/serviceAccountKey.json",
      "FIREBASE_STORAGE_BUCKET": "your-project-id.firebasestorage.app",
      "DEBUG_LOG_FILE": "true"
    }
  }
}
```

#### Real-time Log Viewing
To view logs in real-time:

```bash
# Using tail to follow the log file
tail -f ~/.firebase-mcp/debug.log

# Using a split terminal to capture stderr
npm start 2>&1 | tee logs.txt
```

#### Using MCP Inspector
The MCP Inspector provides interactive debugging:

```bash
# Install MCP Inspector
npm install -g @mcp/inspector

# Connect to your MCP server
mcp-inspector --connect stdio --command "node ./dist/index.js"
```

## 📋 Response Formatting

### Storage Upload Response Example

```json
{
  "name": "reports/quarterly.pdf",
  "size": "1024000",
  "contentType": "application/pdf",
  "updated": "2025-04-11T15:37:10.290Z",
  "downloadUrl": "https://storage.googleapis.com/bucket/reports/quarterly.pdf?alt=media",
  "bucket": "your-project.appspot.com"
}
```

Displayed to the user as:

```markdown
## File Successfully Uploaded! 📁

Your file has been uploaded to Firebase Storage:

**File Details:**
- **Name:** reports/quarterly.pdf
- **Size:** 1024000 bytes
- **Type:** application/pdf
- **Last Updated:** April 11, 2025 at 15:37:10 UTC

**[Click here to download your file](https://storage.googleapis.com/bucket/reports/quarterly.pdf?alt=media)**
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Implement changes with tests (80%+ coverage required)
4. Submit a pull request

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details

## 🔗 Related Resources

- [Model Context Protocol Documentation](https://github.com/modelcontextprotocol)
- [Firebase Documentation](https://firebase.google.com/docs)
- [Firebase Admin SDK](https://firebase.google.com/docs/admin/setup)
