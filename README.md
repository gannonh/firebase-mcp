# Firebase MCP Server

![Project Logo](./assets/logo.png)

<a href="https://glama.ai/mcp/servers/x4i8z2xmrq">
  <img width="380" height="200" src="https://glama.ai/mcp/servers/x4i8z2xmrq/badge" alt="Firebase MCP server" />
</a>

[![Firebase Tests CI](https://github.com/gannonh/firebase-mcp/actions/workflows/tests.yml/badge.svg)](https://github.com/gannonh/firebase-mcp/actions/workflows/tests.yml)

## Overview

The **Firebase MCP Server** bridges the gap between AI assistants and Firebase services through the open [Model Context Protocol (MCP)](https://github.com/modelcontextprotocol). This server enables any MCP-compatible LLM client to interact with Firebase's powerful backend services:

- **Firestore**: Document database operations
- **Storage**: File management with robust upload capabilities
- **Authentication**: User management and verification

By exposing Firebase through standardized MCP tools, this server makes Firebase services accessible to AI clients including [Claude Desktop](https://claude.ai/download), [Augment](https://docs.augmentcode.com/setup-augment/mcp#about-model-context-protocol-servers), [VS Code](https://code.visualstudio.com/docs/copilot/chat/mcp-servers), [Cursor](https://www.cursor.com/), and more.

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

## 🔥 Latest Features: Storage Upload (v1.3.3)

Firebase MCP now offers powerful file upload capabilities with two specialized tools:

- **`storage_upload`**: Upload files from text, base64 content, or local file paths
- **`storage_upload_from_url`**: Import files directly from external URLs

### Key Benefits

- **Permanent Public URLs**: All uploads generate non-expiring public URLs
- **Content Type Detection**: Automatic detection from file extensions and data
- **Multiple Upload Methods**: Flexible options for different use cases
- **Rich Response Formatting**: Clear, well-structured upload confirmations

### Upload Methods

1. **Local File Path** (Recommended for all file types)
   ```ts
   {
     filePath: "my-report.pdf",
     content: "/path/to/local/file.pdf"
   }
   ```

2. **Base64 Data URL** (For smaller files)
   ```ts
   {
     filePath: "my-image.png", 
     content: "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAA..."
   }
   ```

3. **Plain Text** (For text files)
   ```ts
   {
     filePath: "readme.md",
     content: "# My README\n\nThis is a markdown file."
   }
   ```

4. **External URL** (Using storage_upload_from_url)
   ```ts
   {
     filePath: "document.pdf",
     url: "https://example.com/document.pdf"
   }
   ```

> ⚠️ **Important:** For binary files like images and PDFs, always use the direct file path method for best reliability.

## 🛠️ Setup & Configuration

### 1. Firebase Configuration

1. Go to [Firebase Console](https://console.firebase.google.com) → Project Settings → Service Accounts
2. Click "Generate new private key"
3. Save the JSON file securely

### 2. Environment Variables

- `SERVICE_ACCOUNT_KEY_PATH`: Path to your Firebase service account key JSON (required)
- `FIREBASE_STORAGE_BUCKET`: Bucket name for Firebase Storage (optional, defaults to `[projectId].appspot.com`)

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
