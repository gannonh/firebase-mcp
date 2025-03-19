# Secure Firebase MCP Server

A secure implementation of the Model Context Protocol (MCP) server for Firebase services with enhanced security features including authentication, access control, rate limiting, and audit logging.

## Features

- **Authentication Middleware**: Verifies API keys, manages sessions, and authenticates clients
- **Access Control**: Resource-based permissions for different clients accessing Firebase resources
- **Rate Limiting**: Token bucket algorithm to limit request rates and prevent abuse
- **Audit Logging**: Comprehensive logging of all operations for security monitoring and compliance
- **Secure Configuration**: Environment-based configuration with secure defaults

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/secure-firebase-mcp.git
cd secure-firebase-mcp

# Install dependencies
npm install

# Configure environment variables (interactive)
npm run config

# Or configure manually
cp .env.example .env
# Edit .env with your configuration

# Build the project
npm run build

# Start the server
npm start
```

## Configuration

The server can be configured using environment variables in the `.env` file:

### Server Configuration

- `SERVER_NAME`: Name of the server (default: firebase-mcp-secure)
- `SERVER_VERSION`: Version of the server (default: 1.0.0)
- `PORT`: HTTP port to listen on (default: 3000)
- `TRANSPORT`: Transport protocol to use ('http' or 'stdio', default: 'http')
- `ENABLE_SECURITY`: Enable security features (default: true)

### Security Settings

- `SESSION_SECRET`: Secret for session encryption
- `SESSION_EXPIRY`: Session expiry time in seconds (default: 3600)
- `JWT_SECRET`: Secret for JWT token signing
- `JWT_EXPIRY`: JWT token expiry time in seconds (default: 86400)

### Admin Configuration

- `ADMIN_API_KEY`: Custom API key for the admin client (optional)

### CORS Configuration

- `CORS_ORIGINS`: Comma-separated list of allowed origins for CORS

### Audit Logging

- `LOG_DIRECTORY`: Directory for log files (default: logs)
- `LOG_MAX_DAYS`: Number of days to keep logs (default: 30)
- `LOG_ROTATION_INTERVAL`: Interval for log rotation (default: 1d)
- `CONSOLE_LOGGING`: Enable console logging (default: true)

### Firebase Configuration

- `FIREBASE_PROJECT_ID`: Your Firebase project ID
- `FIREBASE_CLIENT_EMAIL`: Your Firebase client email
- `FIREBASE_PRIVATE_KEY`: Your Firebase private key

## Security Modules

### Authentication (src/lib/security/auth.ts)

The authentication middleware verifies API keys, manages sessions, and handles client authentication. It provides:

- API key validation
- Session management
- JWT token verification
- Middleware for securing API endpoints

### Access Control (src/lib/security/accessControl.ts)

The access control middleware manages resource permissions for different clients:

- Resource-based access rules
- Permission checking for operations
- Support for wildcards and operation types

### Rate Limiting (src/lib/security/rateLimiter.ts)

The rate limiting module prevents abuse by limiting the number of requests:

- Token bucket algorithm implementation
- Per-client and per-resource rate limits
- Automatic token refill and bucket expiration

### Audit Logging (src/lib/security/auditLogger.ts)

The audit logger records all operations for security monitoring:

- Detailed request and response logging
- Log rotation and compression
- Sensitive data redaction
- Query capability for historical logs

## API Tools

The server provides the following MCP tools for Firebase operations:

### Firestore Tools

- `firestore_add_document`: Add a document to a Firestore collection
- `firestore_list_collections`: List collections in Firestore
- `firestore_list_documents`: List documents from a Firestore collection
- `firestore_get_document`: Get a document from a Firestore collection
- `firestore_update_document`: Update a document in a Firestore collection
- `firestore_delete_document`: Delete a document from a Firestore collection

### Authentication Tools

- `auth_get_user`: Get a user by ID or email from Firebase Authentication

### Storage Tools

- `storage_list_files`: List files in a given path in Firebase Storage
- `storage_get_file_info`: Get file information including metadata and download URL

## Utility Tools

The project includes several utility tools to help with setup and management:

### Environment Configuration Generator

A tool to help generate environment variables from a Firebase service account key file:

```bash
npm run config
```

This interactive script will:

1. Ask for the path to your Firebase service account key JSON file
2. Generate secure random strings for session and JWT secrets
3. Create a `.env` file with all necessary configuration
4. Generate an admin API key that can be used for initial setup

### Admin Client Setup

The server automatically creates an admin client with full access rights on first startup if none exists. This is to ensure you always have an administrative access point to the server.

The admin client details and API key are saved to `admin-api-key.txt` in the project directory.

## Security Best Practices

When deploying this server to production, please follow these security best practices:

1. **Use HTTPS**: Always deploy behind HTTPS in production
2. **Secure Secrets**: Use a secure method to manage environment variables and secrets
3. **Regular Auditing**: Review the audit logs regularly for suspicious activities
4. **Strict Rate Limits**: Set appropriate rate limits for all clients
5. **Minimal Permissions**: Follow the principle of least privilege for all access rules
6. **Regular Updates**: Keep all dependencies up to date

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Related Resources

- [Model Context Protocol](https://github.com/modelcontextprotocol)
- [Firebase Documentation](https://firebase.google.com/docs)
- [Firebase Admin SDK](https://firebase.google.com/docs/admin/setup)

## Troubleshooting

### Common Issues

#### "The specified bucket does not exist" Error

If you encounter this error when trying to access Firebase Storage:

1. Check that your Firebase project has Storage enabled

   - Go to the Firebase Console
   - Navigate to Storage
   - Complete the initial setup if you haven't already

2. Verify the correct bucket name

   - The default bucket name is usually `[projectId].appspot.com`
   - Some projects use `[projectId].firebasestorage.app` instead
   - You can find your bucket name in the Firebase Console under Storage

3. Set the `FIREBASE_STORAGE_BUCKET` environment variable
   - Add the correct bucket name to your MCP configuration
   - Example: `"FIREBASE_STORAGE_BUCKET": "your-project-id.firebasestorage.app"`

#### "Firebase is not initialized" Error

If you see this error:

1. Verify your service account key path

   - Make sure the path in `SERVICE_ACCOUNT_KEY_PATH` is correct and absolute
   - Check that the file exists and is readable

2. Check service account permissions
   - Ensure the service account has the necessary permissions for the Firebase services you're using
   - For Storage, the service account needs the Storage Admin role

#### JSON Parsing Errors

If you see errors about invalid JSON:

1. Make sure there are no `console.log` statements in the code

   - All logging should use `console.error` to avoid interfering with the JSON communication
   - The MCP protocol uses stdout for JSON communication

2. Check for syntax errors in your requests
   - Verify that all parameters are correctly formatted
   - Check for typos in field names
