#!/usr/bin/env node

/**
 * Firebase MCP Environment Configuration Generator
 *
 * This script helps generate environment variables for the Firebase MCP server
 * from a service account key file downloaded from the Firebase Console.
 */

const fs = require("fs");
const path = require("path");
const readline = require("readline");
const crypto = require("crypto");

// Create interface for command line input/output
const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
});

// Ask for input with a promise
function question(query) {
  return new Promise((resolve) => rl.question(query, resolve));
}

// Generate a random secure string for secrets
function generateSecureString(length = 32) {
  return crypto.randomBytes(length).toString("hex");
}

// Main function
async function main() {
  console.log("\n=== Firebase MCP Environment Configuration Generator ===\n");

  try {
    // Get service account key file path
    const defaultKeyPath = path.join(process.cwd(), "serviceAccountKey.json");
    const keyFilePath = await question(
      `Enter path to your Firebase service account key JSON file [${defaultKeyPath}]: `
    );
    const actualKeyPath = keyFilePath || defaultKeyPath;

    // Check if the file exists
    if (!fs.existsSync(actualKeyPath)) {
      throw new Error(`File not found: ${actualKeyPath}`);
    }

    // Read and parse the file
    const serviceAccount = JSON.parse(fs.readFileSync(actualKeyPath, "utf8"));

    // Get server configuration
    const serverName = await question(
      "Enter server name [firebase-mcp-secure]: "
    );
    const serverVersion = await question("Enter server version [1.0.0]: ");
    const port = await question("Enter HTTP port [3000]: ");
    const transport = await question(
      "Enter transport (http or stdio) [http]: "
    );
    const enableSecurity = await question(
      "Enable security features? (true/false) [true]: "
    );

    // Generate secrets
    const sessionSecret = generateSecureString();
    const jwtSecret = generateSecureString();

    // Prepare environment variables
    const envVars = {
      // Server configuration
      SERVER_NAME: serverName || "firebase-mcp-secure",
      SERVER_VERSION: serverVersion || "1.0.0",
      PORT: port || "3000",
      TRANSPORT: transport || "http",
      ENABLE_SECURITY: enableSecurity || "true",

      // Security settings
      SESSION_SECRET: sessionSecret,
      SESSION_EXPIRY: "3600",
      JWT_SECRET: jwtSecret,
      JWT_EXPIRY: "86400",

      // CORS configuration
      CORS_ORIGINS: "http://localhost:3000,http://localhost:8080",

      // Audit logging
      LOG_DIRECTORY: "logs",
      LOG_MAX_DAYS: "30",
      LOG_ROTATION_INTERVAL: "1d",
      CONSOLE_LOGGING: "true",

      // Firebase configuration
      FIREBASE_PROJECT_ID: serviceAccount.project_id,
      FIREBASE_CLIENT_EMAIL: serviceAccount.client_email,
      FIREBASE_PRIVATE_KEY: serviceAccount.private_key,
    };

    // Create .env file content
    let envContent = "";
    for (const [key, value] of Object.entries(envVars)) {
      envContent += `${key}=${value}\n`;
    }

    // Write to .env file
    const envFilePath = path.join(process.cwd(), ".env");
    fs.writeFileSync(envFilePath, envContent);

    console.log(
      `\n✅ Environment configuration successfully written to ${envFilePath}`
    );
    console.log(
      "\n⚠️  WARNING: This file contains sensitive information. Do not commit it to version control."
    );
    console.log("   Make sure .env is in your .gitignore file.\n");

    // Generated admin API key
    const adminApiKey = generateSecureString(24);
    console.log(`Generated Admin API Key: ${adminApiKey}`);
    console.log(
      "You can add this to your .env file as ADMIN_API_KEY to create an admin client with this key.\n"
    );
  } catch (error) {
    console.error(`\n❌ Error: ${error.message}`);
    process.exit(1);
  } finally {
    rl.close();
  }
}

// Run the script
main();
