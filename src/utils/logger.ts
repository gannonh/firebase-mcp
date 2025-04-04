/**
 * Simple logger utility that wraps console methods
 * Avoids direct console usage which can interfere with MCP stdio
 */
import * as fs from 'fs';
import * as path from 'path';

const LOG_FILE = '/tmp/firebase-mcp.log';

// Ensure log file exists and is writable
try {
  fs.writeFileSync(LOG_FILE, '', { flag: 'a' });
} catch (error) {
  console.error(`Failed to create log file at ${LOG_FILE}:`, error);
}

const writeToLog = (level: string, message: string, data?: any) => {
  const timestamp = new Date().toISOString();
  const logMessage = `[${timestamp}] [${level}] ${message}\n`;
  
  // Write to stderr
  process.stderr.write(logMessage);
  
  // Write to log file
  try {
    fs.appendFileSync(LOG_FILE, logMessage);
    if (data) {
      const dataStr = JSON.stringify(data, null, 2);
      fs.appendFileSync(LOG_FILE, `${dataStr}\n`);
    }
  } catch (error) {
    process.stderr.write(`Failed to write to log file: ${error}\n`);
  }
};

export const logger = {
  info: (message: string, ...args: any[]) => {
    writeToLog('INFO', message, args.length > 0 ? args : undefined);
  },
  
  error: (message: string, error?: any) => {
    writeToLog('ERROR', message, error);
  },
  
  debug: (message: string, ...args: any[]) => {
    writeToLog('DEBUG', message, args.length > 0 ? args : undefined);
  },
  
  warn: (message: string, ...args: any[]) => {
    writeToLog('WARN', message, args.length > 0 ? args : undefined);
  }
};