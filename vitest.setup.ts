/* eslint-disable */
import path from 'path';
import fs from 'fs';
import admin from 'firebase-admin';
import { vi, beforeAll, afterAll } from 'vitest';

// Configuration
const USE_EMULATOR = process.env.USE_FIREBASE_EMULATOR === 'true';
const TEST_USER_ID = 'testid';
const TEST_USER_EMAIL = 'test@example.com';
const TEST_USER_PASSWORD = 'password123';
const SERVICE_ACCOUNT_KEY_PATH =
  process.env.SERVICE_ACCOUNT_KEY_PATH || path.resolve(process.cwd(), 'firebaseServiceKey.json');

// Set the service account key path for environment
process.env.SERVICE_ACCOUNT_KEY_PATH = SERVICE_ACCOUNT_KEY_PATH;

// Initialize Firebase
function initializeFirebase() {
  try {
    // Connect to emulator if configured
    if (USE_EMULATOR) {
      process.env.FIRESTORE_EMULATOR_HOST = '127.0.0.1:8080';
      process.env.FIREBASE_AUTH_EMULATOR_HOST = '127.0.0.1:9099';
      process.env.FIREBASE_STORAGE_EMULATOR_HOST = '127.0.0.1:9199';
      console.log('Using Firebase emulator suite');

      // When using emulators, we don't need a real service account
      if (admin.apps.length === 0) {
        admin.initializeApp({
          projectId: 'demo-project',
          storageBucket: 'demo-project.appspot.com',
        });
        console.log('Firebase initialized for testing with emulators');
      }

      return admin;
    }

    // For non-emulator mode, we need a real service account
    const serviceAccountPath = SERVICE_ACCOUNT_KEY_PATH;

    // Check if service account file exists
    if (!fs.existsSync(serviceAccountPath)) {
      throw new Error(
        `Service account key file not found at ${serviceAccountPath}. Set SERVICE_ACCOUNT_KEY_PATH or use USE_FIREBASE_EMULATOR=true.`
      );
    }

    const serviceAccount = JSON.parse(fs.readFileSync(serviceAccountPath, 'utf8'));

    // Check if Firebase is already initialized
    if (admin.apps.length === 0) {
      admin.initializeApp({
        credential: admin.credential.cert(serviceAccount),
        projectId: serviceAccount.project_id,
        storageBucket: `${serviceAccount.project_id}.firebasestorage.app`,
      });

      console.log('Firebase initialized for testing with real Firebase');
    }

    return admin;
  } catch (error) {
    console.error('Firebase initialization failed:', error);
    // Don't throw — unit tests mock Firebase and don't need real credentials
  }
}

// Initialize Firebase before any tests run
initializeFirebase();

// Create test user before tests
beforeAll(async () => {
  try {
    // Make sure Firebase is initialized
    if (!admin.apps.length) {
      initializeFirebase();
    }

    // Try to create the test user
    await admin
      .auth()
      .createUser({
        uid: TEST_USER_ID,
        email: TEST_USER_EMAIL,
        password: TEST_USER_PASSWORD,
        emailVerified: true,
      })
      .catch(error => {
        // If user already exists, that's fine
        if (
          error.code === 'auth/uid-already-exists' ||
          error.code === 'auth/email-already-exists'
        ) {
          console.log(`Test user already exists: ${TEST_USER_EMAIL}`);
        } else {
          throw error;
        }
      });

    console.log(`Test user created/verified: ${TEST_USER_EMAIL}`);
  } catch (error) {
    console.error('Error setting up test user:', error);
  }
}, 10000); // Increase timeout for user creation

// Delete test user after tests
afterAll(async () => {
  try {
    // Make sure Firebase is initialized
    if (!admin.apps.length) {
      initializeFirebase();
    }

    await admin
      .auth()
      .deleteUser(TEST_USER_ID)
      .then(() => console.log(`Test user deleted: ${TEST_USER_EMAIL}`))
      .catch(error => {
        if (error.code !== 'auth/user-not-found') {
          console.error('Error deleting test user:', error);
        }
      });
  } catch (error) {
    console.error('Error cleaning up test user:', error);
  } finally {
    // Only terminate the app if it exists and tests are complete
    if (admin.apps.length) {
      await admin.app().delete().catch(console.error);
    }
  }
}, 10000); // Increase timeout for cleanup

// Mock console methods
console.log = vi.fn(message => process.stdout.write(message + '\n'));
console.info = vi.fn(message => process.stdout.write(message + '\n'));
console.warn = vi.fn(message => process.stdout.write(message + '\n'));
console.error = vi.fn(message => process.stderr.write(message + '\n'));

// Mock logger
vi.mock('../src/utils/logger', () => ({
  logger: {
    debug: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  },
}));
