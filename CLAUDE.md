# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Firebase MCP is an MCP (Model Context Protocol) server that exposes Firebase services (Firestore, Storage, Authentication) as tools for AI assistants. Published as `@gannonh/firebase-mcp` on npm.

## Common Commands

```bash
npm run build              # TypeScript compilation (tsc)
npm run test:emulator      # Run tests against Firebase emulator (preferred)
npm run test               # Run tests against real Firebase (needs service account)
npm run test:verbose       # Tests with detailed output
npm run lint               # ESLint check
npm run fix                # Lint fix + Prettier format
npm run preflight          # Full pre-merge check: format, lint, build, coverage (emulator)
npm run dev                # Build + run server (stdio)
npm run dev:http           # Build + run server (HTTP transport)
```

Single test file: `npx vitest run path/to/file.test.ts`

## Architecture

### Server Core (`src/index.ts`)
Single `FirebaseMcpServer` class that:
1. Initializes Firebase Admin SDK from `SERVICE_ACCOUNT_KEY_PATH`
2. Registers 12 MCP tools via `setupToolHandlers()` (ListTools + CallTool handlers)
3. Dispatches tool calls through a switch statement
4. Connects to a transport (stdio or HTTP)

### Firebase Service Clients (`src/lib/firebase/`)
- `firestoreClient.ts` - Firestore CRUD, queries, collection group queries
- `storageClient.ts` - File list/info/upload (local, base64, text, URL)
- `authClient.ts` - User lookup by email or UID

### Transport Layer (`src/transports/`)
- `index.ts` - Factory that selects stdio vs HTTP based on config
- `http.ts` - Express.js server with session-based SSE for MCP over HTTP

### Configuration (`src/config.ts`)
Environment variables loaded via dotenv. `SERVICE_ACCOUNT_KEY_PATH` is required; transport defaults to stdio. `FIRESTORE_DATABASE_ID` optionally targets a named Firestore database. Auto-detects stdio context from TTY state.

## Key Patterns

- **Logging**: Use `logger` from `src/utils/logger.ts`, never `console.log` (eslint rule). All log output goes to stderr to preserve stdout for JSON-RPC.
- **Timestamps**: ISO date strings in Firestore queries auto-convert to `Timestamp` objects. `{ __serverTimestamp: true }` triggers `FieldValue.serverTimestamp()`.
- **Responses**: All tool responses return `{ content: [{ type: "text", text: string }], isError?: boolean }`.
- **ESM**: The project uses ES modules (`"type": "module"` in package.json). All local imports use `.js` extensions.

## Testing

- **Framework**: Vitest with globals enabled
- **Test location**: `src/**/__tests__/*.test.ts`
- **Setup**: `vitest.setup.ts` initializes Firebase (emulator or real), creates/cleans up a test user (`testid`/`test@example.com`), and mocks console + logger
- **Emulator mode**: `USE_FIREBASE_EMULATOR=true` connects to local emulators on ports 8080 (Firestore), 9099 (Auth), 9199 (Storage)
- **Coverage thresholds**: statements 50%, branches 65%, functions 80%, lines 50%

## Lint/Format Rules

- Prettier: 100 char width, 2-space indent, single quotes, semicolons, trailing commas
- ESLint: TypeScript strict mode, no unused vars (except `_`-prefixed), warn on explicit `any`, consistent type imports, no `console.log`
