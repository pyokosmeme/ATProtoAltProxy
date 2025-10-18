# Local Build & Test Guide

This document walks through installing dependencies, configuring the proxy, and running it locally for manual testing.

## 1. Prerequisites
- **Node.js 18+** (the server relies on `Readable.fromWeb`, available starting in Node 18).
- **npm** (comes with Node) or **pnpm/yarn** if you prefer alternatives.
- An upstream Bluesky-compatible host to proxy (e.g., `bsky.app`, `blacksky.community`).

## 2. Clone & Install
```bash
git clone https://github.com/<your-account>/ATProtoAltProxy.git
cd ATProtoAltProxy
npm install
```

## 3. Configure Environment
Create a `.env` file (or export variables in your shell) with the required secrets:
```bash
cp .env.sample .env
# Edit .env and set the variables below
```
Required variables:
- `UPSTREAM_HOST`: Hostname of the upstream Bluesky client (no scheme).
- `BASIC_USER`: Username for HTTP Basic authentication.
- `BASIC_PASS`: Password for HTTP Basic authentication.

You can also export them directly when running commands:
```bash
export UPSTREAM_HOST=blacksky.community
export BASIC_USER=localuser
export BASIC_PASS=localpass
```

## 4. Run the Development Server
Use the TypeScript watcher for a live-reloading development experience:
```bash
npm run dev
```
This starts the proxy on `http://localhost:8787`. Visit that URL, enter your basic-auth credentials, and confirm that the upstream site loads with the injected addon widget.

## 5. Build the Production Bundle
Compile TypeScript to plain JavaScript in the `dist/` folder:
```bash
npm run build
```
The command runs `tsc` using `tsconfig.json` and outputs `dist/server.js` and friends.

## 6. Run the Compiled Server
After `npm run build`, start the compiled output with Node:
```bash
npm run start
```
The `start` script executes `node dist/server.js` and respects the same environment variables described above.

## 7. Lint & Quality Checks
To ensure the codebase passes linting before you commit:
```bash
npm run lint
```
This uses ESLint with the TypeScript plugin to catch style and correctness issues.

## 8. Optional: Exercise the Health Check
With the server running (dev or compiled), verify the health endpoint:
```bash
curl -u "$BASIC_USER:$BASIC_PASS" http://localhost:8787/healthz
```
You should receive `{ "ok": true }`.

## 9. Cleanup
Stop the server with `Ctrl+C`. You can remove build artifacts by deleting the `dist/` directory:
```bash
rm -rf dist
```

You are now set up to iterate locally, test changes, and build production artifacts.
