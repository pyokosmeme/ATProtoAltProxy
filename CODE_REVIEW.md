# Code Review

## Summary
This review focuses on the current TypeScript proxy implementation, with an emphasis on runtime behavior and security boundaries.

## Findings

### 1. Response headers conflict with rewritten bodies (bug)
- `proxyHtml` rewrites HTML bodies by injecting the addon script but forwards all upstream headers verbatim (except for a few overrides).
- If the upstream response is compressed (e.g., `content-encoding: gzip`) or has a specific `content-length`, Express will send the modified, uncompressed body with the stale headers.
- This leads to mismatched lengths or incorrect encodings that can break page loads in browsers.
- **Fix:** Remove hop-by-hop headers such as `content-encoding`, `content-length`, and `transfer-encoding` before sending the modified HTML so Express can set them correctly.

### 2. Missing cache-control strategy for addon bundle (observation)
- `/_addon.js` is served with default Express caching headers, so browsers may cache aggressively.
- During development or rapid iteration, users might not see updated addon code.
- **Suggestion:** Add `Cache-Control: no-store` (or similar) for the addon endpoint to guarantee that updates propagate immediately.

### 3. Basic-auth parsing lacks defensive logging (nit)
- When credentials are missing or malformed, the proxy silently responds `401` without logging the event.
- Minimal audit logging (e.g., warn on failures with the request IP) would assist debugging failed logins without revealing credentials.

## Positive Notes
- The CSP helper removes the upstream policy and constructs a deterministic policy with the injected script in mind.
- Restricting the proxy to `GET` and `HEAD` reduces the attack surface substantially.
- Streaming passthrough for non-HTML content prevents buffering large asset responses in memory.

