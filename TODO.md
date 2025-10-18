# TODO

## Project: Bluesky Reverse-Proxy Injector (Personal)

A living task list to get from zero → usable → hardened.

---

## Phase 0 — Repo & Scaffolding
- [x] Initialize repo structure (`src/server.ts`, `src/addon/*`, Dockerfile, README, DESIGN, TODO)
- [x] Choose license (likely MIT) and `.editorconfig`
- [x] Setup TypeScript, ts-node/dev server, ESLint/Prettier
- [x] Add minimal Express server + health check (`/healthz`)

## Phase 1 — Proxy MVP (Cloud Run)
- [x] Implement **Basic Auth** middleware (401 with `WWW-Authenticate`)
- [x] Hardcode/ENV `UPSTREAM_HOST` (e.g., `blacksky.community`)
- [x] Pass-through for non-HTML; transform only `text/html`
- [x] **CSP rewrite**: allow self + official Bluesky domains; block 3rd-party scripts
- [x] Inject `<script src="/_addon.js">` before `</body>`
- [x] Add headers: `X-Robots-Tag`, `Referrer-Policy`, `Permissions-Policy`
- [x] No request body logging; confirm Cloud Run default access logs only
- [ ] Build & run locally

## Phase 2 — Addon MVP
- [ ] Minimal floating UI: “Compose (alts)”, account dropdown, textarea
- [ ] IndexedDB vault (plain JSON first)
- [ ] ATProto helpers: `createSession`, `refreshSession`, `createRecord`
- [ ] Post text as selected account
- [ ] Quote via URL: resolve `{uri,cid}` using `app.bsky.feed.getPosts` (public read API)
- [ ] Basic error toasts + success confirmation
- [ ] Keyboard shortcut (`c`) to focus composer

## Phase 3 — Security & Storage
- [ ] Encrypt vault with Web Crypto (AES-GCM) + PBKDF2 passphrase
- [ ] Optional WebAuthn device-unlock (wrap vault key)
- [ ] “Lock now” and “Clear vault” controls
- [ ] Use **App Passwords** only; document this in UI

## Phase 4 — Posting Features
- [ ] Media upload: `com.atproto.repo.uploadBlob` (images); preview thumbnails
- [ ] Facets (links/mentions) and basic character counter
- [ ] Reply flow: paste a post URL and set `reply` block
- [ ] Switch account retains compose text (drafts per account)
- [ ] Token refresh retry-once logic; surface refresh failures

## Phase 5 — Integration Quality
- [ ] Intercept site “Post/Quote” buttons: capturing click listener + robust selectors
- [ ] Site-agnostic selectors: support blacksky.community, bsky.app, deer.social
- [ ] Fallback if selector fails: prompt to paste URL
- [ ] Position UI so it doesn’t occlude site controls; responsive layout

## Phase 6 — Deployment (GCP)
- [ ] Create secrets in Secret Manager: `BASIC_USER`, `BASIC_PASS`
- [ ] Cloud Build image publish
- [ ] Cloud Run deploy (min 0, max 1, allow unauth; Basic Auth gates within)
- [ ] Custom domain mapping (optional), HTTPS enforced
- [ ] Verify Basic Auth challenge; verify addon injection
- [ ] Confirm API (XRPC) goes direct to PDS (DevTools network check)

## Phase 7 — Hardening (Optional/Recommended)
- [ ] Replace Basic Auth with **IAP** (Cloud Run behind HTTPS LB + IAP)
- [ ] Set Cloud Run ingress to **internal & LB** when using IAP
- [ ] Cloud Armor IP allowlist for home/VPN egress
- [ ] Tighten CSP to exact domains you use; remove `'unsafe-inline'` if possible
- [ ] Strip or rewrite SRI attrs if present; consider SRI re-add for untouched bundles
- [ ] HSTS (at domain), noindex headers confirmed
- [ ] Disable all analytics/telemetry

## Phase 8 — Quality & Testing
- [ ] Unit tests for inject & CSP logic
- [ ] E2E smoke test against upstream (Playwright): verify injection + basic posting
- [ ] Snapshot-based check for selector drift
- [ ] Manual test checklist across Chrome/Firefox/Safari

## Phase 9 — DX & Ops
- [ ] Makefile / npm scripts: `dev`, `build`, `deploy`
- [ ] CI: Cloud Build or GitHub Actions (build + deploy on tag)
- [ ] Error monitoring (optional): client-side toast only; no PII
- [ ] Version pinning and Renovate for deps

## Phase 10 — Documentation
- [ ] Update README with screenshots/gifs
- [ ] Add SECURITY.md (personal-use notes, scope)
- [ ] Document WebAuthn unlock flow + recovery
- [ ] Note limitations and future enhancement ideas

---

## Backlog / Nice-to-have
- [ ] Toggle to hide the site’s native composer (overlay shield)
- [ ] Per-portal settings (enable/disable intercepts)
- [ ] Compact mode for small screens
- [ ] Import/export accounts (encrypted file)
- [ ] Theme sync (light/dark) with upstream
