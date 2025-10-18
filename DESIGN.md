# DESIGN.md

## Project: Bluesky “Reverse-Proxy Injector” (Personal Use)

### Goal
Provide a **bookmarkable URL** that serves an upstream Bluesky client (e.g., `blacksky.community`) unaltered **except** for injecting a small **addon script** that adds a **multi-account composer** and an **account dropdown**. The addon posts/quotes via **AT Protocol** using your **own locally stored app passwords/tokens**—not the site’s session—so you can post as alts without switching accounts. The proxy is **password-gated** and intended for **your personal use only**.

---

## High-Level Architecture

```
Browser ──HTTPS──> Cloud Run (proxy) ──HTTPS──> Upstream (e.g., blacksky.community)
           │                 │
           │                 └─ serves /_addon.js (your decorator)
           │
           └─ Direct HTTPS to PDS/XRPC (posting/quoting via AT Proto)
```

- **Cloud Run (Node/Express)**  
  - Enforces **Basic Auth** (or optional Google IAP) on every request
  - Fetches upstream HTML, **rewrites CSP** headers to allow your one injected script & official API origins
  - **Injects** `<script src="/_addon.js">` before `</body>`
  - Pass-through for non-HTML assets (JS/CSS/images) and all other methods
  - **Does not** proxy XRPC calls; your browser talks directly to PDS/ATProto endpoints

- **Addon (`/_addon.js`)**  
  - Mounts a small floating UI (account dropdown, “Compose”, optional “Quote URL” field)
  - Stores **account tokens** client-side (IndexedDB; optional passphrase; optional WebAuthn unlock)
  - Intercepts “Post”/“Quote” affordances with capturing listeners and routes to your composer
  - Uses `com.atproto.server.createSession/refreshSession` and `com.atproto.repo.createRecord` to post as the **selected account**  
  - For quotes, resolves `{uri,cid}` via `app.bsky.feed.getPosts` using the public read API

---

## Security Model

**What the proxy can see**
- Only the HTML (and assets) it fetches from upstream.
- It **does not** see your ATProto app passwords/tokens if the addon calls PDS endpoints directly.

**Controls**
- **Password gate**: Basic Auth (stored in Secret Manager) or **Google IAP** (preferred if you want Google-account login)
- **No request logging** in code (Cloud Run access logs remain minimal; you can restrict or retain per your policy)
- **CSP rewrite**: Narrow policy that allows only self + official Bluesky domains; blocks 3rd-party scripts
- **Robots**: `noindex, nofollow`
- **Referrer-Policy**: `strict-origin-when-cross-origin`
- **Permissions-Policy**: Disable camera/mic/geolocation, etc.
- Optional: **Cloud Armor IP allowlist** (only your home/VPN egress)

**Addon storage**
- **IndexedDB** vault with **Web Crypto (AES-GCM)**; key derived via **PBKDF2** from a passphrase or unwrapped via **WebAuthn** for passwordless unlock
- Tokens refreshed on 401 via `refreshSession`

---

## Request Flow

1. **Browser → Cloud Run**  
   - Cloud Run challenges with **Basic Auth** (401) unless correct credentials provided.
   - On success, Cloud Run fetches upstream HTML.

2. **Cloud Run → Upstream**  
   - Returns upstream HTML; proxy **replaces CSP** and **injects** `<script src="/_addon.js">`.

3. **Browser loads page + addon**  
   - Addon mounts UI, loads/requests your vault unlock, and registers click handlers.

4. **User composes a post**  
   - Addon sends **direct XRPC** to the selected account’s **PDS**; not via the proxy.

---

## Trade-offs

- **Pros**
  - Upstream stays current automatically—no fork to maintain
  - Your URL works on all devices/browsers
  - Proxy never handles credentials if you keep XRPC direct

- **Cons**
  - If upstream radically changes DOM affordances, selectors in the addon may need small tweaks
  - If upstream sets very strict CSP/SRI, you must keep the rewrite logic up to date
  - You manage a tiny serverless service (Cloud Run) instead of pure static hosting

---

## Threat Model & Mitigations

- **Unauthorized use of your proxy** → Basic Auth or IAP; optional IP allowlist via Cloud Armor  
- **Proxy abused as public MITM** → Gate all requests; hardcode upstream host; refuse non-GET/HEAD for HTML  
- **Addon exfiltration risk** → No 3rd-party code; strict CSP; local-only token storage; no telemetry  
- **Credential exposure** → ATProto tokens stay in browser; proxy doesn’t see them; use App Passwords

---

## File/Module Structure

```
/
├─ src/
│  ├─ server.ts            # Express app: auth → proxy → inject
│  ├─ csp.ts               # CSP builder for rewrite
│  ├─ inject.ts            # HTML transform (insert <script>, strip SRI if needed)
│  └─ addon/
│     ├─ addon.ts          # UI mount, event interception
│     ├─ vault.ts          # IndexedDB + Web Crypto + optional WebAuthn
│     ├─ atproto.ts        # createSession, refreshSession, createRecord helpers
│     └─ selectors.ts      # resilient matchers for Post/Quote buttons (site-agnostic fallback)
├─ package.json
├─ tsconfig.json
├─ Dockerfile
├─ .dockerignore
├─ .env.sample
├─ DESIGN.md
└─ README.md
```

---

## Key Headers We Set

- `Content-Security-Policy`:  
  ```
  default-src 'self' https:;
  script-src 'self' 'unsafe-inline' https:;
  style-src 'self' 'unsafe-inline' https:;
  img-src 'self' https: data: blob:;
  connect-src 'self' https: blob: data: https://public.api.bsky.app https://*.bsky.app https://*.social https://*.community;
  frame-ancestors 'self';
  ```
- `X-Robots-Tag: noindex, nofollow`  
- `Referrer-Policy: strict-origin-when-cross-origin`  
- `Permissions-Policy: geolocation=(), camera=(), microphone=()`  

(Adjust `connect-src` for any PDS you use.)

---

## Future Enhancements

- **IAP** instead of Basic Auth for Google-account login  
- **Cloud Armor** IP allowlist  
- **Feature flags** in addon (enable/disable intercepts per domain)  
- **SRI-aware injector** that re-adds integrity for untouched bundles  
- **Testing harness** that validates selectors against upstream snapshots
