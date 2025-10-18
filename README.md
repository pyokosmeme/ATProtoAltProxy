# README.md

## Bluesky Reverse-Proxy Injector (Personal)

Serve an upstream Bluesky client (e.g., Blacksky) at your own **private URL** and inject a tiny addon that enables **multi-account posting** without switching accounts. Intended for **personal use** and gated with **Basic Auth** (or Google IAP).

### What it does
- Proxies only **HTML** and injects `/_addon.js`
- Leaves **API/XRPC** calls to go **directly** from your browser to the PDS/Bluesky domains
- Addon provides:
  - **Account vault** (IndexedDB + optional passphrase/WebAuthn)
  - **Account dropdown** and composer
  - **Quote via pasted URL** (resolves `{uri,cid}` and posts as the selected alt)
  - **Token refresh** on 401

### What it does **not** do
- It does **not** read or reuse the site’s login session
- It does **not** proxy XRPC calls (safer, simpler)
- It is **not** for multi-user/public use

---

## Costs (Google Cloud)
- **Cloud Run**: scale-to-zero; for a single user, traffic is tiny. Free tier typically covers hobby use; beyond that, expect **cents/month**.  
- **Secret Manager**: pennies/month for a couple of secrets.  
- Optional services (IAP/Armor/LB) may add small fixed costs.

---

## Prerequisites
- Google Cloud project with **Billing** enabled
- `gcloud` CLI installed & authenticated
- Enable APIs:
  ```bash
  gcloud services enable run.googleapis.com secretmanager.googleapis.com cloudbuild.googleapis.com
  ```
- Node.js 18+ for local build

---

## Quick Start (Cloud Run)

1) **Clone & configure**
```bash
git clone <this-repo>
cd <this-repo>
cp .env.sample .env
# Edit .env for local dev only; production uses Secret Manager
```

2) **Set secrets (Basic Auth)**
```bash
gcloud secrets create BSKY_PROXY_BASIC_USER --replication-policy=automatic
gcloud secrets create BSKY_PROXY_BASIC_PASS --replication-policy=automatic

echo -n 'yourUser'  | gcloud secrets versions add BSKY_PROXY_BASIC_USER --data-file=-
echo -n 'yourPass!' | gcloud secrets versions add BSKY_PROXY_BASIC_PASS --data-file=-
```

3) **Build container (Cloud Build)**
```bash
gcloud builds submit --tag gcr.io/$(gcloud config get-value project)/bsky-proxy
```

4) **Deploy to Cloud Run**
```bash
gcloud run deploy bsky-proxy \
  --image gcr.io/$(gcloud config get-value project)/bsky-proxy \
  --region us-central1 \
  --allow-unauthenticated \
  --set-secrets BASIC_USER=BSKY_PROXY_BASIC_USER:latest,BASIC_PASS=BSKY_PROXY_BASIC_PASS:latest \
  --update-env-vars UPSTREAM_HOST=blacksky.community \
  --min-instances=0 --max-instances=1 \
  --ingress=all
```
> We gate with **Basic Auth** inside the service. If using **IAP** instead, put Cloud Run behind a Load Balancer with IAP and remove Basic Auth.

5) **Open the service URL**  
- Your browser will prompt for **Basic Auth**. Enter credentials you set.  
- You should see Blacksky, with a small addon widget injected.

---

## Configuration
Environment variables (Cloud Run):
- `UPSTREAM_HOST` (required): e.g., `blacksky.community`
- `BASIC_USER`, `BASIC_PASS` (required for Basic Auth): provided via **Secret Manager**

Client-side (addon):  
- No server secrets. Accounts/tokens live in your browser’s IndexedDB only.

---

## Local Development
```bash
npm install
npm run dev
# visit http://localhost:8787
```
- The dev server mimics Cloud Run behavior and injects `/_addon.js` in HTML responses.

---

## Hardening (Optional)
- **Google IAP**: use Google account login; remove Basic Auth.  
- **Cloud Armor**: IP allowlist for home/VPN.  
- **Ingress**: set Cloud Run to internal & LB only when using IAP/LB.  
- **Caching**: pass-through upstream cache headers for assets.

---

## Addon Behavior (Overview)
- UI: “Compose (alts)” button, account dropdown, textarea, optional “Quote URL”  
- Storage: IndexedDB vault; optional passphrase or WebAuthn unlock  
- Post: `com.atproto.repo.createRecord` with selected account; refresh on 401  
- Quote: `app.bsky.feed.getPosts` to resolve `{uri,cid}`, embed `app.bsky.embed.record`

---

## Privacy
- The proxy does **not** handle your ATProto login or tokens.  
- Keep the service URL private and guarded by Basic Auth or IAP.  
- Set `X-Robots-Tag: noindex, nofollow`.

---

## Limitations
- Upstream DOM/CSP changes may require minor updates.  
- The proxy is for **you**; do not share the URL.  
- For deeper integration (one-click quote from feed), consider a userscript or a small fork.

---

## Cleanup
```bash
gcloud run services delete bsky-proxy --region us-central1
gcloud artifacts docker images delete gcr.io/$(gcloud config get-value project)/bsky-proxy --quiet
gcloud secrets delete BSKY_PROXY_BASIC_USER
gcloud secrets delete BSKY_PROXY_BASIC_PASS
```

---

## Minimal Server & Injector (TypeScript Skeleton)

```ts
// src/server.ts
import express from "express";
import fetch, { Headers } from "node-fetch";

const app = express();

const upstreamHost = process.env.UPSTREAM_HOST!;
const user = process.env.BASIC_USER!;
const pass = process.env.BASIC_PASS!;

function unauthorized(res: express.Response) {
  res.set("WWW-Authenticate", 'Basic realm="Private Proxy"');
  return res.status(401).send("Unauthorized");
}

function checkAuth(req: express.Request) {
  const hdr = req.headers.authorization || "";
  if (!hdr.startsWith("Basic ")) return false;
  const given = Buffer.from(hdr.slice(6), "base64").toString("utf8");
  const [u, p] = given.split(":");
  return u === user && p === pass;
}

app.get("/_addon.js", (req, res) => {
  if (!checkAuth(req)) return unauthorized(res);
  res.set("content-type", "application/javascript; charset=utf-8");
  // Keep this file self-contained; no external CDNs
  res.send(`(function(){ /* mount UI, vault, atproto helpers */ })();`);
});

app.use(async (req, res) => {
  if (!checkAuth(req)) return unauthorized(res);

  const upstreamUrl = new URL(req.originalUrl, `https://${upstreamHost}`);
  const upstream = await fetch(upstreamUrl.toString(), {
    method: req.method,
    headers: req.headers as any,
    redirect: "manual",
  });

  const ct = upstream.headers.get("content-type") || "";
  if (!ct.includes("text/html")) {
    upstream.headers.forEach((v, k) => res.set(k, v));
    return upstream.body ? upstream.body.pipe(res) : res.sendStatus(upstream.status);
  }

  let html = await upstream.text();

  // Rewrite CSP narrowly and inject our script
  const headers = new Headers(upstream.headers);
  headers.delete("content-security-policy");
  headers.set(
    "content-security-policy",
    "default-src 'self' https:; script-src 'self' https: 'unsafe-inline'; " +
    "style-src 'self' https: 'unsafe-inline'; img-src 'self' https: data: blob:; " +
    "connect-src 'self' https: blob: data: https://public.api.bsky.app https://*.bsky.app https://*.social https://*.community; " +
    "frame-ancestors 'self';"
  );
  headers.set("x-robots-tag", "noindex, nofollow");
  headers.set("referrer-policy", "strict-origin-when-cross-origin");
  headers.set("permissions-policy", "geolocation=(), microphone=(), camera=()");

  html = html.replace(/<\/body>/i, `<script src="/_addon.js"></script></body>`);

  headers.forEach((v, k) => res.set(k, v));
  res.status(upstream.status).send(html);
});

export default app;
```
