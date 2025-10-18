import express, { NextFunction, Request, Response } from "express";
import fetch, { Headers } from "node-fetch";
import { Readable } from "node:stream";
import { buildCsp } from "./csp.js";
import { injectAddon } from "./inject.js";
import { addonBundle } from "./addon/bundle.js";

const upstreamHost = process.env.UPSTREAM_HOST;
const basicUser = process.env.BASIC_USER;
const basicPass = process.env.BASIC_PASS;

if (!upstreamHost) {
  throw new Error("Missing required env UPSTREAM_HOST");
}
if (!basicUser || !basicPass) {
  throw new Error("Missing BASIC_USER or BASIC_PASS env vars");
}

function unauthorized(res: Response): Response {
  res.setHeader("WWW-Authenticate", 'Basic realm="Private Proxy"');
  return res.status(401).send("Unauthorized");
}

function parseBasicAuth(header: unknown): { name: string; pass: string } | null {
  if (!header || Array.isArray(header)) {
    return null;
  }
  const value = header.toString();
  if (!value.startsWith("Basic ")) {
    return null;
  }
  const encoded = value.slice(6);
  let decoded: string;
  try {
    decoded = Buffer.from(encoded, "base64").toString("utf8");
  } catch (error) {
    console.warn("Failed to decode authorization header", error);
    return null;
  }
  const separator = decoded.indexOf(":");
  if (separator === -1) {
    return null;
  }
  const name = decoded.slice(0, separator);
  const pass = decoded.slice(separator + 1);
  return { name, pass };
}

function authMiddleware(req: Request, res: Response, next: NextFunction): void {
  const credentials = parseBasicAuth(req.headers.authorization);
  if (!credentials) {
    unauthorized(res);
    return;
  }
  const { name, pass } = credentials;
  if (name !== basicUser || pass !== basicPass) {
    unauthorized(res);
    return;
  }
  next();
}

async function proxyHtml(req: Request, res: Response): Promise<void> {
  if (!["GET", "HEAD"].includes(req.method)) {
    res.status(405).send("Method not allowed");
    return;
  }
  const upstreamUrl = new URL(req.originalUrl, `https://${upstreamHost}`);
  const headers = new Headers();
  for (const [key, value] of Object.entries(req.headers)) {
    if (!value) continue;
    if (key.toLowerCase() === "host") continue;
    if (Array.isArray(value)) {
      for (const v of value) {
        headers.append(key, v);
      }
    } else {
      headers.set(key, value);
    }
  }

  const upstreamResponse = await fetch(upstreamUrl, {
    method: req.method,
    headers,
    redirect: "manual"
  });

  const contentType = upstreamResponse.headers.get("content-type") ?? "";
  if (!contentType.includes("text/html")) {
    upstreamResponse.headers.forEach((value, key) => {
      res.setHeader(key, value);
    });
    res.status(upstreamResponse.status);
    const body = upstreamResponse.body;
    if (body) {
      Readable.fromWeb(body as unknown as any).pipe(res);
      return;
    }
    res.end();
    return;
  }

  const headersToSend = new Headers(upstreamResponse.headers);
  headersToSend.delete("content-security-policy");
  headersToSend.set("content-security-policy", buildCsp());
  headersToSend.set("x-robots-tag", "noindex, nofollow");
  headersToSend.set("referrer-policy", "strict-origin-when-cross-origin");
  headersToSend.set("permissions-policy", "geolocation=(), microphone=(), camera=()");

  headersToSend.forEach((value, key) => {
    res.setHeader(key, value);
  });

  if (req.method === "HEAD") {
    res.status(upstreamResponse.status).end();
    return;
  }

  let html = await upstreamResponse.text();
  html = injectAddon(html);
  res.status(upstreamResponse.status).send(html);
}

const app = express();
app.disable("x-powered-by");

app.get("/healthz", (_req, res) => {
  res.status(200).json({ ok: true });
});

app.get("/_addon.js", authMiddleware, (_req, res) => {
  res.type("application/javascript");
  res.send(addonBundle);
});

app.use(authMiddleware, async (req, res) => {
  try {
    await proxyHtml(req, res);
  } catch (error) {
    console.error("Proxy error", error);
    res.status(502).send("Upstream fetch failed");
  }
});

const port = Number.parseInt(process.env.PORT ?? "8787", 10);

if (Number.isNaN(port)) {
  throw new Error("PORT must be a number");
}

if (process.env.NODE_ENV !== "test") {
  app.listen(port, () => {
    console.log(`Proxy listening on :${port}, upstream ${upstreamHost}`);
  });
}

export default app;
