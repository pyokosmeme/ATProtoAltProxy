const DEFAULT_CONNECT_SRC = [
  "'self'",
  "https://public.api.bsky.app",
  "https://*.bsky.app",
  "https://*.social",
  "https://*.community"
];

export function buildCsp(connectSrc: string[] = DEFAULT_CONNECT_SRC): string {
  const connect = Array.from(new Set(connectSrc));
  return [
    "default-src 'self' https:",
    "script-src 'self' 'unsafe-inline' https:",
    "style-src 'self' 'unsafe-inline' https:",
    "img-src 'self' https: data: blob:",
    `connect-src ${connect.join(' ')}`,
    "frame-ancestors 'self'"
  ].join('; ');
}
