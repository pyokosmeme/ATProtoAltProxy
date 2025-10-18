const INJECT_MARKER = /<\/body>/i;

export function injectAddon(html: string): string {
  if (INJECT_MARKER.test(html)) {
    return html.replace(INJECT_MARKER, "<script src=\"/_addon.js\"></script></body>");
  }
  return `${html}\n<script src="/_addon.js"></script>`;
}
