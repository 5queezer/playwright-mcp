// OAuth 2.1 PKCE auth proxy for Playwright MCP
// Sits in front of the Playwright MCP server, adds authentication.
import http from 'node:http';
import crypto from 'node:crypto';
import { URL, URLSearchParams } from 'node:url';

const PORT = parseInt(process.env.PORT || '3000', 10);
const UPSTREAM = process.env.UPSTREAM || 'http://127.0.0.1:8931';
const AUTH_PIN = process.env.AUTH_PIN;
const PUBLIC_URL = process.env.PUBLIC_URL; // e.g. https://browser.vasudev.xyz

if (!AUTH_PIN) { console.error('AUTH_PIN env var is required'); process.exit(1); }
if (!PUBLIC_URL) { console.error('PUBLIC_URL env var is required'); process.exit(1); }

// ── In-memory stores ────────────────────────────────────────────────────────
const authCodes = new Map();   // code → { codeChallenge, clientId, redirectUri, expiresAt }
const tokens = new Set();      // valid access tokens
const clients = new Map();     // clientId → { redirectUris, clientName }

const rand = () => crypto.randomBytes(24).toString('base64url');

// ── Helpers ─────────────────────────────────────────────────────────────────
function json(res, status, data) {
  res.writeHead(status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
  res.end(JSON.stringify(data));
}

function readBody(req) {
  return new Promise(r => { let b = ''; req.on('data', c => b += c); req.on('end', () => r(b)); });
}

function parseForm(body) { return Object.fromEntries(new URLSearchParams(body)); }

function verifyS256(verifier, challenge) {
  return crypto.createHash('sha256').update(verifier).digest('base64url') === challenge;
}

function bearerToken(req) {
  const h = req.headers.authorization || '';
  return h.startsWith('Bearer ') ? h.slice(7) : null;
}

// ── OAuth Metadata (RFC 8414) ───────────────────────────────────────────────
function metadata(_req, res) {
  json(res, 200, {
    issuer: PUBLIC_URL,
    authorization_endpoint: `${PUBLIC_URL}/authorize`,
    token_endpoint: `${PUBLIC_URL}/token`,
    registration_endpoint: `${PUBLIC_URL}/register`,
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code'],
    token_endpoint_auth_methods_supported: ['none', 'client_secret_post'],
    code_challenge_methods_supported: ['S256'],
  });
}

// ── Dynamic Client Registration (RFC 7591) ──────────────────────────────────
async function register(req, res) {
  const data = JSON.parse(await readBody(req));
  const clientId = rand();
  clients.set(clientId, {
    redirectUris: data.redirect_uris || [],
    clientName: data.client_name || 'mcp-client',
  });
  json(res, 201, {
    client_id: clientId,
    client_name: data.client_name,
    redirect_uris: data.redirect_uris,
    grant_types: ['authorization_code'],
    response_types: ['code'],
    token_endpoint_auth_method: 'none',
  });
}

// ── Authorization Endpoint ──────────────────────────────────────────────────
async function authorize(req, res) {
  const url = new URL(req.url, PUBLIC_URL);

  if (req.method === 'GET') {
    // Show PIN form
    const qs = url.searchParams;
    const fields = ['client_id', 'redirect_uri', 'state', 'code_challenge', 'code_challenge_method', 'response_type', 'scope']
      .map(k => `<input type="hidden" name="${k}" value="${esc(qs.get(k) || '')}">`)
      .join('\n');

    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(`<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>Authorize</title><style>
*{box-sizing:border-box}body{font-family:system-ui;max-width:380px;margin:60px auto;padding:20px;color:#1a1a1a}
input[type=password]{display:block;width:100%;padding:14px;margin:8px 0;font-size:24px;text-align:center;
letter-spacing:10px;border:2px solid #d0d0d0;border-radius:8px}
button{display:block;width:100%;padding:14px;margin-top:16px;font-size:16px;font-weight:600;
background:#111;color:#fff;border:none;border-radius:8px;cursor:pointer}
.err{color:#c00;font-weight:600}
</style></head><body>
<h2>Authorize MCP</h2>
<p>Enter PIN to allow browser automation access.</p>
${url.searchParams.get('error') ? '<p class="err">Wrong PIN. Try again.</p>' : ''}
<form method="POST" action="/authorize">${fields}
<input type="password" name="pin" maxlength="20" placeholder="PIN" autofocus required>
<button type="submit">Authorize</button>
</form></body></html>`);
    return;
  }

  // POST — validate PIN, issue code
  const form = parseForm(await readBody(req));

  if (form.pin !== AUTH_PIN) {
    // Re-show form with error
    const retry = new URL('/authorize', PUBLIC_URL);
    for (const k of ['client_id', 'redirect_uri', 'state', 'code_challenge', 'code_challenge_method', 'response_type', 'scope'])
      if (form[k]) retry.searchParams.set(k, form[k]);
    retry.searchParams.set('error', '1');
    res.writeHead(303, { Location: retry.toString() });
    res.end();
    return;
  }

  const code = rand();
  authCodes.set(code, {
    codeChallenge: form.code_challenge,
    clientId: form.client_id,
    redirectUri: form.redirect_uri,
    expiresAt: Date.now() + 5 * 60_000,
  });

  const cb = new URL(form.redirect_uri);
  cb.searchParams.set('code', code);
  if (form.state) cb.searchParams.set('state', form.state);
  res.writeHead(303, { Location: cb.toString() });
  res.end();
}

function esc(s) { return s.replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]); }

// ── Token Endpoint ──────────────────────────────────────────────────────────
async function token(req, res) {
  const form = parseForm(await readBody(req));

  if (form.grant_type !== 'authorization_code') return json(res, 400, { error: 'unsupported_grant_type' });

  const entry = authCodes.get(form.code);
  if (!entry || entry.expiresAt < Date.now()) return json(res, 400, { error: 'invalid_grant' });

  if (!verifyS256(form.code_verifier, entry.codeChallenge)) return json(res, 400, { error: 'invalid_grant', error_description: 'PKCE verification failed' });

  authCodes.delete(form.code);

  const accessToken = rand();
  tokens.add(accessToken);

  json(res, 200, {
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: 86400,
  });
}

// ── MCP Reverse Proxy ───────────────────────────────────────────────────────
function proxyMcp(req, res) {
  const tok = bearerToken(req);
  if (!tok || !tokens.has(tok)) {
    res.writeHead(401, {
      'WWW-Authenticate': `Bearer resource_metadata="${PUBLIC_URL}/.well-known/oauth-protected-resource"`,
      'Content-Type': 'application/json',
    });
    res.end(JSON.stringify({ error: 'unauthorized' }));
    return;
  }

  // Forward to upstream, stripping auth header
  const upstream = new URL(req.url, UPSTREAM);
  const headers = { ...req.headers };
  delete headers.authorization;
  delete headers.host;
  // Cloudflare sends HTTP/2 pseudo-headers that break Node http.request
  for (const k of Object.keys(headers)) { if (k.startsWith(':')) delete headers[k]; }
  headers.host = new URL(UPSTREAM).host;
  headers.connection = 'keep-alive';

  const proxy = http.request(upstream, { method: req.method, headers }, (upRes) => {
    const ct = upRes.headers['content-type'] || '';
    console.log(`  ↳ upstream ${upRes.statusCode} ${ct.split(';')[0]}`);
    // Disable buffering for SSE responses
    if (ct.includes('text/event-stream')) {
      res.writeHead(upRes.statusCode, { ...upRes.headers, 'X-Accel-Buffering': 'no', 'Cache-Control': 'no-cache' });
      upRes.on('data', (chunk) => { res.write(chunk); });
      upRes.on('end', () => { res.end(); });
    } else {
      res.writeHead(upRes.statusCode, upRes.headers);
      upRes.pipe(res, { end: true });
    }
  });
  proxy.on('error', (e) => {
    console.error('Upstream error:', e.message);
    if (!res.headersSent) json(res, 502, { error: 'upstream_unavailable' });
  });
  req.pipe(proxy, { end: true });
}

// ── Protected Resource Metadata ─────────────────────────────────────────────
function resourceMetadata(_req, res) {
  json(res, 200, {
    resource: `${PUBLIC_URL}/mcp`,
    authorization_servers: [PUBLIC_URL],
  });
}

// ── Router ──────────────────────────────────────────────────────────────────
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, PUBLIC_URL);
  const path = url.pathname;

  console.log(`${req.method} ${path}${bearerToken(req) ? ' [auth]' : ''}`);

  try {
    if (path === '/.well-known/oauth-authorization-server') return metadata(req, res);
    if (path === '/.well-known/oauth-protected-resource') return resourceMetadata(req, res);
    if (path === '/register' && req.method === 'POST') return await register(req, res);
    if (path === '/authorize') return await authorize(req, res);
    if (path === '/token' && req.method === 'POST') return await token(req, res);
    if (path === '/mcp' || path.startsWith('/mcp/')) return proxyMcp(req, res);
    if (path === '/sse') return proxyMcp(req, res);      // legacy SSE stream
    if (path === '/messages') return proxyMcp(req, res);  // legacy SSE message endpoint

    // Health check
    if (path === '/healthz') return json(res, 200, { status: 'ok' });

    json(res, 404, { error: 'not_found' });
  } catch (e) {
    console.error('Error:', e);
    if (!res.headersSent) json(res, 500, { error: 'internal_error' });
  }
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`Auth proxy listening on http://0.0.0.0:${PORT}`);
  console.log(`Upstream: ${UPSTREAM}`);
  console.log(`Public URL: ${PUBLIC_URL}`);
});
