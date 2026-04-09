#!/bin/sh
set -e

# Start Playwright MCP server in the background (internal, port 8931)
node /app/cli.js \
  --headless --browser chromium --no-sandbox \
  --port 8931 --host 127.0.0.1 \
  --allowed-hosts '*' &

# Wait for Playwright MCP to be ready
for i in $(seq 1 30); do
  if wget -q -O /dev/null http://127.0.0.1:8931/mcp 2>/dev/null; then
    break
  fi
  sleep 1
done

# Start OAuth auth proxy (public-facing, port 3000)
exec node /proxy/auth-proxy.mjs
