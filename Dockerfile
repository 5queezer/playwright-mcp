FROM mcr.microsoft.com/playwright/mcp:latest

# Bind to all interfaces and allow any Host header (required behind a reverse proxy).
# --allowed-hosts '*' disables the DNS-rebinding check that rejects non-localhost hosts.
ENTRYPOINT ["node", "/app/cli.js", \
  "--headless", "--browser", "chromium", "--no-sandbox", \
  "--port", "8931", "--host", "0.0.0.0", \
  "--allowed-hosts", "*", \
  "--isolated"]
EXPOSE 8931
