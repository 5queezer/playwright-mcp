FROM mcr.microsoft.com/playwright/mcp:latest

# Override entrypoint: bind to all interfaces so the reverse proxy can reach the service
ENTRYPOINT ["node", "/app/cli.js", "--headless", "--browser", "chromium", "--no-sandbox", "--port", "8931", "--host", "0.0.0.0", "--isolated"]
