FROM mcr.microsoft.com/playwright/mcp:latest

# Override: bind to all interfaces so Traefik can reach the service
CMD ["--port", "8931", "--host", "0.0.0.0", "--isolated"]
