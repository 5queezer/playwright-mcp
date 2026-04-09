FROM mcr.microsoft.com/playwright/mcp:latest

# Wrapper script — Coolify may override ENTRYPOINT/CMD, but not the script contents
USER root
RUN printf '#!/bin/sh\nexec node /app/cli.js --headless --browser chromium --no-sandbox --port 8931 --host 0.0.0.0 --isolated "$@"\n' > /start.sh && chmod +x /start.sh
USER node

EXPOSE 8931
ENTRYPOINT ["/start.sh"]
