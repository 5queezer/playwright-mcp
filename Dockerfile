FROM mcr.microsoft.com/playwright/mcp:latest

USER root
COPY auth-proxy.mjs /proxy/auth-proxy.mjs
COPY start.sh /start.sh
RUN chmod +x /start.sh
USER node

EXPOSE 3000
ENTRYPOINT ["/start.sh"]
