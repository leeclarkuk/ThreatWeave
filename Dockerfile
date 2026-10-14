# syntax=docker/dockerfile:1
# Local, single-user container. No cloud account needed. Not a hardened multi-tenant service.
FROM node:22.22.0-slim AS build
WORKDIR /app
COPY package.json package-lock.json tsconfig.base.json ./
COPY packages/core/package.json packages/core/
COPY packages/ai/package.json packages/ai/
COPY packages/server/package.json packages/server/
COPY packages/cli/package.json packages/cli/
COPY packages/web/package.json packages/web/
RUN npm ci
COPY packages packages
RUN npm run build && npm prune --omit=dev

FROM node:22.22.0-slim
ENV NODE_ENV=production THREATWEAVE_DATA=/data THREATWEAVE_EXAMPLES=/app/examples THREATWEAVE_WEB_DIR=/app/packages/web/dist THREATWEAVE_BIND_ACK=1
WORKDIR /app
COPY --from=build /app/node_modules node_modules
COPY --from=build /app/package.json ./
COPY --from=build /app/packages/core/dist packages/core/dist
COPY --from=build /app/packages/core/package.json packages/core/
COPY --from=build /app/packages/ai/dist packages/ai/dist
COPY --from=build /app/packages/ai/package.json packages/ai/
COPY --from=build /app/packages/server/dist packages/server/dist
COPY --from=build /app/packages/server/package.json packages/server/
COPY --from=build /app/packages/cli/dist packages/cli/dist
COPY --from=build /app/packages/cli/package.json packages/cli/
COPY --from=build /app/packages/web/dist packages/web/dist
COPY examples examples
COPY LICENSE NOTICE ./
RUN mkdir -p /data && chown node:node /data
USER node
VOLUME ["/data"]
EXPOSE 4317
HEALTHCHECK --interval=30s --timeout=3s CMD node -e "fetch('http://127.0.0.1:4317/api/health').then(r=>process.exit(r.ok?0:1),()=>process.exit(1))"
CMD ["node", "packages/cli/dist/bin.js", "serve", "--host", "0.0.0.0", "--port", "4317"]
