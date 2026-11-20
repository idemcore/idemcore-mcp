# Runs the Idemcore MCP server (stdio) built from this repository's source.
# No API key is needed to start it or to list its tools; IDEMCORE_API_KEY is
# read at run time only by the chat, get-receipt and export-audit tools.

FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json tsconfig.json ./
RUN npm ci --ignore-scripts
COPY src ./src
RUN npm run build

FROM node:22-alpine
WORKDIR /app
ENV NODE_ENV=production
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts && npm cache clean --force
COPY --from=build /app/dist ./dist
USER node
CMD ["node", "dist/index.js"]
