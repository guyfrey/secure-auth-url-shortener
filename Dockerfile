# Build stage
FROM node:20 AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y openssl libssl-dev libpq-dev && rm -rf /var/lib/apt/lists/*

COPY package*.json ./
COPY apps/*/package*.json ./
COPY packages/*/package*.json ./

RUN npm ci

# CRITICAL: Fix Prisma executable permissions (Alpine/Debian quirk)
RUN chmod 755 node_modules/.bin/prisma || true
RUN chmod 755 node_modules/prisma/build/index.js || true
RUN chmod -R 755 node_modules/.prisma || true
RUN chmod -R 755 node_modules/prisma || true

COPY . .

# Generate Prisma client (full path, no cd)
RUN npx prisma generate --schema=packages/db/prisma/schema.prisma

# Build apps
RUN npm run build --workspace=apps/auth || echo "Auth build skipped or failed"
RUN npm run build --workspace=apps/shortener || echo "Shortener build failed or skipped"

# Production stage
FROM node:20-slim

WORKDIR /app

RUN apt-get update && apt-get install -y openssl && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/package*.json ./
COPY --from=builder /app/apps/*/package*.json ./
COPY --from=builder /app/packages/*/package*.json ./

RUN npm ci --omit=dev

# Fix permissions in production
RUN find node_modules/.bin -type f -exec chmod +x {} \; || true
RUN chmod -R +x node_modules/prisma node_modules/.prisma || true

COPY --from=builder /app/apps/auth/dist ./apps/auth/dist
COPY --from=builder /app/apps/shortener/dist ./apps/shortener/dist

COPY --from=builder /app/packages/db/generated ./packages/db/generated
COPY --from=builder /app/node_modules/.prisma ./node_modules/.prisma
COPY --from=builder /app/packages/db/prisma ./packages/db/prisma

ENV NODE_ENV=production
ENV PORT=8080

CMD ["sh", "-c", "npm run start --workspace=apps/$APP_TO_RUN"]