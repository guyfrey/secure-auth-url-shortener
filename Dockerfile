# Build stage
FROM node:20 AS builder

WORKDIR /app

# Install runtime deps for Prisma
RUN apt-get update && apt-get install -y openssl libssl-dev libpq-dev && rm -rf /var/lib/apt/lists/*

# Copy package files (caching)
COPY package*.json ./
COPY apps/*/package*.json ./
COPY packages/*/package*.json ./

# Install all deps
RUN npm ci

# Copy source code
COPY . .

# Fix ALL Prisma & TypeScript binary permissions (after full copy/install)
RUN find node_modules/.bin -type f -name "prisma" -exec chmod +x {} \; || true
RUN find node_modules -type f -name "*.js" -exec chmod +x {} \; || true
RUN chmod -R +x node_modules/prisma node_modules/.prisma node_modules/typescript/bin || true

# Generate Prisma client
RUN cd packages/db && npx prisma generate --schema=prisma/schema.prisma

# Build each workspace
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

# Fix permissions in production stage too
RUN find node_modules/.bin -type f -name "prisma" -exec chmod +x {} \; || true
RUN chmod -R +x node_modules/prisma node_modules/.prisma node_modules/typescript/bin || true

# Copy built files
COPY --from=builder /app/apps/auth/dist ./apps/auth/dist
COPY --from=builder /app/apps/shortener/dist ./apps/shortener/dist

# Copy Prisma generated client + engines
COPY --from=builder /app/packages/db/generated ./packages/db/generated
COPY --from=builder /app/node_modules/.prisma ./node_modules/.prisma

# Copy schema (optional but safe)
COPY --from=builder /app/packages/db/prisma ./packages/db/prisma

ENV NODE_ENV=production
ENV PORT=8080

CMD ["sh", "-c", "npm run start --workspace=apps/$APP_TO_RUN"]