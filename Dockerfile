# Build stage
FROM node:20-slim AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y openssl libssl-dev libpq-dev && rm -rf /var/lib/apt/lists/*

COPY package*.json ./
COPY apps/*/package*.json ./
COPY packages/*/package*.json ./

RUN npm ci

# Fix ALL binary permissions (this solves prisma & tsc permission denied)
RUN chmod 755 node_modules/.bin/* || true
RUN find node_modules -type f -name "*.js" -exec chmod 755 {} \; || true
RUN chmod -R 755 node_modules/prisma node_modules/.prisma node_modules/typescript/bin || true

COPY . .

# Generate Prisma client once (shared)
RUN npx prisma generate --schema=packages/db/prisma/schema.prisma

# Build both apps (both will have dist folders)
RUN npm run build --workspace=apps/auth || echo "Auth build skipped"
RUN npm run build --workspace=apps/shortener || echo "Shortener build skipped"

# Production stage
FROM node:20-slim

WORKDIR /app

RUN apt-get update && apt-get install -y openssl && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/package*.json ./
COPY --from=builder /app/apps/*/package*.json ./
COPY --from=builder /app/packages/*/package*.json ./

RUN npm ci --omit=dev

# Fix permissions in production stage too
RUN chmod 755 node_modules/.bin/* || true
RUN chmod -R 755 node_modules/prisma node_modules/.prisma || true

# Copy built files
COPY --from=builder /app/apps/auth/dist ./apps/auth/dist 
COPY --from=builder /app/apps/shortener/dist ./apps/shortener/dist 
# Copy Prisma generated client + engines
COPY --from=builder /app/packages/db/generated ./packages/db/generated
COPY --from=builder /app/node_modules/.prisma ./node_modules/.prisma

COPY --from=builder /app/packages/db/prisma ./packages/db/prisma

ENV NODE_ENV=production
ENV PORT=8080

# Choose which service to start
CMD ["sh", "-c", "npm run start --workspace=apps/$APP_TO_RUN"]