# Build stage
FROM node:20-alpine AS builder

WORKDIR /app

# Install minimal deps for Prisma engines on Alpine
RUN apk add --no-cache openssl libc6-compat

# Copy package files first (caching)
COPY package*.json ./
COPY apps/*/package*.json ./
COPY packages/*/package*.json ./

# Install all deps
RUN npm ci

RUN find node_modules/.bin -type f -exec chmod +x {} \; || true
RUN find node_modules -name "*.js" -exec chmod +x {} \; || true
RUN chmod -R +x node_modules/.prisma || true

# Copy source code
COPY . .

# Explicitly fix Prisma binary permissions (critical on Alpine)
RUN chmod +x ./node_modules/prisma/build/index.js || true
RUN chmod +x ./node_modules/.bin/prisma || true
RUN chmod -R +x ./node_modules/.prisma || true

# Generate Prisma client from shared schema
RUN cd packages/db && npx prisma generate --schema=prisma/schema.prisma

RUN ls -la node_modules/.bin/tsc && ls -la node_modules/typescript/bin/tsc
# Build your apps
RUN npm run build --workspace=apps/auth || echo "Auth build skipped or failed"
RUN npm run build --workspace=apps/shortener || echo "Shortener build skipped or failed"

# Production stage
FROM node:20-alpine

WORKDIR /app

RUN apk add --no-cache openssl libc6-compat

# Copy package files
COPY --from=builder /app/package*.json ./
COPY --from=builder /app/apps/*/package*.json ./
COPY --from=builder /app/packages/*/package*.json ./

# Install only production deps
RUN npm ci --omit=dev

# Fix permissions again in production (belt and suspenders)
RUN find node_modules/.bin -type f -exec chmod +x {} \; || true
RUN chmod -R +x node_modules/.prisma || true

# Copy built files
COPY --from=builder /app/apps/auth/dist ./apps/auth/dist 
COPY --from=builder /app/apps/shortener/dist ./apps/shortener/dist

# Copy Prisma generated client + engines (this is the key part)
COPY --from=builder /app/packages/db/generated ./packages/db/generated
COPY --from=builder /app/node_modules/.prisma ./node_modules/.prisma

# Copy schema (optional)
COPY --from=builder /app/packages/db/prisma ./packages/db/prisma



ENV NODE_ENV=production
ENV PORT=8080

# Use env var to select app
CMD ["sh", "-c", "npm run start --workspace=apps/$APP_TO_RUN"]