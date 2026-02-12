FROM node:20-alpine AS builder

WORKDIR /app

RUN apk add --no-cache openssl libc6-compat

COPY package*.json ./
COPY apps/*/package*.json ./
COPY packages/*/package*.json ./

RUN npm ci

COPY . .

# Fix permissions on Prisma binaries (Alpine quirk)
RUN chmod -R +x node_modules/.bin/prisma node_modules/prisma/build node_modules/.prisma || true

# Generate Prisma client
RUN cd packages/db \
  && ../node_modules/.bin/prisma generate --schema=prisma/schema.prisma

# Build apps
RUN npm run build --workspace=apps/auth || echo "Auth build skipped"
RUN npm run build --workspace=apps/shortener || echo "Shortener build skipped"

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

# Copy built code
COPY --from=builder /app/apps/auth/dist ./apps/auth/dist
COPY --from=builder /app/apps/shortener/dist ./apps/shortener/dist

# Copy Prisma generated client + engines (very important!)
COPY --from=builder /app/packages/db/generated ./packages/db/generated
COPY --from=builder /app/node_modules/.prisma ./node_modules/.prisma

# Copy schema (optional but safe)
COPY --from=builder /app/packages/db/prisma ./packages/db/prisma
COPY --from=builder /app/packages/db/generated ./packages/db/generated

# Permissions fix again in prod stage
RUN chmod -R +x node_modules/.prisma || true

ENV NODE_ENV=production
ENV PORT=8080

# Use env var to choose which app to run
CMD ["sh", "-c", "npm run start --workspace=apps/$APP_TO_RUN"]