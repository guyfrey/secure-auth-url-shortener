# Build stage
FROM node:20-slim AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y openssl libssl-dev libpq-dev && rm -rf /var/lib/apt/lists/*

COPY package*.json ./
COPY apps/*/package*.json ./
COPY packages/*/package*.json ./

RUN npm ci

COPY . .

# After COPY . . and npm ci

# Fix root-level binaries
RUN chmod -R 755 node_modules/.bin || true
RUN chmod -R 755 node_modules/prisma node_modules/.prisma node_modules/typescript || true

# Fix workspace-specific binaries (auth & shortener)
RUN chmod -R 755 apps/auth/node_modules/.bin || true
RUN chmod -R 755 apps/shortener/node_modules/.bin || true
RUN chmod -R 755 apps/auth/node_modules/typescript apps/shortener/node_modules/typescript || true

# Debug: verify permissions
RUN ls -la node_modules/.bin/prisma || echo "prisma binary missing"

# Generate Prisma client
RUN ./node_modules/.bin/prisma generate --schema=packages/db/prisma/schema.prisma


RUN echo "Running auth build" && npm run build --workspace=apps/auth
RUN echo "Running shortener build" && npm run build --workspace=apps/shortener
# Build apps
RUN npm run build --workspace=apps/auth 
RUN npm run build --workspace=apps/shortener 

# Production stage
FROM node:20-slim

WORKDIR /app

RUN apt-get update && apt-get install -y openssl && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/package*.json ./
COPY --from=builder /app/apps/*/package*.json ./
COPY --from=builder /app/packages/*/package*.json ./

RUN npm ci --omit=dev

# Fix permissions in production stage too
RUN chmod 755 node_modules/.bin/prisma || true
RUN chmod 755 node_modules/prisma/build/index.js || true
RUN chmod -R 755 node_modules/.prisma || true
RUN chmod -R 755 node_modules/prisma || true
RUN chmod -R 755 node_modules/typescript/bin || true

# Copy built files
COPY --from=builder /app/apps/auth/dist ./apps/auth/dist 
COPY --from=builder /app/apps/shortener/dist ./apps/shortener/dist 

COPY --from=builder /app/packages/db/generated ./packages/db/generated
COPY --from=builder /app/node_modules/.prisma ./node_modules/.prisma
COPY --from=builder /app/packages/db/prisma ./packages/db/prisma

ENV NODE_ENV=production
ENV PORT=8080

CMD ["npm", "run", "start-$APP_TO_RUN"]