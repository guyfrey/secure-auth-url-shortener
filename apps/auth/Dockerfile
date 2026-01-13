# Stage 1: Builder
FROM node:20-slim AS builder

# Install build essentials for native modules (bcrypt, etc.)
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    make \
    g++ \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY package*.json ./
RUN npm ci

COPY . .

# Build TS → should now work without permission issues
RUN npm run build

# Stage 2: Production runner
FROM node:20-slim

# Minimal runtime deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    libc6 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy built artifacts + prod deps only
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/package*.json ./
RUN npm ci --omit=dev

# If using Prisma (migrate on start)
COPY --from=builder /app/prisma ./prisma

EXPOSE 3000

# Use Railway's $PORT if set
CMD ["npm", "start"]