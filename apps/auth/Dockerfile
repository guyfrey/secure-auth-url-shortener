# Stage 1: Builder
FROM node:20-slim AS builder

# Install build tools + openssl (Prisma engines need it)
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    make \
    g++ \
    openssl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY package*.json ./

# Install all deps (dev included for prisma CLI)
RUN npm ci

# Copy Prisma schema + migrations first (important!)
COPY prisma ./prisma

# Generate Prisma Client → this creates node_modules/.prisma/client/
RUN npx prisma generate

# Now copy the rest of the source
COPY . .

# Build your TS app (creates dist/)
RUN npm run build

# Stage 2: Production runner
FROM node:20-slim

# Minimal runtime deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    libc6 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy built dist + prod deps only
COPY --from=builder /app/dist ./dist/
COPY --from=builder /app/package*.json ./
COPY --from=builder /app/prisma ./prisma/  

# Install production deps only
RUN npm ci --omit=dev

# Copy generated Prisma client from builder (critical!)
COPY --from=builder /app/node_modules/.prisma ./node_modules/.prisma/

EXPOSE 3000

# Optional: Run migrations on start (see below)
CMD ["npm", "start"]