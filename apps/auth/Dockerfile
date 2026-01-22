# Stage 1: Builder
FROM node:20-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 make g++ openssl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY package*.json ./

RUN npm ci

# Fix permissions on ALL npm bin scripts (critical for tsc/npx wrappers)
RUN chmod +x ./node_modules/.bin/* || true

# Optional: If still issues, make tsc globally available too
RUN npm install -g typescript

# Copy Prisma schema early for generate
COPY prisma ./prisma

# Generate Prisma Client (now with fixed perms)
RUN npx prisma generate

COPY . .

# Build – use plain tsc to avoid npx wrapper issues
RUN tsc   # ← Change from npm run build if needed, or keep npm run build after updating scripts below

COPY --from=builder /app/src ./src

# Stage 2: Production runner
FROM node:20-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    libc6 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/dist ./dist
COPY --from=builder /app/package*.json ./
COPY --from=builder /app/prisma ./prisma
COPY --from=builder /app/node_modules/.prisma ./node_modules/.prisma  
RUN npm ci --omit=dev

EXPOSE 3000

CMD ["npm", "start"]