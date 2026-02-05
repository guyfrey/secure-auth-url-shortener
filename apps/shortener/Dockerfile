# Build stage
FROM node:20-slim AS builder
WORKDIR /app

# Install OpenSSL to silence detection warning (optional but recommended)
RUN apt-get update -y && apt-get install -y openssl ca-certificates && rm -rf /var/lib/apt/lists/*

COPY package*.json ./
RUN npm ci

COPY prisma ./prisma
RUN npx prisma generate


COPY . .


# Production stage
FROM node:20-slim
WORKDIR /app

# Install OpenSSL here too
RUN apt-get update -y && apt-get install -y openssl ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/package*.json ./
RUN npm ci --only=production

# Copy generated Prisma client & engines (required at runtime)
COPY --from=builder /app/node_modules/.prisma ./node_modules/.prisma
COPY --from=builder /app/node_modules/@prisma ./node_modules/@prisma

COPY --from=builder /app/dist ./dist
RUN npx prisma generate

CMD ["npm", "start"]