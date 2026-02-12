# Build stage
FROM node:20-slim AS builder
WORKDIR /app
RUN apk add --no-cache openssl libc6-compat
# Install OpenSSL to silence detection warning (optional but recommended)
RUN apt-get update -y && apt-get install -y openssl ca-certificates && rm -rf /var/lib/apt/lists/*

COPY package*.json ./
RUN npm ci




COPY . .
RUN npm run build

# Production stage
FROM node:20-slim
WORKDIR /app

# Install OpenSSL here too
RUN apt-get update -y && apt-get install -y openssl ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/package*.json ./
RUN npm ci --only=production

# Copy generated Prisma client & engines (required at runtime)

COPY --from=builder /app/dist ./dist


CMD ["npm", "start"]