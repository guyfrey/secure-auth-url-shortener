# Build stage
FROM node:20-alpine AS builder

WORKDIR /app

RUN apk add --no-cache openssl libc6-compat

COPY package*.json ./
COPY apps/auth/package*.json ./apps/auth/
COPY packages/db/package*.json ./packages/db/

RUN npm ci

COPY . .

# Generate Prisma client from shared location
RUN npx prisma generate --schema=packages/db/prisma/schema.prisma

# Build only auth
RUN cd apps/auth && npm run build

# Production stage
FROM node:20-alpine

WORKDIR /app

RUN apk add --no-cache openssl libc6-compat

COPY --from=builder /app/package*.json ./
COPY --from=builder /app/apps/auth/package*.json ./apps/auth/
COPY --from=builder /app/packages/db/package*.json ./packages/db/

RUN npm ci --omit=dev

# Copy built auth files
COPY --from=builder /app/apps/auth/dist ./apps/auth/dist

# Copy shared Prisma client + engines
COPY --from=builder /app/packages/db/generated ./packages/db/generated
COPY --from=builder /app/node_modules/.prisma ./node_modules/.prisma



CMD ["npm", "start", "--prefix", "apps/auth"]