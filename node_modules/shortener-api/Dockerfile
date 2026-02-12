# Build stage
FROM node:20-alpine AS builder

WORKDIR /app

RUN apk add --no-cache openssl libc6-compat

COPY package*.json ./
COPY apps/shortener/package*.json ./apps/shortener/
COPY packages/db/package*.json ./packages/db/

RUN npm ci

COPY . .

# Generate Prisma client from shared location
RUN npx prisma generate --schema=packages/db/prisma/schema.prisma

# Build only shortener
RUN cd apps/shortener && npm run build

# Production stage
FROM node:20-alpine

WORKDIR /app

RUN apk add --no-cache openssl libc6-compat

COPY --from=builder /app/package*.json ./
COPY --from=builder /app/apps/shortener/package*.json ./apps/shortener/
COPY --from=builder /app/packages/db/package*.json ./packages/db/

RUN npm ci --omit=dev

# Copy built shortener files
COPY --from=builder /app/apps/shortener/dist ./apps/shortener/dist

# Copy shared Prisma client + engines
COPY --from=builder /app/packages/db/generated ./packages/db/generated
COPY --from=builder /app/node_modules/.prisma ./node_modules/.prisma


CMD ["npm", "start", "--prefix", "apps/shortener"]