# Root Dockerfile (place at project root)

FROM node:20-alpine AS builder

WORKDIR /app

RUN apk add --no-cache openssl libc6-compat

# Copy lockfile & package files first
COPY package*.json ./
COPY apps/*/package*.json ./
COPY packages/*/package*.json ./

RUN npm ci

COPY . .

# Generate Prisma client once from shared schema
RUN cd packages/db && npx prisma generate --schema=prisma/schema.prisma

# Build both apps
RUN npm run build --workspace=apps/auth
RUN npm run build --workspace=apps/shortener

FROM node:20-alpine

WORKDIR /app

RUN apk add --no-cache openssl libc6-compat

COPY --from=builder /app/package*.json ./
COPY --from=builder /app/apps/*/package*.json ./
COPY --from=builder /app/packages/*/package*.json ./

RUN npm ci --omit=dev

# Copy built files
COPY --from=builder /app/apps/auth/dist ./apps/auth/dist
COPY --from=builder /app/apps/shortener/dist ./apps/shortener/dist

# Copy Prisma generated client & engines (critical!)
COPY --from=builder /app/packages/db/generated ./packages/db/generated
COPY --from=builder /app/node_modules/.prisma ./node_modules/.prisma

# Copy schema if needed at runtime
COPY --from=builder /app/packages/db/prisma ./packages/db/prisma

ENV NODE_ENV=production

# Railway will override PORT to 8080
ENV PORT=8080

# Choose app via env var
CMD ["sh", "-c", "npm run start --workspace=apps/$APP_TO_RUN"]