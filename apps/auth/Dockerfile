# Stage 1: Builder
FROM node:20-alpine AS builder
RUN apk add --no-cache python3 make g++

WORKDIR /app

COPY package*.json ./
RUN npm ci --include=dev

COPY . .
RUN npm run build

# Stage 2: Runner
FROM node:20-alpine
RUN apk add --no-cache libc6-compat

WORKDIR /app

COPY package*.json ./
RUN npm ci --omit=dev

COPY --from=builder /app/dist ./dist

EXPOSE 5000
CMD ["node", "dist/server.js"]

# Stage 2: Production runner (slim image)
FROM node:20-alpine AS runner

# Add minimal deps if needed (e.g. for Prisma)
RUN apk add --no-cache libc6-compat

WORKDIR /app

# Copy only what's needed from builder
COPY --from=builder /app /app

# Expose port (Railway uses $PORT env var)
EXPOSE 3000

# Start command – use process.env.PORT for Railway compatibility
CMD ["npm", "start"]