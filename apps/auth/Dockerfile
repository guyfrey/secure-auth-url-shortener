# Stage 1: Builder (install deps + build if needed)
FROM node:20-alpine AS builder

# Install dependencies needed for native modules (bcrypt, etc.)
RUN apk add --no-cache python3 make g++

WORKDIR /app

# Copy package files first → cache this layer
COPY package*.json ./

# Use npm ci for exact lockfile install (faster & reproducible)
# --omit=dev skips dev deps in prod, but keep for build if you have build scripts
RUN npm ci

# Copy source code
COPY . .

# If you have a build step (e.g. tsc for TS)
# RUN npm run build

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