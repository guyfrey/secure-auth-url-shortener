# Stage 1: Builder
FROM node:20-slim AS builder

# Install build tools for native deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    make \
    g++ \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY package*.json ./

# Install all deps (including dev for typescript)
RUN npm ci

# Install typescript globally → fixes permission/exec issues
RUN npm install -g typescript

COPY . .

# Now tsc is global and executable
RUN npm run build

# Stage 2: Production runner
FROM node:20-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    libc6 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/dist ./dist
COPY --from=builder /app/package*.json /app/

# Only prod deps now
RUN npm ci --omit=dev

# Prisma if needed
COPY --from=builder /app/prisma ./prisma  

EXPOSE 3000

CMD ["npm", "start"]