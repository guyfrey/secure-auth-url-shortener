# Build stage
FROM node:20-slim AS builder
WORKDIR /app

# Copy package files first (caching)
COPY package*.json ./

RUN npm ci

# Copy prisma schema & code
COPY prisma ./prisma
COPY . .

# Generate Prisma client
RUN npx prisma generate

# Build TS
RUN npm run build

# Production stage
FROM node:20-slim
WORKDIR /app

COPY --from=builder /app/package*.json ./
RUN npm ci --only=production

# Copy generated Prisma files (required at runtime)
COPY --from=builder /app/node_modules/.prisma ./node_modules/.prisma
COPY --from=builder /app/node_modules/@prisma ./node_modules/@prisma

# Copy compiled app
COPY --from=builder /app/dist ./dist

EXPOSE 5001
CMD ["npm", "start"]