# Build stage
FROM node:20-alpine AS builder
WORKDIR /app

# Copy package files first (for caching)
COPY package*.json ./

# Copy prisma schema BEFORE install/generate
COPY prisma ./prisma

# Now install → postinstall will see the schema and succeed
RUN npm ci

# Copy the rest of the code
COPY . .

# Optional: force generate again if needed (but postinstall should handle it)
RUN npx prisma generate

# Build TS
RUN npm run build

# Production stage
FROM node:20-alpine
WORKDIR /app

# Copy package files
COPY --from=builder /app/package*.json ./

# Install only prod deps
RUN npm ci --only=production

# Copy generated Prisma client files (critical!)
COPY --from=builder /app/node_modules/.prisma ./node_modules/.prisma
COPY --from=builder /app/node_modules/@prisma ./node_modules/@prisma

# Copy compiled app
COPY --from=builder /app/dist ./dist

# Copy prisma schema if migrations needed later (optional)
COPY --from=builder /app/prisma ./prisma

EXPOSE 5001
CMD ["npm", "start"]