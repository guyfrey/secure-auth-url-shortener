# Stage 1: Build
FROM node:20-alpine AS builder

WORKDIR /app

# Install dependencies (including dev for TypeScript)
COPY package*.json ./
RUN npm install --include=dev

# Copy source code
COPY . .

# Build TypeScript
RUN npm run build

# Stage 2: Run
FROM node:20-alpine

WORKDIR /app

# Install only production dependencies
COPY package*.json ./
RUN npm install --omit=dev

# Copy compiled code from builder
COPY --from=builder /app/dist ./dist

# Expose the port your app uses
EXPOSE 5000

# Start the app
CMD ["node", "dist/server.js"]