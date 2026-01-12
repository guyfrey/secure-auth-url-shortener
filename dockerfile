# Use official Node.js LTS
FROM node:20-alpine

WORKDIR /app

# Copy package files first for caching
COPY package*.json ./
RUN npm ci   # or npm install

# Copy source
COPY . .

# If you build (e.g. tsc)
RUN npm run build

# Expose port (change if not 3000/8080)
EXPOSE 3000

# Start command - MUST listen on 0.0.0.0 and use $PORT if set
CMD ["npm", "start"]