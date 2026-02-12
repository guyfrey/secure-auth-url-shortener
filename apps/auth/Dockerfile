FROM node:20-alpine AS builder
WORKDIR /app
RUN apk add --no-cache openssl libc6-compat
COPY package*.json ./
COPY ../../packages/db/package*.json ../../packages/db/
RUN npm ci
COPY . .
COPY ../../packages/db ../../packages/db
RUN npx prisma generate --schema=../../packages/db/prisma/schema.prisma
RUN npm run build
FROM node:20-alpine
WORKDIR /app
RUN apk add --no-cache openssl libc6-compat
COPY --from=builder /app/package*.json ./
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/packages/db/generated ./packages/db/generated
COPY --from=builder /app/node_modules/.prisma ./node_modules/.prisma

CMD ["npm", "start"]