# Secure Auth API (Node.js + TypeScript)

Production-ready authentication service with:
- JWT + Refresh Tokens (HTTP-only cookies)
- Email verification & password reset (Resend)
- Rate limiting & brute-force protection
- Role-based access (RBAC)
- Swagger docs at /api-docs
- Jest tests
- Pino structured logging
- Deployed on Railway

## Tech Stack
- Node.js 20 + TypeScript
- Express
- Prisma + PostgreSQL
- Redis
- JWT, bcrypt, Zod, Pino, Helmet, Swagger

## Setup
1. `docker compose up -d`
2. `cd apps/auth && npx prisma migrate dev`
3. `npm run dev`

Live: https://secure-auth-url-shortener-production.up.railway.app/api-docs/#/

## Security Features
- Argon2/bcrypt hashing
- Short-lived access tokens
- Refresh token revocation via Redis
- Helmet headers
- Rate limiting on auth routes
