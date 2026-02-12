import {PrismaClient} from '@guyfrey_auth_short/db';

const globalForPrisma = global as unknown as { prisma: PrismaClient };

export const prisma =
  globalForPrisma.prisma ||
  new PrismaClient({
    log: ['query'], // optional
  });

if (process.env.NODE_ENV !== 'production') globalForPrisma.prisma = prisma;