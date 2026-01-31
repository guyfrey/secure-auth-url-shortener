import { PrismaClient } from '@prisma/client';

const globalForPrisma = global as unknown as { prismaShort: PrismaClient };

export const prisma =
  globalForPrisma.prismaShort ||
  new PrismaClient({
    log: ['query'],
  });

if (process.env.NODE_ENV !== 'production') globalForPrisma.prismaShort = prisma;