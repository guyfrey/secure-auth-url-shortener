"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.prisma = void 0;
const client_1 = require("@prisma/client");
const globalForPrisma = global;
exports.prisma = globalForPrisma.prismaShort ||
    new client_1.PrismaClient({
        log: ['query'],
    });
if (process.env.NODE_ENV !== 'production')
    globalForPrisma.prismaShort = exports.prisma;
//# sourceMappingURL=prisma.js.map