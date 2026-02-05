"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.createUniqueShortCode = createUniqueShortCode;
const nanoid_1 = require("nanoid");
const prisma_1 = require("../services/prisma"); // We'll create this next
const alphabet = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
const generateShortCode = (0, nanoid_1.customAlphabet)(alphabet, 7); // ~3.5 trillion combos
async function createUniqueShortCode() {
    let shortCode;
    let attempts = 0;
    const maxAttempts = 10; // safety net
    do {
        shortCode = generateShortCode();
        attempts++;
        const existing = await prisma_1.prisma.shortLink.findUnique({
            where: { shortCode },
        });
        if (!existing) {
            return shortCode;
        }
        if (attempts >= maxAttempts) {
            throw new Error('Failed to generate unique short code after max attempts');
        }
    } while (true);
}
//# sourceMappingURL=shortCode.js.map