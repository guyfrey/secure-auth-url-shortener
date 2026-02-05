"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.getStats = exports.redirect = exports.shorten = void 0;
const zod_1 = require("zod");
const prisma_1 = require("../services/prisma");
const redis_1 = require("../services/redis");
const shortCode_1 = require("../utils/shortCode");
const logger_1 = __importDefault(require("../logger"));
const shortenSchema = zod_1.z.object({
    url: zod_1.z.string().url({ message: 'Invalid URL ' }),
});
const shorten = async (req, res) => {
    try {
        const { url } = shortenSchema.parse(req.body);
        // Normalize URL (optional but good practice)
        const normalizedUrl = new URL(url).toString();
        // Check if this exact URL already exists (to avoid duplicates)
        const existing = await prisma_1.prisma.shortLink.findFirst({
            where: { originalUrl: normalizedUrl },
        });
        if (existing) {
            const baseUrl = process.env.BASE_URL || 'http://localhost:5001';
            const shortUrl = `${baseUrl}/api/${existing.shortCode}`;
            return res.json({
                shortUrl,
                originalUrl: normalizedUrl,
                shortCode: existing.shortCode,
                message: 'Existing link reused',
            });
        }
        // Generate unique short code
        const shortCode = await (0, shortCode_1.createUniqueShortCode)();
        // Create the link (userId null for now – anonymous)
        const newLink = await prisma_1.prisma.shortLink.create({
            data: {
                shortCode,
                originalUrl: normalizedUrl,
                userId: null, // we'll link to auth later
                expiresAt: null, // add later if you want expiration
            },
        });
        const baseUrl = process.env.BASE_URL || 'http://localhost:5001';
        const shortUrl = `${baseUrl}/api/${shortCode}`;
        logger_1.default?.info(`New short link created: ${shortCode} → ${normalizedUrl}`);
        res.status(201).json({
            shortUrl,
            originalUrl: normalizedUrl,
            shortCode: newLink.shortCode,
        });
    }
    catch (err) {
        if (err instanceof zod_1.z.ZodError) {
            return res.status(400).json({ error: err.errors });
        }
        logger_1.default?.error(err);
        res.status(500).json({ error: 'Failed to create short link' });
    }
};
exports.shorten = shorten;
const redirect = async (req, res) => {
    const { shortCode } = req.params;
    try {
        // First check Redis cache for fast redirect
        const cachedUrl = await redis_1.redis.get(`link:${shortCode}`);
        if (cachedUrl) {
            await redis_1.redis.incr(`clicks:${shortCode}`); // atomic increment
            return res.redirect(301, cachedUrl);
        }
        const link = await prisma_1.prisma.shortLink.findUnique({
            where: { shortCode },
        });
        if (!link) {
            return res.status(404).json({ error: 'Short link not found' });
        }
        // Cache the original URL for 24 hours (or longer)
        await redis_1.redis.set(`link:${shortCode}`, link.originalUrl, { EX: 86400 });
        // Increment click count (use Redis for speed + eventual consistency with DB)
        await redis_1.redis.incr(`clicks:${shortCode}`);
        // Optional: Track more detailed analytics in Redis sets/hashes (for later dashboard)
        const clickData = {
            timestamp: new Date().toISOString(),
            ip: req.ip || 'unknown',
            userAgent: req.headers['user-agent'] || 'unknown',
            referrer: req.get('referer') || 'direct',
            // You can add geoip lookup later (e.g., via free API or library)
        };
        await redis_1.redis.rPush(`clicks:details:${shortCode}`, JSON.stringify(clickData)); // list for recent clicks
        await redis_1.redis.lTrim(`clicks:details:${shortCode}`, 0, 999); // keep last 1000 clicks
        // Optional: Increment unique visitors (using HyperLogLog for approx uniqueness)
        await redis_1.redis.pfAdd(`visitors:${shortCode}`, req.ip || 'anon');
        // Increment in DB only if Redis is primary source (or use background job later)
        await prisma_1.prisma.shortLink.update({
            where: { id: link.id },
            data: { clicks: { increment: 1 } },
        });
        await prisma_1.prisma.click.create({
            data: {
                linkId: link.id,
                ip: req.ip || null,
                userAgent: req.get('User-Agent') || null,
                referrer: req.headers.referer || null,
            },
        });
        res.redirect(301, link.originalUrl);
    }
    catch (err) {
        logger_1.default?.error(err);
        res.status(500).json({ error: 'Failed to redirect', details: String(err) });
    }
};
exports.redirect = redirect;
const getStats = async (req, res) => {
    const { shortCode } = req.params;
    try {
        const link = await prisma_1.prisma.shortLink.findUnique({
            where: { shortCode },
            select: { clicks: true, originalUrl: true, createdAt: true },
        });
        if (!link) {
            return res.status(404).json({ error: 'Short link not found' });
        }
        // Get real-time clicks from Redis (more accurate than DB if not synced yet)
        const redisClicks = await redis_1.redis.get(`clicks:${shortCode}`);
        const totalClicks = redisClicks ? parseInt(redisClicks, 10) : link.clicks;
        const uniqueVisitors = await redis_1.redis.pfCount(`visitors:${shortCode}`);
        const recent = await redis_1.redis.lRange(`clicks:details:${shortCode}`, 0, 4);
        const recentClicks = recent.map((json) => JSON.parse(json));
        res.json({
            shortCode,
            originalUrl: link.originalUrl,
            totalClicks,
            uniqueVisitorsApprox: uniqueVisitors,
            createdAt: link.createdAt,
            recentClicks, // for demo/debug
        });
    }
    catch (err) {
        logger_1.default?.error(err);
        res.status(500).json({ error: 'Failed to fetch stats', details: String(err) });
    }
};
exports.getStats = getStats;
//# sourceMappingURL=link.controller.js.map