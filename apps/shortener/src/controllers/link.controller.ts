import { Request, Response } from 'express';
import { string, z } from 'zod';
import { prisma } from '../services/prisma';
import { redis } from '../services/redis';
import { createUniqueShortCode } from '../utils/shortCode';
import logger from '../logger';  
import { AuthenticatedRequest } from '../middleware/auth';


export const shorten = async (req: AuthenticatedRequest, res: Response) => {
  try {
    const { url, customAlias } = z.object({
      url: z.string().url(),
      customAlias: z.string().optional(),
    }).parse(req.body);

    // Normalize URL (optional but good practice)
    const normalizedUrl = new URL(url).toString();

    let shortCode : string;


    if (customAlias) {
      const existing = await prisma.shortLink.findUnique({
        where: { shortCode: customAlias },
      });

      if (existing) {
        return res.status(404).json({ error: 'Custom alias already taken' });
      }
      shortCode = customAlias;
    } else {
      shortCode = await createUniqueShortCode();
    }

    // Create the link (userId null for now – anonymous)
    const newLink = await prisma.shortLink.create({
      data: {
        shortCode,
        originalUrl: normalizedUrl,
        userId: req.user?.userId || null,           // we'll link to auth later
      },
    });

    const baseUrl = process.env.RAILWAY_URL || 'http://localhost:5001';
    const shortUrl = `${baseUrl}/api/${shortCode}`;

    logger?.info(`New short link created: ${shortCode} → ${normalizedUrl}`);

    res.status(201).json({
      shortUrl,
      shortCode,
      originalUrl: normalizedUrl,
    });
  } catch (err) {
    if (err instanceof z.ZodError) {
      return res.status(400).json({ error: err.errors });
    }
    logger?.error(err);
    res.status(500).json({ error: 'Failed to create short link' });
  }
};

export const redirect = async (req: Request, res: Response) => {
    const { shortCode } = req.params;

    try {
        // First check Redis cache for fast redirect
        const cachedUrl = await redis.get(`link:${shortCode}`);
        if (cachedUrl) {
        await redis.incr(`clicks:${shortCode}`); // atomic increment
        return res.redirect(301, cachedUrl);
        }

        const link = await prisma.shortLink.findUnique({
            where: { shortCode },
        });

        if (!link) {
            return res.status(404).json({ error: 'Short link not found' });
        }
        // Cache the original URL for 24 hours (or longer)
        await redis.set(`link:${shortCode}`, link.originalUrl, { EX: 86400 });

        // Increment click count (use Redis for speed + eventual consistency with DB)
        await redis.incr(`clicks:${shortCode}`);

        // Optional: Track more detailed analytics in Redis sets/hashes (for later dashboard)
        const clickData = {
          timestamp: new Date().toISOString(),
          ip: req.ip || 'unknown',
          userAgent: req.headers['user-agent'] || 'unknown',
          referrer: req.get('referer') || 'direct',
          // You can add geoip lookup later (e.g., via free API or library)
        };

        await redis.rPush(`clicks:details:${shortCode}`, JSON.stringify(clickData)); // list for recent clicks
        await redis.lTrim(`clicks:details:${shortCode}`, 0, 999); // keep last 1000 clicks

        // Optional: Increment unique visitors (using HyperLogLog for approx uniqueness)
        await redis.pfAdd(`visitors:${shortCode}`, req.ip || 'anon');

        // Increment in DB only if Redis is primary source (or use background job later)
        await prisma.shortLink.update({
          where: { id: link.id },
          data: { clicks: { increment: 1 } },
        });

        await prisma.click.create({
            data: {
                linkId: link.id,
                ip: req.ip || null,
                userAgent: req.get('User-Agent') || null,
                referrer: req.headers.referer || null,  
            },
        });
        
        res.redirect(301, link.originalUrl);
    } catch (err) {
        logger?.error(err);
        res.status(500).json({ error: 'Failed to redirect',details:String(err) });
    }   
};

export const getStats = async (req: Request, res: Response) => {
  const { shortCode } = req.params;

  try {
    const link = await prisma.shortLink.findUnique({
      where: { shortCode },
      select: { clicks: true, originalUrl: true, createdAt: true },
    });

    if (!link) {
      return res.status(404).json({ error: 'Short link not found' });
    }

    // Get real-time clicks from Redis (more accurate than DB if not synced yet)
    const redisClicks = await redis.get(`clicks:${shortCode}`);
    const totalClicks = redisClicks ? parseInt(redisClicks, 10) : link.clicks;

    const uniqueVisitors = await redis.pfCount(`visitors:${shortCode}`);

    const recent = await redis.lRange(`clicks:details:${shortCode}`, 0, 4);
    const recentClicks = recent.map((json) => JSON.parse(json));

    res.json({
      shortCode,
      originalUrl: link.originalUrl,
      totalClicks,
      uniqueVisitorsApprox: uniqueVisitors,
      createdAt: link.createdAt,
      recentClicks, // for demo/debug
    });
  } catch (err) {
    logger?.error(err);
    res.status(500).json({ error: 'Failed to fetch stats', details: String(err) });
  }
};

export const getMyLinks = async (req: AuthenticatedRequest, res: Response) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  try {
    const links = await prisma.shortLink.findMany({
      where: { userId: req.user.userId },
      orderBy: { createdAt: 'desc' },
      select: { shortCode: true, originalUrl: true, clicks: true, createdAt: true },
    
    take:20,
    });
    res.json({ links });
  } catch (err) {
    logger?.error(err);
    res.status(500).json({ error: 'Failed to fetch links', details: String(err) });
  }
}