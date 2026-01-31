import { Request, Response } from 'express';
import { string, z } from 'zod';
import { prisma } from '../services/prisma';
import { redis } from '../services/redis';
import { createUniqueShortCode } from '../utils/shortCode';
import logger from '../logger';  

const shortenSchema = z.object({
    url: z.string().url({ message: 'Invalid URL ' }),
});


export const shorten = async (req: Request, res: Response) => {
  try {
    const { url } = shortenSchema.parse(req.body);

    // Normalize URL (optional but good practice)
    const normalizedUrl = new URL(url).toString();

    // Check if this exact URL already exists (to avoid duplicates)
    const existing = await prisma.shortLink.findFirst({
      where: { originalUrl: normalizedUrl },
    });

    if (existing) {
      const shortUrl = `${process.env.BASE_URL || 'http://localhost:5001'}/${existing.shortCode}`;
      return res.json({
        shortUrl,
        originalUrl: normalizedUrl,
        shortCode: existing.shortCode,
        message: 'Existing link reused',
      });
    }

    // Generate unique short code
    const shortCode = await createUniqueShortCode();

    // Create the link (userId null for now – anonymous)
    const newLink = await prisma.shortLink.create({
      data: {
        shortCode,
        originalUrl: normalizedUrl,
        userId: null,           // we'll link to auth later
        expiresAt: null,        // add later if you want expiration
      },
    });

    const shortUrl = `${process.env.BASE_URL || 'http://localhost:5001'}/${shortCode}`;

    logger?.info(`New short link created: ${shortCode} → ${normalizedUrl}`);

    res.status(201).json({
      shortUrl,
      originalUrl: normalizedUrl,
      shortCode: newLink.shortCode,
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

    res.json({
      shortCode,
      originalUrl: link.originalUrl,
      totalClicks,
      createdAt: link.createdAt,
    });
  } catch (err) {
    logger?.error(err);
    res.status(500).json({ error: 'Failed to fetch stats' });
  }
};


