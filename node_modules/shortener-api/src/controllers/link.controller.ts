import { Request, Response } from 'express';
import { string, z } from 'zod';
import { prisma } from '../lib/db';
import { redis } from '../services/redis';
import { createUniqueShortCode } from '../utils/shortCode';
import logger from '../logger';  
import { AuthenticatedRequest } from '../middleware/auth';


export const shorten = async (req: AuthenticatedRequest, res: Response) => {
  try {
    const { url, customAlias,expiresInDays } = z.object({
      url: z.string().url(),
      customAlias: z.string().optional(),
      expiresInDays: z.number().int().positive().min(1).max(365).optional(), // for future use
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

    let expiresAt: Date | null = null;
    if (expiresInDays) {
      expiresAt = new Date(Date.now() + expiresInDays * 24 * 60 * 60 * 1000);
    }

    // Create the link (userId null for now – anonymous)
    const newLink = await prisma.shortLink.create({
      data: {
        shortCode,
        expiresAt,
        originalUrl: normalizedUrl,
        userId: (req as any).user?.userId || null,           // we'll link to auth later
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
        const link = await prisma.shortLink.findUnique({//check short code in DB first 
            where: { shortCode },
        });

        if (!link) {
            return res.status(404).json({ error: 'Short link not found' });
        }

        if (link.expiresAt && new Date(link.expiresAt) < new Date()) {//check expiration
            return res.status(410).json({ error: 'Short link has expired' });
        }
        // First check Redis cache for fast redirect
        const cachedUrl = await redis.get(`link:${shortCode}`);
        if (cachedUrl) {
        await redis.incr(`clicks:${shortCode}`); // atomic increment
        return res.redirect(301, cachedUrl);
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

export const getStats = async (req: AuthenticatedRequest, res: Response) => {
  const { shortCode } = req.params;
  
  try {
    const link = await prisma.shortLink.findUnique({
      where: { shortCode },
      select: { clicks: true, originalUrl: true, 
        createdAt: true, expiresAt: true, userId: true, },
    });

    if (!link) {
      return res.status(404).json({ error: 'Short link not found' });
    }

    // Get real-time clicks from Redis (more accurate than DB if not synced yet)
    const redisClicks = await redis.get(`clicks:${shortCode}`);
    const totalClicks = redisClicks ? parseInt(redisClicks, 10) : link.clicks;

    const uniqueVisitors = await redis.pfCount(`visitors:${shortCode}`);

    const dailyClicks: Record<string, number> = {};

    const recentDetails = await redis.lRange(`clicks:details:${shortCode}`, 0, 999);
    recentDetails.forEach((jsonStr) => {
      const data = JSON.parse(jsonStr);
      const day = new Date(data.timestamp).toISOString().split('T')[0];
      dailyClicks[day] = (dailyClicks[day] || 0) + 1;
  });


    //const recent = await redis.lRange(`clicks:details:${shortCode}`, 0, 4);
    //const recentClicks = recent.map((json) => JSON.parse(json));
    
    res.json({
      shortCode,
      originalUrl: link.originalUrl,
      totalClicks,
      uniqueVisitorsApprox: uniqueVisitors,
      createdAt: link.createdAt,
      dailyClicksLast7: Object.fromEntries(
        Object.entries(dailyClicks)
          .sort(([a], [b]) => b.localeCompare(a)) // sort by date desc
          .slice(0, 7) // last 7 days
      ),
      isOwnedByUser: !!req.user && req.user.userId === link.userId,

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
    const baseUrl = process.env.RAILWAY_URL || 'http://localhost:5001';
    const enrichedLinks = links.map(link => ({
      ...link,
      shortUrl: `${baseUrl}/api/${link.shortCode}`,
    }));

    res.json({ links: enrichedLinks });
  } catch (err) {
    logger?.error(err);
    res.status(500).json({ error: 'Failed to fetch links', details: String(err) });
  }
}

export const getDashboardSummary = async (req: AuthenticatedRequest, res: Response) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  try {
    const userLInks = await prisma.shortLink.findMany({
      where: { userId: req.user.userId },
      select: { id: true, clicks: true },
    });

    const totalLinks = userLInks.length;
    let totalClicks = 0;

    for (const link of userLInks) {
      const redisClicks = await redis.get(`clicks:${link.id}`);

      totalClicks+= link.clicks;
    }

    res.json({ totalLinks, totalClicks, 
      averageClicksPerLink: totalLinks > 0 ? totalClicks / totalLinks : 0,
      });
  } catch (err) {
    logger?.error(err);
    res.status(500).json({ error: 'Failed to fetch dashboard summary', details: String(err) });
  }
}


