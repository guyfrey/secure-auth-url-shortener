import rateLimit from 'express-rate-limit';
import { Request, Response, NextFunction } from 'express';
import { redis } from '../services/redis';
import { AuthenticatedRequest } from './auth';


const keyGenerator = (req: AuthenticatedRequest) => {
    if(req.user?.userId) {
        return `rate:shorten:user:${req.user.userId}`;
    }
    return `rate:shorten:ip:${req.ip}`;
};

export const shortenRateLimiter = rateLimit({
    windowMs: 24*60 * 60 * 1000, // 24 hour
    max: 15, // limit each user/IP to 100 requests per windowMs
    keyGenerator,
    standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
    legacyHeaders: false, // Disable the `X-RateLimit-*` headers
    handler: (req: Request, res: Response) => {
        res.status(429).json({ error: 'Too many requests, please try again later.' });
    },
    skip:(req:Request) => {
        return false;

    },
});