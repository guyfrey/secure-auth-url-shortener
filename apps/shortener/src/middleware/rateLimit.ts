import rateLimit from 'express-rate-limit';
import { Request, Response } from 'express';
import { AuthenticatedRequest } from '../middleware/auth';

export const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: 'Too many requests, please try again later.',
  handler: (req: Request, res: Response) => {
    res.status(429).json({ error: 'Too many requests, please try again later.' });
  },
  keyGenerator: (req: Request) => req.ip || 'anonymous',
});

export const userRateLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 10,
  message: 'Too many requests, please try again later.',
  handler: (req: Request, res: Response) => {
    res.status(429).json({ error: 'Too many requests, please try again later.' });
  },
  keyGenerator: (req: AuthenticatedRequest) => {
    return req.user ? req.user.userId : req.ip || 'anonymous';
  },
  skip: (req: AuthenticatedRequest) => !req.user,
});