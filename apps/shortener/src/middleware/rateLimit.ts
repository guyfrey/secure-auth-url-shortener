import rateLimit from 'express-rate-limit';
import { Request, Response, NextFunction } from 'express';
import { AuthenticatedRequest } from '../middleware/auth'; // your extended interface

export const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per window
  message: { error: 'Too many requests, please try again later.' },
  keyGenerator: (req: Request) => req.ip || 'anonymous', // use plain Request here
});

// If you need to use AuthenticatedRequest for custom logic (e.g. per-user limit)
export const userRateLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 50, // 50 requests per hour per user
  keyGenerator: (req: AuthenticatedRequest) => {
    return req.user ? req.user.userId : req.ip || 'anonymous';
  },
  skip: (req: AuthenticatedRequest) => !req.user, // skip for unauthenticated
});