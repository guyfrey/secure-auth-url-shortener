import { Request, Response } from 'express';
import rateLimit from 'express-rate-limit';
import { AuthenticatedRequest } from '../middleware/auth';

// Standard limiter for public routes (plain Request)
export const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Too many requests from this IP',
  keyGenerator: (req: Request) => req.ip || 'anonymous',
});

export const userLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 50,
  message: 'Too many requests from this user',
  keyGenerator: (req: Request) => {
    const authReq = req as AuthenticatedRequest;
    return authReq.user?.userId || req.ip || 'anonymous';
  },
  skip: (req: Request) => {
    const authReq = req as AuthenticatedRequest;
    return !authReq.user;
  },
});