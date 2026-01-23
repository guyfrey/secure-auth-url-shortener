import { Request, Response } from 'express';
import { prisma } from '../services/prisma';
import { AuthRequest } from '../middleware/auth';
import logger from '../logger';

export const getAllUsers = async (req: AuthRequest, res: Response) => {
  try {
    const users = await prisma.user.findMany({
      select: { id: true, email: true, name: true, role: true, isVerified: true, createdAt: true },
    });
    logger.info(`Admin ${req.user?.userId} viewed all users`);
    res.json({ users });
  } catch (err) {
    logger.error(err);
    res.status(500).json({ error: 'Server error' });
  }
};