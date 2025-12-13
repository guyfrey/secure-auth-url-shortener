import { Request, Response } from 'express';
import { prisma } from '../services/prisma';
import { redis } from '../services/redis';
import bcrypt from 'bcryptjs';
import { z } from 'zod';
import { signAccessToken, signRefreshToken, verifyRefreshToken } from '../utils/jwt';

const registerSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
  name: z.string().optional(),
});

const loginSchema = z.object({
  email: z.string().email(),
  password: z.string(),
});

export const register = async (req: Request, res: Response) => {
  try {
    const { email, password, name } = registerSchema.parse(req.body);

    const existing = await prisma.user.findUnique({ where: { email } });
    if (existing) return res.status(400).json({ error: 'Email already exists' });

    const passwordHash = await bcrypt.hash(password, 12);

    const user = await prisma.user.create({
      data: { email, passwordHash, name },
    });

    res.status(201).json({ message: 'User created', user: { id: user.id, email: user.email } });
  } catch (err) {
    if (err instanceof z.ZodError) {
      return res.status(400).json({ error: err.errors });
    }
    res.status(500).json({ error: 'Server error' });
  }
};

export const login = async (req: Request, res: Response) => {
  try {
    const { email, password } = loginSchema.parse(req.body);

    const user = await prisma.user.findUnique({ where: { email } });
    if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const accessToken = signAccessToken({ userId: user.id, role: user.role });
    const refreshToken = signRefreshToken({ userId: user.id });

    // Store refresh token in Redis (key: userId, value: refreshToken) - for revocation later
    await redis.set(`refresh:${user.id}`, refreshToken, { EX: 7 * 24 * 60 * 60 });

    // Send refresh token in HTTP-only secure cookie
    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    res.json({ accessToken, user: { id: user.id, email: user.email, role: user.role } });
  } catch (err) {
    if (err instanceof z.ZodError) return res.status(400).json({ error: err.errors });
    res.status(500).json({ error: 'Server error' });
  }
};

export const me = async (req: Request, res: Response) => {
  // req.user is added by protect middleware
  const authReq = req as any;
  const user = await prisma.user.findUnique({
    where: { id: authReq.user.userId },
    select: { id: true, email: true, name: true, role: true },
  });
  res.json({ user });
};

export const refresh = async (req: Request, res: Response) => {
  const token = req.cookies.refreshToken;
  if (!token) return res.status(401).json({ error: 'No refresh token' });

  try {
    const payload = verifyRefreshToken(token);
    const stored = await redis.get(`refresh:${payload.userId}`);
    if (token !== stored) return res.status(401).json({ error: 'Invalid refresh token' });

    const user = await prisma.user.findUnique({ where: { id: payload.userId } });
    if (!user) return res.status(401).json({ error: 'User not found' });

    const newAccessToken = signAccessToken({ userId: user.id, role: user.role });
    res.json({ accessToken: newAccessToken });
  } catch (err) {
    res.status(401).json({ error: 'Invalid refresh token' });
  }
};

export const logout = async (req: Request, res: Response) => {
  const token = req.cookies.refreshToken;
  if (token) {
    try {
      const payload = verifyRefreshToken(token);
      await redis.del(`refresh:${payload.userId}`);
    } catch {}
  }
  res.clearCookie('refreshToken');
  res.json({ message: 'Logged out' });
};