import jwt from 'jsonwebtoken';

const ACCESS_SECRET = process.env.JWT_ACCESS_SECRET!;
const REFRESH_SECRET = process.env.JWT_REFRESH_SECRET!;

export const signAccessToken = (payload: { userId: string; role: string }) => {
  return jwt.sign(payload, ACCESS_SECRET, { expiresIn: '15m' });
};

export const signRefreshToken = (payload: { userId: string }) => {
  return jwt.sign(payload, REFRESH_SECRET, { expiresIn: '7d' });
};

export const verifyAccessToken = (token: string) => {
  return jwt.verify(token, ACCESS_SECRET) as { userId: string; role: string };
};

export const verifyRefreshToken = (token: string) => {
  return jwt.verify(token, REFRESH_SECRET) as { userId: string };
};