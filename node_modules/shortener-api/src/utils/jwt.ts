import jwt from 'jsonwebtoken';

const ACCESS_SECRET = process.env.JWT_ACCESS_SECRET!;

if (!ACCESS_SECRET) {
  throw new Error('JWT_ACCESS_SECRET is not set');
}

export interface JwtPayload {
  userId: string;
  role: string;
}

export const verifyAccessToken = (token: string): JwtPayload => {
  return jwt.verify(token, ACCESS_SECRET) as JwtPayload;
};