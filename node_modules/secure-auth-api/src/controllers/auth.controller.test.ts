import { prismaMock } from '../../jest.setup';  // Adjust path if needed
import bcrypt from 'bcryptjs';
import { register } from './auth.controller'; // Adjust import
import { Request, Response } from 'express';

describe('Auth Controller - register', () => {
  let mockReq: Partial<Request>;
  let mockRes: Partial<Response>;

  beforeEach(() => {
    mockReq = { body: {} };
    mockRes = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };
  });

  it('should register a new user successfully', async () => {
    mockReq.body = { email: 'new@example.com', password: 'password123', name: 'New User' };

    // Cast to any or use as jest.Mock to access mockResolvedValue
    (prismaMock.user.findUnique as jest.Mock).mockResolvedValue(null);

    const mockUser = {
      id: '1',
      email: 'new@example.com',
      passwordHash: 'hashed',
      name: 'New User',
      role: 'USER' as const,
      isVerified: false,
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    (prismaMock.user.create as jest.Mock).mockResolvedValue(mockUser);

    jest.spyOn(bcrypt, 'hash').mockResolvedValue('hashed' as never);

    await register(mockReq as Request, mockRes as Response);

    expect(mockRes.status).toHaveBeenCalledWith(201);
    expect(mockRes.json).toHaveBeenCalledWith(
      expect.objectContaining({ message: 'User created' })
    );
  });

  it('should return 400 on duplicate email', async () => {
    mockReq.body = { email: 'duplicate@example.com', password: 'password123' };

    (prismaMock.user.findUnique as jest.Mock).mockResolvedValue({ id: 'existing' }); // simulate existing user

    await register(mockReq as Request, mockRes as Response);

    expect(mockRes.status).toHaveBeenCalledWith(400);
    expect(mockRes.json).toHaveBeenCalledWith(expect.objectContaining({ error: 'Email already exists' }));
  });

  // Add a test for duplicate email, etc.
});