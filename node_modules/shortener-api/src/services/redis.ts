import { createClient } from 'redis';
import logger from '../logger';

const client = createClient({
  url: process.env.REDIS_URL || 'redis://localhost:6379'
});

client.on('error', (err) => logger.error('Redis Client Error', err));

export const redis = client;

export async function connectRedis() {
  if (!client.isOpen) {
    await client.connect();
  }
}