// src/logger.ts
import pino from 'pino';

const isDevelopment = process.env.NODE_ENV !== 'production';

// Only use pretty transport in development/local
const logger = pino({
  level: 'info', // default level – you can change to 'debug' if you want more locally
  transport: isDevelopment
    ? {
        target: 'pino-pretty',
        options: {
          colorize: true,
          translateTime: 'yyyy-mm-dd HH:MM:ss',
          ignore: 'pid,hostname',
        },
      }
    : undefined, // production → fast raw JSON, no transport needed
});

export default logger;