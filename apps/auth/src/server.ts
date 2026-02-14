import dotenv from 'dotenv';
dotenv.config(); // Load environment variables early

import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import authRoutes from './routes/auth.routes';
import { connectRedis } from './services/redis';
import rateLimit from 'express-rate-limit';
import { login, register, forgotPassword } from './controllers/auth.controller';
import swaggerUi from 'swagger-ui-express';
import { specs } from './swagger';
import logger from './logger';
import pinoHttp from 'pino-http';
import helmet from 'helmet';
import { ErrorRequestHandler, Request, Response, NextFunction } from 'express';



const app = express();
const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 5000;



(async () => {
 await connectRedis(); //  connect Redis after env is loaded
})();


//connectRedis()
  //.then(() => console.log('Redis connected successfully'))
  //.catch(err => console.error('Redis connect failed (non-blocking):', err));


//app.get('/health', (req, res) => {
//  res.status(200).json({ status: 'ok', uptime: process.uptime() });
//});

app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:3000',
  credentials: true
}));
app.use(express.json());
app.use(cookieParser());

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // limit each IP to 5 requests per window
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many attempts, try again later' },
});

// Apply to sensitive routes
app.post('/api/auth/login', limiter, login);
app.post('/api/auth/register', limiter, register);
app.post('/api/auth/forgot-password', limiter, forgotPassword);


// After other middleware
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(specs));


// Security headers
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      
    },
  },
}));

// Pino request logging
app.use(pinoHttp({
  logger,
  serializers: {
    req: (req) => ({
      method: req.method,
      url: req.url,
      remoteAddress: req.socket?.remoteAddress || req.ip,
      userAgent: req.headers['user-agent'],
    }),
  },
  customLogLevel: (req, res, err) => {
    if (res.statusCode >= 500) return 'error';
    if (res.statusCode >= 400) return 'warn';
    return 'info';
  },
}));

// /health check
app.get('/health', (req, res) => {
  logger.info('Health check requested');
  res.json({ status: 'OK', message: 'Auth server running!' });
});

app.use('/api/auth', authRoutes);

app.use('*', (req, res) => {
  res.status(404).json({ error: 'Not found' });
});

// error handler 
const errorHandler: ErrorRequestHandler = (err: any, req: Request, res: Response, next: NextFunction) => {
  logger.error(err); 

  const status = err.status || err.statusCode || 500;
  const message = err.message || 'Internal Server Error';

  res.status(status).json({
    error: {
      message,
      ...(process.env.NODE_ENV === 'development' && { stack: err.stack }),
    },
  });
};

app.use(errorHandler);




app.listen(PORT, '0.0.0.0', () => {
  logger.info(`Auth server running on http://0.0.0.0:${PORT}`);
  
// Debug helper for Railway
  logger.info(`Railway assigned PORT: ${process.env.PORT || '(not set - using fallback)'}`);
  if (process.env.RAILWAY_PUBLIC_DOMAIN) {
    logger.info(`Expected public access: https://${process.env.RAILWAY_PUBLIC_DOMAIN}`);
  }
});