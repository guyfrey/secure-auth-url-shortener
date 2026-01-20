import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';
import authRoutes from './routes/auth.routes';
import { connectRedis } from './services/redis';
import rateLimit from 'express-rate-limit';
import { login, register, forgotPassword } from './controllers/auth.controller';
import swaggerUi from 'swagger-ui-express';
import { specs } from './swagger';


dotenv.config(); // ✅ load .env first

const app = express();
const PORT = process.env.PORT || 5000;

(async () => {
  await connectRedis(); // ✅ connect Redis after env is loaded
})();

app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:3000',
  credentials: true
}));
app.use(express.json());
app.use(cookieParser());

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // limit each IP to 5 requests per window
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


app.get('/health', (req, res) => {
  res.json({ status: 'OK', message: 'Auth server running!' });
});

app.use('/api/auth', authRoutes);

app.use('*', (req, res) => {
  res.status(404).json({ error: 'Not found' });
});

app.listen(PORT, () => {
  console.log(`Auth server running on http://localhost:${PORT}`);
});