import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';
import authRoutes from './routes/auth.routes';
import { connectRedis } from './services/redis';

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