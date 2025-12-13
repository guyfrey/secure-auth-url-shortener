import { Router } from 'express';
import { register, login, me, refresh, logout } from '../controllers/auth.controller';
import { protect } from '../middleware/auth';

const router = Router();

router.post('/register', register);
router.post('/login', login);
router.get('/me', protect, me);
router.post('/refresh', refresh);
router.post('/logout', logout);

export default router;