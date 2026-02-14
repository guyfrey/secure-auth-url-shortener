import {Router} from 'express';
import { shorten ,redirect, getStats, getMyLinks, getDashboardSummary} from '../controllers/link.controller';
import { protect, optionalProtect } from '../middleware/auth';
import { limiter, userLimiter  } from '../middleware/rateLimit';

const router = Router();

router.post('/shorten', limiter, shorten); // public
router.post('/protected-shorten', protect, userLimiter, shorten); // protected

router.get('/my/links',protect,getMyLinks);

router.get('/dashboard/summary',protect,getDashboardSummary);

router.get('/:shortCode/stats',optionalProtect,getStats);


router.get('/:shortCode',redirect);

export default router;




