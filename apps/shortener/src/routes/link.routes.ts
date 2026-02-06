import {Router} from 'express';
import { shorten ,redirect, getStats, getMyLinks} from '../controllers/link.controller';
import { protect } from '../middleware/auth';

const router = Router();

router.post('/shorten',shorten);

router.get('/my/links',protect,getMyLinks);

router.get('/:shortCode/stats',getStats);


router.get('/:shortCode',redirect);

export default router;




