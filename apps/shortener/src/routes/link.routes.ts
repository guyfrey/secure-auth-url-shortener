import {Router} from 'express';
import { shorten ,redirect, getStats} from '../controllers/link.controller';

const router = Router();

router.post('/shorten',shorten);
router.get('/:shortCode/stats',getStats);


router.get('/:shortCode',redirect);

export default router;




