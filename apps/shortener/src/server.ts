//import dotenv from 'dotenv';


//dotenv.config();

import express from 'express';
import cors from 'cors';
import linkRoutes from './routes/link.routes';
import logger from './logger';
import { connectRedis } from './services/redis';



const apps = express();
const PORT = process.env.PORT || 5001;

(async () => {
 await connectRedis(); //  connect Redis after env is loaded
})();

apps.use(cors({origin: '*'}));
apps.use(express.json());

//health check
apps.get('/health',(req,res)=>{
    logger.info('Shortner health check');
    res.json({status:'ok',message:'URL Shortener running!'});
});

apps.use('/api',linkRoutes); //under api/

apps.use((req,res)=>{
    res.status(404).json({error:'Not Found'});
});

apps.listen(PORT, () => {
  logger?.info(`Shortener running on http://localhost:${PORT}`);
});

//asdfadsfad