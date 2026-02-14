import {Request, Response, NextFunction} from 'express';
import {verifyAccessToken, JwtPayload} from '../utils/jwt';

export interface AuthenticatedRequest extends Request {
    user?: JwtPayload;
}

export const protect = (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    const authHeader = req.headers.authorization;   
    if(!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({error: 'No token provided'});
    }

    const token = authHeader.split(' ')[1];

    try {
        const payload = verifyAccessToken(token);
        req.user = payload;
        next();
    } catch (err) {
        return res.status(401).json({error: 'Invalid or expired token'});
    }
};

export const optionalProtect = (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    const authHeader = req.headers.authorization;   
    if(!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({error: 'No token provided'});
    }

    const token = authHeader.split(' ')[1];

    try {
        const payload = verifyAccessToken(token);
        req.user = payload;
        
    } catch {
       
    }
    next();
};



export const adminOnly = (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    if(req.user?.role !== 'ADMIN') {
        return res.status(403).json({error: 'Admin access required'});
    }
    next();
}