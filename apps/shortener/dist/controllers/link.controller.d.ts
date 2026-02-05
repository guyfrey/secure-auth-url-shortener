import { Request, Response } from 'express';
export declare const shorten: (req: Request, res: Response) => Promise<Response<any, Record<string, any>> | undefined>;
export declare const redirect: (req: Request, res: Response) => Promise<void | Response<any, Record<string, any>>>;
export declare const getStats: (req: Request, res: Response) => Promise<Response<any, Record<string, any>> | undefined>;
//# sourceMappingURL=link.controller.d.ts.map