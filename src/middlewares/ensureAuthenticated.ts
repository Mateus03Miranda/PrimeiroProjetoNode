import { Request, Response, NextFunction } from 'express';
import { verify } from 'jsonwebtoken';
import AuthConfig from '../config/auth';
import AppError from '../errors/AppError';

interface TokenPayLoad {
    iat: number;
    exp: number;
    sub: string;
}

export default function ensureAuthenticated(
    request: Request,
    response: Response,
    next: NextFunction,
): void {
    const authHeader = request.headers.authorization;
    if (!authHeader) throw new AppError('JWT token is missing!', 401);

    const [, token] = authHeader.split(' ');
    try {
        const decoded = verify(token, AuthConfig.jwt.secret);
        const { sub } = decoded as TokenPayLoad;
        request.user = {
            id: sub,
        };
        return next();
    } catch {
        throw new AppError('Invalid Token', 401);
    }
}
