import jwt from 'jsonwebtoken';
import { ApiError } from '../utils/apiError.js';
import { asyncHandler } from '../utils/asyncHandler.js';
import prisma from '../prisma/prismaClient.js';

export const verifyJWT = asyncHandler(async (req, res, next) => {
    try {
        const token = req.cookies?.accessToken || 
                      req.header("Authorization")?.replace("Bearer ", "");

        if (!token) {
            throw new ApiError(401, "Unauthorized - No token provided");
        }

        const decodedToken = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);

        const user = await prisma.user.findUnique({
            where: { id: decodedToken.userId },
            select: {
                id: true,
                email: true,
                name: true,
                isVerified: true
            }
        });

        if (!user) {
            throw new ApiError(401, "Unauthorized - Invalid token");
        }

        if (!user.isVerified) {
            throw new ApiError(403, "Please verify your email first");
        }

        req.user = user;
        next();
    } catch (error) {
        if (error.name === 'JsonWebTokenError') {
            throw new ApiError(401, "Unauthorized - Invalid token");
        }
        if (error.name === 'TokenExpiredError') {
            throw new ApiError(401, "Unauthorized - Token expired");
        }
        throw error;
    }
});