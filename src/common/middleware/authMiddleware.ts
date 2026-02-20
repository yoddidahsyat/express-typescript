import type { NextFunction, Request, Response } from "express";
import jwt from "jsonwebtoken";

import type { TokenPayload } from "@/api/auth/authModel";
import { AuthRepository } from "@/api/auth/authRepository";
import { env } from "@/common/utils/envConfig";
import { logger } from "@/server";

// Extend Express Request to include user property
declare global {
	namespace Express {
		interface Request {
			user?: TokenPayload;
		}
	}
}

/**
 * Middleware to authenticate JWT token from Authorization header
 */
export const authenticateJwt = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
	try {
		// Extract token from Authorization header
		const authHeader = req.headers.authorization;
		if (!authHeader || !authHeader.startsWith("Bearer ")) {
			res.status(401).json({
				success: false,
				message: "Missing or invalid Authorization header",
				data: null,
				statusCode: 401,
			});
			return;
		}

		const token = authHeader.substring(7); // Remove "Bearer " prefix

		// Verify token
		const decoded = jwt.verify(token, env.JWT_SECRET) as TokenPayload;

		// Ensure the user still has an active refresh token (i.e. not logged out).
		// If refreshTokenHash is null it means the user logged out and access tokens should be invalidated.
		const repo = new AuthRepository();
		const user = await repo.findByIdAsync(decoded.userId);
		if (!user || !user.refreshTokenHash) {
			res.status(401).json({
				success: false,
				message: "User session invalidated",
				data: null,
				statusCode: 401,
			});
			return;
		}

		req.user = decoded;
		next();
	} catch (error) {
		if (error instanceof jwt.TokenExpiredError) {
			res.status(401).json({
				success: false,
				message: "Token has expired",
				data: null,
				statusCode: 401,
			});
			return;
		}

		if (error instanceof jwt.JsonWebTokenError) {
			res.status(401).json({
				success: false,
				message: "Invalid token",
				data: null,
				statusCode: 401,
			});
			return;
		}

		logger.error({ error }, "Authentication error");
		res.status(401).json({
			success: false,
			message: "Authentication failed",
			data: null,
			statusCode: 401,
		});
	}
};

/**
 * Middleware factory to authorize based on user roles
 */
export const authorizeRole = (...allowedRoles: string[]) => {
	return (req: Request, res: Response, next: NextFunction): void => {
		if (!req.user) {
			res.status(401).json({
				success: false,
				message: "User not authenticated",
				data: null,
				statusCode: 401,
			});
			return;
		}

		if (!allowedRoles.includes(req.user.role)) {
			res.status(403).json({
				success: false,
				message: "You do not have permission to access this resource",
				data: null,
				statusCode: 403,
			});
			return;
		}

		next();
	};
};
