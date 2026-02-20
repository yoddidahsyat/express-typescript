import { randomUUID } from "node:crypto";
import bcrypt from "bcryptjs";
import { StatusCodes } from "http-status-codes";
import jwt from "jsonwebtoken";
import type { TokenPayload } from "@/api/auth/authModel";
import { AuthRepository } from "@/api/auth/authRepository";
import type { User, UserWithSecrets } from "@/api/user/userModel";
import { ServiceResponse } from "@/common/models/serviceResponse";
import { env } from "@/common/utils/envConfig";
import { logger } from "@/server";

export interface TokenResponse {
	accessToken: string;
	expiresIn: string;
}

export class AuthService {
	private authRepository: AuthRepository;

	constructor(
		repository: AuthRepository = new AuthRepository(),
	) {
		this.authRepository = repository;
	}

	/**
	 * Removes sensitive authentication fields from user object
	 */
	private sanitizeUser(user: Partial<UserWithSecrets>): User {
		const { passwordHash: _, refreshTokenHash: __, phone: ___, ...publicUser } = user;
		return publicUser as User;
	}

	/**
	 * Hashes a password using bcrypt
	 */
	private async hashPassword(password: string): Promise<string> {
		const salt = bcrypt.genSaltSync(10);
		return bcrypt.hashSync(password, salt);
	}

	/**
	 * Verifies a password against its hash
	 */
	private async verifyPassword(password: string, hash: string): Promise<boolean> {
		return bcrypt.compareSync(password, hash);
	}

	/**
	 * Generates JWT access and refresh tokens
	 */
	private generateTokens(userId: number, email: string, role: string): { accessToken: string; refreshToken: string } {
		const payload: TokenPayload = { userId, email, role: role as "ADMIN" | "USER" | "MODERATOR" };

		// Include a unique jwtid to ensure tokens generated at the same second differ
		const jwtId = randomUUID();

		const accessToken = jwt.sign(payload, env.JWT_SECRET, {
			expiresIn: env.JWT_ACCESS_EXPIRY,
			jwtid: jwtId,
		} as jwt.SignOptions);

		const refreshToken = jwt.sign(
			payload,
			env.JWT_REFRESH_SECRET as string,
			{
				expiresIn: env.JWT_REFRESH_EXPIRY,
				jwtid: randomUUID(),
			} as jwt.SignOptions,
		);

		return { accessToken, refreshToken };
	}

	/**
	 * Verifies a refresh token
	 */
	private verifyRefreshToken(token: string): TokenPayload | null {
		try {
			return jwt.verify(token, env.JWT_REFRESH_SECRET) as TokenPayload;
		} catch {
			return null;
		}
	}

	/**
	 * Register a new user
	 */
	async registerAsync(email: string, password: string, name: string): Promise<ServiceResponse<User | null>> {
		try {
			// Check if user already exists
			const existingUser = await this.authRepository.findByEmailAsync(email);
			if (existingUser) {
				return ServiceResponse.failure("Email already in use", null, StatusCodes.BAD_REQUEST);
			}

			// Hash password
			const passwordHash = await this.hashPassword(password);

			// Create new user
			const newUser = await this.authRepository.createUserAsync({
				email,
				passwordHash,
				name,
				role: "USER",
				phone: null,
				refreshTokenHash: null,
			});

			const sanitizedUser = this.sanitizeUser(newUser);
			return ServiceResponse.success<User>("User registered successfully", sanitizedUser, StatusCodes.CREATED);
		} catch (ex) {
			const errorMessage = `Error registering user: ${(ex as Error).message}`;
			logger.error(errorMessage);
			return ServiceResponse.failure(
				"An error occurred while registering user.",
				null,
				StatusCodes.INTERNAL_SERVER_ERROR,
			);
		}
	}

	/**
	 * Login user with email and password
	 */
	async loginAsync(
		email: string,
		password: string,
	): Promise<ServiceResponse<{ user: User; accessToken: string; refreshToken: string } | null>> {
		try {
			// Find user by email
			const user = await this.authRepository.findByEmailAsync(email);
			if (!user) {
				return ServiceResponse.failure("Invalid email or password", null, StatusCodes.UNAUTHORIZED);
			}

			// Verify password
			const isPasswordValid = await this.verifyPassword(password, user.passwordHash);
			if (!isPasswordValid) {
				return ServiceResponse.failure("Invalid email or password", null, StatusCodes.UNAUTHORIZED);
			}

			// Generate tokens
			const { accessToken, refreshToken } = this.generateTokens(user.id, user.email, user.role);

			// Hash and store refresh token
			const refreshTokenHash = await this.hashPassword(refreshToken);
			await this.authRepository.updateRefreshTokenHashAsync(user.id, refreshTokenHash);

			const sanitizedUser = this.sanitizeUser(user);
			return ServiceResponse.success<{ user: User; accessToken: string; refreshToken: string }>(
				"Login successful",
				{ user: sanitizedUser, accessToken, refreshToken },
				StatusCodes.OK,
			);
		} catch (ex) {
			const errorMessage = `Error logging in user: ${(ex as Error).message}`;
			logger.error(errorMessage);
			return ServiceResponse.failure("An error occurred while logging in.", null, StatusCodes.INTERNAL_SERVER_ERROR);
		}
	}

	/**
	 * Refresh access token using refresh token
	 */
	async refreshTokenAsync(
		refreshToken: string,
	): Promise<ServiceResponse<{ accessToken: string; refreshToken: string } | null>> {
		try {
			// Verify refresh token
			const payload = this.verifyRefreshToken(refreshToken);
			if (!payload) {
				return ServiceResponse.failure("Invalid or expired refresh token", null, StatusCodes.UNAUTHORIZED);
			}

			// Find user and verify refresh token hash
			const user = await this.authRepository.findByIdAsync(payload.userId);
			if (!user || !user.refreshTokenHash) {
				return ServiceResponse.failure("Invalid or expired refresh token", null, StatusCodes.UNAUTHORIZED);
			}

			// Verify stored hash matches token
			const isTokenValid = await this.verifyPassword(refreshToken, user.refreshTokenHash);
			if (!isTokenValid) {
				return ServiceResponse.failure("Invalid or expired refresh token", null, StatusCodes.UNAUTHORIZED);
			}

			// Generate new tokens
			const { accessToken, refreshToken: newRefreshToken } = this.generateTokens(user.id, user.email, user.role);

			// Hash and store new refresh token
			const newRefreshTokenHash = await this.hashPassword(newRefreshToken);
			await this.authRepository.updateRefreshTokenHashAsync(user.id, newRefreshTokenHash);

			return ServiceResponse.success<{ accessToken: string; refreshToken: string }>(
				"Token refreshed successfully",
				{ accessToken, refreshToken: newRefreshToken },
				StatusCodes.OK,
			);
		} catch (ex) {
			const errorMessage = `Error refreshing token: ${(ex as Error).message}`;
			logger.error(errorMessage);
			return ServiceResponse.failure(
				"An error occurred while refreshing token.",
				null,
				StatusCodes.INTERNAL_SERVER_ERROR,
			);
		}
	}

	/**
	 * Logout user by clearing refresh token
	 */
	async logoutAsync(userId: number): Promise<ServiceResponse<null>> {
		try {
			await this.authRepository.clearRefreshTokenHashAsync(userId);
			return ServiceResponse.success<null>("Logout successful", null, StatusCodes.OK);
		} catch (ex) {
			const errorMessage = `Error logging out user: ${(ex as Error).message}`;
			logger.error(errorMessage);
			return ServiceResponse.failure("An error occurred while logging out.", null, StatusCodes.INTERNAL_SERVER_ERROR);
		}
	}

	/**
	 * Get current user by id
	 */
	async getCurrentUserAsync(userId: number): Promise<ServiceResponse<User | null>> {
		try {
			const user = await this.authRepository.findByIdAsync(userId);
			if (!user) {
				return ServiceResponse.failure("User not found", null, StatusCodes.NOT_FOUND);
			}

			const sanitizedUser = this.sanitizeUser(user);
			return ServiceResponse.success<User>("User fetched successfully", sanitizedUser, StatusCodes.OK);
		} catch (ex) {
			const errorMessage = `Error fetching user: ${(ex as Error).message}`;
			logger.error(errorMessage);
			return ServiceResponse.failure("An error occurred while fetching user.", null, StatusCodes.INTERNAL_SERVER_ERROR);
		}
	}

}
