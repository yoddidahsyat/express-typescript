import type { UserWithSecrets } from "@/api/user/userModel";
import { prisma } from "@/common/lib/prisma";
import { logger } from "@/server";

export class AuthRepository {
	async findByEmailAsync(email: string): Promise<UserWithSecrets | null> {
		try {
			const user = await prisma.users.findUnique({
				where: { email },
			});
			return user || null;
		} catch (error) {
			logger.error({ error }, "Database error in AuthRepository.findByEmailAsync");
			throw error;
		}
	}

	async createUserAsync(userData: Omit<UserWithSecrets, "id" | "createdAt" | "updatedAt">): Promise<UserWithSecrets> {
		try {
			const newUser = await prisma.users.create({
				data: {
					...userData,
					updatedAt: new Date(),
				},
			});
			return newUser;
		} catch (error) {
			logger.error({ error }, "Database error in AuthRepository.createUserAsync");
			throw error;
		}
	}

	async updateRefreshTokenHashAsync(userId: number, refreshTokenHash: string): Promise<void> {
		try {
			await prisma.users.update({
				where: { id: userId },
				data: {
					refreshTokenHash,
					updatedAt: new Date(),
				},
			});
		} catch (error) {
			logger.error({ error }, "Database error in AuthRepository.updateRefreshTokenHashAsync");
			throw error;
		}
	}

	async clearRefreshTokenHashAsync(userId: number): Promise<void> {
		try {
			await prisma.users.update({
				where: { id: userId },
				data: {
					refreshTokenHash: null,
					updatedAt: new Date(),
				},
			});
		} catch (error) {
			logger.error({ error }, "Database error in AuthRepository.clearRefreshTokenHashAsync");
			throw error;
		}
	}

	async findByIdAsync(userId: number): Promise<UserWithSecrets | null> {
		try {
			const user = await prisma.users.findUnique({
				where: { id: userId },
			});
			return user || null;
		} catch (error) {
			logger.error({ error }, "Database error in AuthRepository.findByIdAsync");
			throw error;
		}
	}
}
