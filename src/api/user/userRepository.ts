import type { UserWithSecrets } from "@/api/user/userModel";
import { prisma } from "@/common/lib/prisma";
import { logger } from "@/server";

export class UserRepository {
	async findAllAsync(): Promise<UserWithSecrets[]> {
		try {
			const users = await prisma.users.findMany();
			return users;
		} catch (error) {
			logger.error({ error }, "Database error in UserRepository.findAllAsync");
			throw error;
		}
	}

	async findByIdAsync(id: number): Promise<UserWithSecrets | null> {
		try {
			const user = await prisma.users.findUnique({
				where: { id },
			});
			return user || null;
		} catch (error) {
			logger.error({ error }, "Database error in UserRepository.findByIdAsync");
			throw error;
		}
	}
	
  async findByEmailAsync(email: string): Promise<UserWithSecrets | null> {
		try {
			const user = await prisma.users.findUnique({
				where: { email },
			});
			return user || null;
		} catch (error) {
			logger.error({ error }, "Database error in UserRepository.findByIdAsync");
			throw error;
		}
	}

  async createUserAsync(userData: UserWithSecrets): Promise<UserWithSecrets> {
    try {
      const newUser = await prisma.users.create({
        data: userData,
      });
      return newUser;
    } catch (error) {
      logger.error({ error }, "Database error in UserRepository.createUser");
      throw error;
    }
  }

  async updateUserAsync(id: number, userData: Partial<UserWithSecrets>): Promise<UserWithSecrets> {
    try {
      const updatedUser = await prisma.users.update({
        where: { id },
        data: userData,
      });
      return updatedUser;
    } catch (error) {
      logger.error({ error }, "Database error in UserRepository.updateUserAsync");
      throw error;
    }
  }

  async deleteUserAsync(id: number): Promise<void> {
    try {
      await prisma.users.delete({
        where: { id },
      });
    } catch (error) {
      logger.error({ error }, "Database error in UserRepository.deleteUserAsync");
      throw error;
    }
  }
}
