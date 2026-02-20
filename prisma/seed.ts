import "dotenv/config";
import { PrismaMariaDb } from "@prisma/adapter-mariadb";
import { hashSync } from "bcryptjs";

import { PrismaClient, type users_role } from "../generated/prisma/client";

const adapter = new PrismaMariaDb({
	host: process.env.DATABASE_HOST,
	user: process.env.DATABASE_USER,
	password: process.env.DATABASE_PASSWORD,
	database: process.env.DATABASE_NAME,
	connectionLimit: 5,
});

const prisma = new PrismaClient({ adapter });

const seedUsers = [
	{
		email: "admin@example.com",
		name: "Admin User",
		role: "ADMIN",
		password: "AdminPass123!",
	},
	{
		email: "user1@example.com",
		name: "User One",
		role: "USER",
		password: "UserPass123!",
	},
	{
		email: "user2@example.com",
		name: "User Two",
		role: "USER",
		password: "UserPass123!",
	},
	{
		email: "user3@example.com",
		name: "User Three",
		role: "USER",
		password: "UserPass123!",
	},
	{
		email: "user4@example.com",
		name: "User Four",
		role: "USER",
		password: "UserPass123!",
	},
];

const seed = async (): Promise<void> => {
	const now = new Date();

	for (const user of seedUsers) {
		const passwordHash = hashSync(user.password, 10);

		await prisma.users.upsert({
			where: { email: user.email },
			create: {
				email: user.email,
				name: user.name,
				role: user.role as users_role,
				passwordHash,
				createdAt: now,
				updatedAt: now,
			},
			update: {
				name: user.name,
				role: user.role as users_role,
				passwordHash,
				updatedAt: now,
			},
		});
	}
};

seed()
	.then(async () => {
		await prisma.$disconnect();
	})
	.catch(async (error) => {
		console.error("Seed failed", error);
		await prisma.$disconnect();
		process.exit(1);
	});
