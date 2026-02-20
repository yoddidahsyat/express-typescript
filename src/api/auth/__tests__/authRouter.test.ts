import { StatusCodes } from "http-status-codes";
import request from "supertest";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { User } from "@/api/user/userModel";
import { prisma } from "@/common/lib/prisma";
import type { ServiceResponse } from "@/common/models/serviceResponse";
import { app } from "@/server";

describe("Auth API endpoints", () => {
	const testUser = {
		email: "test@example.com",
		password: "password123",
		name: "Test User",
	};

	const invalidUser = {
		email: "invalid@example.com",
		password: "wrongpassword",
		name: "Invalid User",
	};

	let accessToken: string;

	beforeAll(async () => {
		// Clean up test user if exists
		await prisma.users.deleteMany({
			where: { email: { in: [testUser.email, invalidUser.email] } },
		});
	});

	afterAll(async () => {
		// Clean up test users
		await prisma.users.deleteMany({
			where: { email: { in: [testUser.email, invalidUser.email] } },
		});
	});

	describe("POST /auth/register", () => {
		it("should register a new user successfully", async () => {
			const response = await request(app).post("/api/auth/register").send({
				email: testUser.email,
				password: testUser.password,
				name: testUser.name,
			});

			const result: ServiceResponse<User | null> = response.body;

			expect(response.statusCode).toEqual(StatusCodes.CREATED);
			expect(result.success).toBeTruthy();
			expect(result.data).toBeDefined();
			if (result.data) {
				expect(result.data.email).toEqual(testUser.email);
				expect(result.data.name).toEqual(testUser.name);
				expect(result.data.id).toBeDefined();
			}
		});

		it("should reject duplicate email", async () => {
			const response = await request(app).post("/api/auth/register").send({
				email: testUser.email,
				password: testUser.password,
				name: testUser.name,
			});

			const result: ServiceResponse<User | null> = response.body;

			expect(response.statusCode).toEqual(StatusCodes.BAD_REQUEST);
			expect(result.success).toBeFalsy();
			expect(result.message).toContain("Email already in use");
		});

		it("should reject password that is too short", async () => {
			const response = await request(app).post("/api/auth/register").send({
				email: "newuser@example.com",
				password: "short",
				name: "New User",
			});

			expect(response.statusCode).toEqual(StatusCodes.BAD_REQUEST);
		});

		it("should reject invalid email", async () => {
			const response = await request(app).post("/api/auth/register").send({
				email: "not-an-email",
				password: testUser.password,
				name: "Invalid Email User",
			});

			expect(response.statusCode).toEqual(StatusCodes.BAD_REQUEST);
		});
	});

	describe("POST /auth/login", () => {
		it("should login user successfully", async () => {
			const response = await request(app).post("/api/auth/login").send({
				email: testUser.email,
				password: testUser.password,
			});

			const result: ServiceResponse<{ user: User; accessToken: string; refreshToken: string } | null> = response.body;

			expect(response.statusCode).toEqual(StatusCodes.OK);
			expect(result.success).toBeTruthy();
			expect(result.data).toBeDefined();
			if (result.data) {
				expect(result.data.user).toBeDefined();
				expect(result.data.accessToken).toBeDefined();
				expect(result.data.user.email).toEqual(testUser.email);
				// Extract tokens
				accessToken = result.data.accessToken;
			}

			// Verify refresh token is in httpOnly cookie
			expect(response.headers["set-cookie"]).toBeDefined();
			expect(response.headers["set-cookie"][0]).toContain("HttpOnly");
		});

		it("should reject invalid credentials", async () => {
			const response = await request(app).post("/api/auth/login").send({
				email: testUser.email,
				password: "wrongpassword",
			});

			const result: ServiceResponse<{ user: User; accessToken: string; refreshToken: string } | null> = response.body;

			expect(response.statusCode).toEqual(StatusCodes.UNAUTHORIZED);
			expect(result.success).toBeFalsy();
			expect(result.message).toContain("Invalid email or password");
		});

		it("should reject non-existent user", async () => {
			const response = await request(app).post("/api/auth/login").send({
				email: "nonexistent@example.com",
				password: testUser.password,
			});

			const result: ServiceResponse<{ user: User; accessToken: string; refreshToken: string } | null> = response.body;

			expect(response.statusCode).toEqual(StatusCodes.UNAUTHORIZED);
			expect(result.success).toBeFalsy();
		});
	});

	describe("POST /auth/refresh", () => {
		it("should refresh token successfully", async () => {
			// First login to get tokens
			const loginResponse = await request(app).post("/api/auth/login").send({
				email: testUser.email,
				password: testUser.password,
			});

			const cookie = loginResponse.headers["set-cookie"][0];

			// Now refresh
			const response = await request(app).post("/api/auth/refresh").set("Cookie", cookie);

			const result: ServiceResponse<{ accessToken: string; refreshToken: string } | null> = response.body;

			expect(response.statusCode).toEqual(StatusCodes.OK);
			expect(result.success).toBeTruthy();
			expect(result.data).toBeDefined();
			if (result.data) {
				expect(result.data.accessToken).toBeDefined();
				expect(result.data.accessToken).not.toEqual(accessToken);
			}

			// Verify new refresh token is set
			expect(response.headers["set-cookie"]).toBeDefined();
		});

		it("should reject refresh without token", async () => {
			const response = await request(app).post("/api/auth/refresh");

			const result: ServiceResponse<{ accessToken: string; refreshToken: string } | null> = response.body;

			expect(response.statusCode).toEqual(StatusCodes.UNAUTHORIZED);
			expect(result.success).toBeFalsy();
			expect(result.message).toContain("Refresh token not found");
		});
	});

	describe("POST /auth/logout", () => {
		it("should logout user successfully", async () => {
			// First login to get access token
			const loginResponse = await request(app).post("/api/auth/login").send({
				email: testUser.email,
				password: testUser.password,
			});

			const newAccessToken = (
				loginResponse.body as ServiceResponse<{ user: User; accessToken: string; refreshToken: string } | null>
			).data?.accessToken;

			// Now logout
			const response = await request(app).post("/api/auth/logout").set("Authorization", `Bearer ${newAccessToken}`);

			const result: ServiceResponse<null> = response.body;

			expect(response.statusCode).toEqual(StatusCodes.OK);
			expect(result.success).toBeTruthy();

			// Verify refresh token cookie is cleared
			expect(response.headers["set-cookie"]).toBeDefined();
			expect(response.headers["set-cookie"][0]).toContain("refreshToken=");
		});

		it("should reject logout without token", async () => {
			const response = await request(app).post("/api/auth/logout");

			expect(response.statusCode).toEqual(StatusCodes.UNAUTHORIZED);
		});

		it("should reject logout with invalid token", async () => {
			const response = await request(app).post("/api/auth/logout").set("Authorization", "Bearer invalid.token.here");

			expect(response.statusCode).toEqual(StatusCodes.UNAUTHORIZED);
		});
	});

	describe("PUT /auth/profile", () => {
		let profileAccessToken: string;

		beforeAll(async () => {
			const loginResponse = await request(app).post("/api/auth/login").send({
				email: testUser.email,
				password: testUser.password,
			});

			const loginResult: ServiceResponse<{ user: User; accessToken: string; refreshToken: string } | null> =
				loginResponse.body;
			profileAccessToken = loginResult.data?.accessToken || "";
		});

		it("should update profile with valid token", async () => {
			const response = await request(app)
				.put("/api/auth/profile")
				.set("Authorization", `Bearer ${profileAccessToken}`)
				.send({
					name: "Updated Test User",
				});

			const result: ServiceResponse<User | null> = response.body;

			expect(response.statusCode).toEqual(StatusCodes.OK);
			expect(result.success).toBeTruthy();
			expect(result.data).toBeDefined();
			if (result.data) {
				expect(result.data.name).toEqual("Updated Test User");
			}
		});

		it("should reject update without token", async () => {
			const response = await request(app).put("/api/auth/profile").send({
				name: "No Token User",
			});

			expect(response.statusCode).toEqual(StatusCodes.UNAUTHORIZED);
		});

		it("should reject invalid email", async () => {
			const response = await request(app)
				.put("/api/auth/profile")
				.set("Authorization", `Bearer ${profileAccessToken}`)
				.send({
					email: "not-an-email",
				});

			expect(response.statusCode).toEqual(StatusCodes.BAD_REQUEST);
		});
	});

	describe("Protected endpoints with JWT", () => {
		let protectedAccessToken: string;

		beforeAll(async () => {
			const loginResponse = await request(app).post("/api/auth/login").send({
				email: testUser.email,
				password: testUser.password,
			});

			const loginResult: ServiceResponse<{ user: User; accessToken: string; refreshToken: string } | null> =
				loginResponse.body;
			protectedAccessToken = loginResult.data?.accessToken || "";
		});

		it("should access protected endpoint with valid token", async () => {
			const response = await request(app)
				.post("/api/auth/logout")
				.set("Authorization", `Bearer ${protectedAccessToken}`);

			expect(response.statusCode).toEqual(StatusCodes.OK);
		});

		it("should reject access to protected endpoint without token", async () => {
			const response = await request(app).post("/api/auth/logout");

			expect([StatusCodes.UNAUTHORIZED, StatusCodes.TOO_MANY_REQUESTS]).toContain(response.statusCode);
		});

		it("should reject access with expired or invalid token", async () => {
			const response = await request(app).post("/api/auth/logout").set("Authorization", "Bearer invalid.fake.token");

			expect([StatusCodes.UNAUTHORIZED, StatusCodes.TOO_MANY_REQUESTS]).toContain(response.statusCode);
		});
	});
});
