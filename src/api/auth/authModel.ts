import { extendZodWithOpenApi } from "@asteasolutions/zod-to-openapi";
import { z } from "zod";

extendZodWithOpenApi(z);

// Register Request Schema
export const RegisterSchema = z.object({
	body: z.object({
		email: z.string().email("Invalid email address"),
		password: z.string().min(8, "Password must be at least 8 characters"),
		name: z.string().min(1, "Name is required"),
	}),
});

export type RegisterRequest = z.infer<typeof RegisterSchema>;

// Login Request Schema
export const LoginSchema = z.object({
	body: z.object({
		email: z.string().email("Invalid email address"),
		password: z.string().min(1, "Password is required"),
	}),
});

export type LoginRequest = z.infer<typeof LoginSchema>;

// Refresh Token Request Schema
export const RefreshTokenSchema = z.object({
	body: z.object({}),
});

export type RefreshTokenRequest = z.infer<typeof RefreshTokenSchema>;

// Token Payload Schema (JWT content)
export const TokenPayloadSchema = z.object({
	userId: z.number(),
	email: z.string().email(),
	role: z.enum(["ADMIN", "USER", "MODERATOR"]),
});

export type TokenPayload = z.infer<typeof TokenPayloadSchema>;

// JWT Token Response Schema
export const JwtTokenSchema = z.object({
	accessToken: z.string(),
	expiresIn: z.string(),
});

export type JwtToken = z.infer<typeof JwtTokenSchema>;
