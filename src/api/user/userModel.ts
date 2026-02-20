import { extendZodWithOpenApi } from "@asteasolutions/zod-to-openapi";
import { z } from "zod";

import { commonValidations } from "@/common/utils/commonValidation";

extendZodWithOpenApi(z);

// Public user schema - without sensitive fields
export const UserSchema = z.object({
	id: z.number(),
	name: z.string().nullable(),
	email: z.string().email(),
	role: z.enum(["ADMIN", "USER", "MODERATOR"]),
	createdAt: z.date(),
	updatedAt: z.date(),
});

export type User = z.infer<typeof UserSchema>;

// Internal user schema - includes sensitive authentication fields
export const UserWithSecretsSchema = UserSchema.extend({
	passwordHash: z.string(),
	refreshTokenHash: z.string().nullable(),
	phone: z.string().nullable(),
});

export type UserWithSecrets = z.infer<typeof UserWithSecretsSchema>;

// Input Validation for 'GET users/:id' endpoint
export const GetUserSchema = z.object({
	params: z.object({ id: commonValidations.id }),
});

export const CreateUserSchema = z.object({
  body: z.object({
    name: z.string().min(1, "Name is required"),
    email: z.string().email("Invalid email address"),
    role: z.enum(["ADMIN", "USER", "MODERATOR"]),
    password: z.string().min(8, "Password must be at least 8 characters"),
    phone: z.string().nullable(),
  }),
});

export const UpdateUserSchema = z.object({
  params: z.object({ id: commonValidations.id }),
  body: z.object({
    name: z.string().min(1, "Name is required").optional(),
    email: z.string().email("Invalid email address").optional(),
    role: z.enum(["ADMIN", "USER", "MODERATOR"]).optional(),
    password: z.string().min(8, "Password must be at least 8 characters").optional(),
    phone: z.string().nullable().optional(),
  }),
});

export const UpdateProfileSchema = z.object({
  body: UpdateUserSchema.shape.body,
});

export type GetUserRequest = z.infer<typeof GetUserSchema>;
export type CreateUserRequest = z.infer<typeof CreateUserSchema>;
export type UpdateUserRequest = z.infer<typeof UpdateUserSchema>;