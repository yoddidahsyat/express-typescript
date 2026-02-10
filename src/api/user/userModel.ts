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
