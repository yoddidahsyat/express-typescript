import { OpenAPIRegistry } from "@asteasolutions/zod-to-openapi";
import express, { type Router } from "express";
import { z } from "zod";
import { authController } from "@/api/auth/authController";
import { LoginSchema, RegisterSchema } from "@/api/auth/authModel";
import { UpdateProfileSchema, UserSchema } from "@/api/user/userModel";
import { createApiResponse } from "@/api-docs/openAPIResponseBuilders";
import { authenticateJwt } from "@/common/middleware/authMiddleware";
import { validateRequest } from "@/common/utils/httpHandlers";

export const authRegistry = new OpenAPIRegistry();
export const authRouter: Router = express.Router();

// Routes
authRouter.post("/register", validateRequest(RegisterSchema), authController.register);
authRouter.post("/login", validateRequest(LoginSchema), authController.login);
authRouter.post("/refresh", authController.refresh);
authRouter.post("/logout", authenticateJwt, authController.logout);
authRouter.get("/profile", authenticateJwt, authController.me);
authRouter.put("/profile", authenticateJwt, validateRequest(UpdateProfileSchema), authController.updateProfile);

// OpenAPI Registry (Swagger)
authRegistry.registerPath({
	method: "post",
	path: "/auth/register",
	tags: ["Auth"],
	request: {
		body: {
			content: {
				"application/json": {
					schema: RegisterSchema.shape.body,
				},
			},
		},
	},
	responses: createApiResponse(
		z.object({
			user: UserSchema,
		}),
		"User registered successfully",
	),
});

authRegistry.registerPath({
	method: "post",
	path: "/auth/login",
	tags: ["Auth"],
	request: {
		body: {
			content: {
				"application/json": {
					schema: LoginSchema.shape.body,
				},
			},
		},
	},
	responses: createApiResponse(
		z.object({
			user: UserSchema,
			accessToken: z.string(),
		}),
		"Login successful",
	),
});

authRegistry.registerPath({
	method: "post",
	path: "/auth/refresh",
	tags: ["Auth"],
	responses: createApiResponse(
		z.object({
			accessToken: z.string(),
		}),
		"Token refreshed successfully",
	),
});

authRegistry.registerPath({
    method: "get",
    path: "/auth/profile",
    tags: ["Auth"],
    security: [
        {
            bearerAuth: [],
        },
    ],
    responses: createApiResponse(UserSchema, "Current authenticated user"),
});

authRegistry.registerPath({
	method: "put",
	path: "/auth/profile",
	tags: ["Auth"],
	security: [
		{
			bearerAuth: [],
		},
	],
	request: {
		body: {
			content: {
				"application/json": {
					schema: UpdateProfileSchema.shape.body,
				},
			},
		},
	},
	responses: createApiResponse(UserSchema, "Profile updated successfully"),
});

authRegistry.registerPath({
	method: "post",
	path: "/auth/logout",
	tags: ["Auth"],
	security: [
		{
			bearerAuth: [],
		},
	],
	responses: createApiResponse(z.null(), "Logout successful"),
});
