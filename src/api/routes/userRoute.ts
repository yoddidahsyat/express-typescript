import { OpenAPIRegistry } from "@asteasolutions/zod-to-openapi";
import express, { type Router } from "express";
import { z } from "zod";
import { userController } from "@/api/user/userController";
import { CreateUserSchema, GetUserSchema, UpdateUserSchema, UserSchema } from "@/api/user/userModel";
import { createApiResponse } from "@/api-docs/openAPIResponseBuilders";
import { authenticateJwt, authorizeRole } from "@/common/middleware/authMiddleware";
import { validateRequest } from "@/common/utils/httpHandlers";

export const userRegistry = new OpenAPIRegistry();
export const userRouter: Router = express.Router();

userRouter.use(authenticateJwt, authorizeRole("ADMIN"));

// routes
userRouter.get("/", userController.getUsers);
userRouter.get("/:id", validateRequest(GetUserSchema), userController.getUser);
userRouter.post("/", validateRequest(CreateUserSchema), userController.createUser);
userRouter.put("/:id", validateRequest(UpdateUserSchema), userController.updateUser);
userRouter.delete("/:id", validateRequest(GetUserSchema), userController.deleteUser);

// openAPIRegistry (Swagger)
userRegistry.register("User", UserSchema);

userRegistry.registerPath({
	method: "get",
	path: "/users",
	tags: ["User"],
	security: [
		{
			bearerAuth: [],
		},
	],
	responses: createApiResponse(z.array(UserSchema), "Success"),
});

userRegistry.registerPath({
	method: "get",
	path: "/users/{id}",
	tags: ["User"],
	security: [
		{
			bearerAuth: [],
		},
	],
	request: { params: GetUserSchema.shape.params },
	responses: createApiResponse(UserSchema, "Success"),
});

userRegistry.registerPath({
	method: "post",
	path: "/users",
	tags: ["User"],
	security: [
		{
			bearerAuth: [],
		},
	],
	request: {
		body: {
			content: {
				"application/json": {
					schema: UserSchema.omit({ id: true, createdAt: true, updatedAt: true }),
				},
			},
		},
	},
	responses: createApiResponse(z.object({ message: z.string() }), "User created successfully"),
});

userRegistry.registerPath({
	method: "put",
	path: "/users/{id}",
	tags: ["User"],
	security: [
		{
			bearerAuth: [],
		},
	],
	request: {
		params: GetUserSchema.shape.params,
		body: {
			content: {
				"application/json": {
					schema: UserSchema.omit({ id: true, createdAt: true, updatedAt: true }),
				},
			},
		},
	},
	responses: createApiResponse(z.object({ message: z.string() }), "User updated successfully"),
});

userRegistry.registerPath({
	method: "delete",
	path: "/users/{id}",
	tags: ["User"],
	security: [
		{
			bearerAuth: [],
		},
	],
	request: { params: GetUserSchema.shape.params },
	responses: createApiResponse(z.object({ message: z.string() }), "User deleted successfully"),
});
