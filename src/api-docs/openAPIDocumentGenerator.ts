import { OpenAPIRegistry, OpenApiGeneratorV3 } from "@asteasolutions/zod-to-openapi";
import { healthCheckRegistry } from "@/api/healthCheck/healthCheckRouter";
import { authRegistry } from "@/api/routes/authRoute";
import { userRegistry } from "@/api/routes/userRoute";

export type OpenAPIDocument = ReturnType<OpenApiGeneratorV3["generateDocument"]>;
type OpenAPIDocumentConfig = Parameters<OpenApiGeneratorV3["generateDocument"]>[0];

export function generateOpenAPIDocument(): OpenAPIDocument {
	const registry = new OpenAPIRegistry([healthCheckRegistry, userRegistry, authRegistry]);
	registry.registerComponent("securitySchemes", "bearerAuth", {
		type: "http",
		scheme: "bearer",
		bearerFormat: "JWT",
	});
	const generator = new OpenApiGeneratorV3(registry.definitions);
	const documentConfig: OpenAPIDocumentConfig = {
		openapi: "3.0.0",
		info: {
			version: "1.0.0",
			title: "Swagger API",
		},
		externalDocs: {
			description: "View the raw OpenAPI Specification in JSON format",
			url: "/swagger.json",
		},
	};

	return generator.generateDocument(documentConfig);
}
