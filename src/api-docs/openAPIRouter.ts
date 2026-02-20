import express, { type Request, type Response, type Router } from "express";
import swaggerUi from "swagger-ui-express";

import { generateOpenAPIDocument } from "@/api-docs/openAPIDocumentGenerator";

export const openAPIRouter: Router = express.Router();
const openAPIDocument = generateOpenAPIDocument();

openAPIDocument.servers = [
  {
    url: "/api",
    description: "API Server",
  },
];

openAPIRouter.get("/swagger.json", (_req: Request, res: Response) => {
	res.setHeader("Content-Type", "application/json");
	res.send(openAPIDocument);
});

openAPIRouter.use(
  "/",
  swaggerUi.serve,
  swaggerUi.setup(openAPIDocument, {
    swaggerOptions: {
      persistAuthorization: true,
      requestInterceptor: (request: { loadSpec?: boolean; headers?: Record<string, string> }) => {
        if (request.loadSpec) {
          return request;
        }

        const token = typeof window !== "undefined" ? window.localStorage.getItem("swagger_access_token") : null;

        if (token && !request.headers?.Authorization && !request.headers?.authorization) {
          request.headers = {
            ...request.headers,
            Authorization: `Bearer ${token}`,
          };
        }

        return request;
      },
      responseInterceptor: (response: { url?: string; text?: string; body?: unknown; obj?: unknown }) => {
        try {
          const isLoginResponse = typeof response.url === "string" && /\/auth\/login(?:\?|$)/.test(response.url);
          if (!isLoginResponse) {
            return response;
          }

          const payload =
            typeof response.text === "string"
              ? JSON.parse(response.text)
              : ((response.body ?? response.obj) as Record<string, unknown> | undefined);

          const data = (payload as { data?: Record<string, unknown> } | undefined)?.data;
          const accessToken =
            (data?.accessToken as string | undefined) ??
            ((payload as { accessToken?: string } | undefined)?.accessToken ?? undefined);

          if (accessToken && typeof window !== "undefined") {
            window.localStorage.setItem("swagger_access_token", accessToken);
          }
        } catch {
          // no-op: keep Swagger response flow even if token extraction fails
        }

        return response;
      },
    },
  }),
);
