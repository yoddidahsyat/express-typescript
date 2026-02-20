import cookieParser from "cookie-parser";
import cors from "cors";
import express, { type Express } from "express";
import helmet from "helmet";
import { pino } from "pino";
import { healthCheckRouter } from "@/api/healthCheck/healthCheckRouter";
import { authRouter } from "@/api/routes/authRoute";
import { userRouter } from "@/api/routes/userRoute";
import { openAPIRouter } from "@/api-docs/openAPIRouter";
import errorHandler from "@/common/middleware/errorHandler";
import rateLimiter from "@/common/middleware/rateLimiter";
import requestLogger from "@/common/middleware/requestLogger";
import { env } from "@/common/utils/envConfig";

const logger = pino({ name: "server start" });
const app: Express = express();

// Set the application to trust the reverse proxy
app.set("trust proxy", true);

// Middlewares
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(cors({ origin: env.CORS_ORIGIN, credentials: true }));
app.use(
	helmet({
		contentSecurityPolicy: false,
	}),
);
app.use(rateLimiter);

// Request logging
app.use(requestLogger);

// Routes
const apiRouter = express.Router();
apiRouter.use("/health-check", healthCheckRouter);
apiRouter.use("/auth", authRouter);
apiRouter.use("/users", userRouter);

// Expose health-check at root for tests and local dev
app.use("/health-check", healthCheckRouter);

// API routes under /api
app.use("/api", apiRouter);

// Serve OpenAPI (Swagger UI) after API routes
app.use(openAPIRouter);

// Error handlers
app.use(errorHandler());

export { app, logger };
