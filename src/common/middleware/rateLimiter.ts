import { rateLimit, ipKeyGenerator } from "express-rate-limit";

import { env } from "@/common/utils/envConfig";
import { Request } from "express";

const rateLimiter = rateLimit({
	legacyHeaders: true,
	limit: env.COMMON_RATE_LIMIT_MAX_REQUESTS,
	message: "Too many requests, please try again later.",
	standardHeaders: true,
	windowMs: 15 * 60 * env.COMMON_RATE_LIMIT_WINDOW_MS,
	keyGenerator: (req: Request) => ipKeyGenerator(req.ip as string),
	skip: () => env.isDevelopment || env.isTest,
});

export default rateLimiter;
