import type { Request, RequestHandler, Response } from "express";
import type { TokenPayload } from "@/api/auth/authModel";

import { AuthService } from "@/api/auth/authService";
import { UserService } from "../user/userService";

class AuthController {
	private authService: AuthService;
  private userService: UserService;

	constructor() {
		this.authService = new AuthService();
		this.userService = new UserService();
	}

	/**
	 * Set refresh token as httpOnly cookie
	 */
	private setRefreshTokenCookie(res: Response, refreshToken: string): void {
		res.cookie("refreshToken", refreshToken, {
			httpOnly: true,
			secure: process.env.NODE_ENV === "production",
			sameSite: "strict",
			maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
		});
	}

	/**
	 * Clear refresh token cookie
	 */
	private clearRefreshTokenCookie(res: Response): void {
		res.clearCookie("refreshToken", {
			httpOnly: true,
			secure: process.env.NODE_ENV === "production",
			sameSite: "strict",
		});
	}

	/**
	 * Register new user
	 */
	public register: RequestHandler = async (req: Request, res: Response) => {
		const { email, password, name } = req.body;
		const serviceResponse = await this.authService.registerAsync(email, password, name);
		res.status(serviceResponse.statusCode).send(serviceResponse);
	};

	/**
	 * Login user
	 */
	public login: RequestHandler = async (req: Request, res: Response) => {
		const { email, password } = req.body;
		const serviceResponse = await this.authService.loginAsync(email, password);

		if (serviceResponse.success && serviceResponse.data) {
			// Set refresh token in httpOnly cookie
			this.setRefreshTokenCookie(res, serviceResponse.data.refreshToken);

			// Return response without refresh token (only accessToken)
			const responseData = {
				success: serviceResponse.success,
				message: serviceResponse.message,
				data: {
					user: serviceResponse.data.user,
					accessToken: serviceResponse.data.accessToken,
				},
				statusCode: serviceResponse.statusCode,
			};
			res.status(serviceResponse.statusCode).send(responseData);
		} else {
			res.status(serviceResponse.statusCode).send(serviceResponse);
		}
	};

	/**
	 * Refresh access token using refresh token from cookies
	 */
	public refresh: RequestHandler = async (req: Request, res: Response) => {
		const refreshToken = req.cookies.refreshToken;

		if (!refreshToken) {
			res.status(401).send({
				success: false,
				message: "Refresh token not found",
				data: null,
				statusCode: 401,
			});
			return;
		}

		const serviceResponse = await this.authService.refreshTokenAsync(refreshToken);

		if (serviceResponse.success && serviceResponse.data) {
			// Set new refresh token in httpOnly cookie
			this.setRefreshTokenCookie(res, serviceResponse.data.refreshToken);

			// Return response without refresh token (only accessToken)
			const responseData = {
				success: serviceResponse.success,
				message: serviceResponse.message,
				data: {
					accessToken: serviceResponse.data.accessToken,
				},
				statusCode: serviceResponse.statusCode,
			};
			res.status(serviceResponse.statusCode).send(responseData);
		} else {
			res.status(serviceResponse.statusCode).send(serviceResponse);
		}
	};

	/**
	 * Logout user
	 */
	public logout: RequestHandler = async (req: Request, res: Response) => {
		const userId = (req.user as { userId: number }).userId;
		const serviceResponse = await this.authService.logoutAsync(userId);

		if (serviceResponse.success) {
			this.clearRefreshTokenCookie(res);
		}

		res.status(serviceResponse.statusCode).send(serviceResponse);
	};

	/**
	 * Get current authenticated user
	 */
	public me: RequestHandler = async (req: Request, res: Response) => {
		const userId = (req.user as TokenPayload).userId;
		const serviceResponse = await this.authService.getCurrentUserAsync(userId);
		res.status(serviceResponse.statusCode).send(serviceResponse);
	};

  public updateProfile: RequestHandler = async (req: Request, res: Response) => {
    const userData = req.body;
    const userId = (req.user as TokenPayload).userId;
    const serviceResponse = await this.userService.updateUser(userId, userData);
    res.status(serviceResponse.statusCode).send(serviceResponse);
  }
}

export const authController = new AuthController();
