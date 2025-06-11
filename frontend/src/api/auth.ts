import { openHands } from "./open-hands-axios";

export interface AuthStatus {
  authenticated: boolean;
  user_id?: string;
  email?: string;
  github_username?: string;
}

export interface GitHubAuthResponse {
  auth_url: string;
  state: string;
}

export interface OTPResponse {
  message: string;
  email: string;
}

export interface OTPVerificationResponse {
  message: string;
  user_id: string;
  email: string;
}

/**
 * Get current authentication status
 */
export async function getAuthStatus(): Promise<AuthStatus> {
  const response = await openHands.get("/api/auth/status");
  return response.data;
}

/**
 * Generate and send OTP to email
 */
export async function generateOTP(email: string): Promise<OTPResponse> {
  const response = await openHands.post("/api/auth/otp/generate", { email });
  return response.data;
}

/**
 * Verify OTP code
 */
export async function verifyOTP(
  email: string,
  code: string,
): Promise<OTPVerificationResponse> {
  const response = await openHands.post("/api/auth/otp/verify", {
    email,
    code,
  });
  return response.data;
}

/**
 * Get GitHub OAuth authorization URL
 */
export async function getGitHubAuthUrl(): Promise<GitHubAuthResponse> {
  const response = await openHands.get("/api/auth/github/url");
  return response.data;
}

/**
 * Logout current user
 */
export async function logout(): Promise<void> {
  await openHands.post("/api/auth/logout");
}
