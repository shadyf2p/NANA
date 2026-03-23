import rateLimit from "express-rate-limit";
import { env } from "../config/env.js";

export const loginRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 15,
  standardHeaders: true,
  legacyHeaders: false,
  message: { message: "Too many login attempts. Please try again later." }
});

export const verifyRateLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: env.verifyRateLimitPerMinute,
  standardHeaders: true,
  legacyHeaders: false,
  message: { valid: false, message: "Rate limit exceeded for verification." }
});

