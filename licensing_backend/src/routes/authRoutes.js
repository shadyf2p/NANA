import { Router } from "express";
import { loginAdmin } from "../controllers/authController.js";
import { validateBody } from "../middleware/validate.js";
import { loginRateLimiter } from "../middleware/rateLimiters.js";
import { loginSchema } from "../validators/authSchemas.js";

const router = Router();

router.post("/login", loginRateLimiter, validateBody(loginSchema), loginAdmin);

export default router;

