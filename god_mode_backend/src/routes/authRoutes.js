import { Router } from "express";
import { login, logout, refresh } from "../controllers/authController.js";
import { validate } from "../middleware/validate.js";
import { loginSchema, refreshSchema } from "../validators/authSchemas.js";

const router = Router();

router.post("/login", validate(loginSchema), login);
router.post("/refresh", validate(refreshSchema), refresh);
router.post("/logout", validate(refreshSchema), logout);

export default router;

