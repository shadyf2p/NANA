import { Router } from "express";
import { banKey, createKey, getLogs, listKeys } from "../controllers/adminController.js";
import { requireAccessToken, requireRole } from "../middleware/auth.js";
import { validate } from "../middleware/validate.js";
import { banKeySchema, createKeySchema } from "../validators/adminSchemas.js";

const router = Router();

router.use(requireAccessToken);

router.post("/key/create", requireRole(["owner", "admin"]), validate(createKeySchema), createKey);
router.post("/key/ban", requireRole(["owner", "admin", "support"]), validate(banKeySchema), banKey);
router.get("/key/list", requireRole(["owner", "admin", "support", "viewer"]), listKeys);
router.get("/logs/list", requireRole(["owner", "admin", "support"]), getLogs);

export default router;

