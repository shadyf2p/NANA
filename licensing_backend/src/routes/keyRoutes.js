import { Router } from "express";
import {
  banKey,
  createKey,
  listKeys,
  listLogs,
  removeKey,
  verifyKey
} from "../controllers/keyController.js";
import { requireAdminAuth } from "../middleware/authMiddleware.js";
import { validateBody } from "../middleware/validate.js";
import { verifyRateLimiter } from "../middleware/rateLimiters.js";
import {
  banKeySchema,
  createKeySchema,
  deleteKeySchema,
  verifyKeySchema
} from "../validators/keySchemas.js";

const router = Router();

router.post("/key/verify", verifyRateLimiter, validateBody(verifyKeySchema), verifyKey);
router.post("/key/create", requireAdminAuth, validateBody(createKeySchema), createKey);
router.post("/key/ban", requireAdminAuth, validateBody(banKeySchema), banKey);
router.post("/key/delete", requireAdminAuth, validateBody(deleteKeySchema), removeKey);
router.get("/key/list", requireAdminAuth, listKeys);
router.get("/logs/list", requireAdminAuth, listLogs);

export default router;

