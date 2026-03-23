import { Router } from "express";
import { verify } from "../controllers/verifyController.js";
import { validate } from "../middleware/validate.js";
import { verifyEnvelopeSchema } from "../validators/verifySchemas.js";

const router = Router();

router.post("/key/verify", validate(verifyEnvelopeSchema), verify);

export default router;

