import { Router } from "express";
import { dashboardLicenses, paymentWebhook } from "../controllers/paymentController.js";
import { validate } from "../middleware/validate.js";
import { paymentWebhookSchema } from "../validators/paymentSchemas.js";

const router = Router();

router.post("/payment/webhook", validate(paymentWebhookSchema), paymentWebhook);
router.get("/dashboard/licenses", dashboardLicenses);

export default router;

