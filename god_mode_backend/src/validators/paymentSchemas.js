import { z } from "zod";

export const paymentWebhookSchema = z.object({
  event_id: z.string().trim().min(6).max(128),
  provider: z.string().trim().min(2).max(32).default("generic"),
  event_type: z.string().trim().min(3).max(64),
  payment_ref: z.string().trim().max(128).optional().default(""),
  amount_cents: z.number().int().min(0).default(0),
  currency: z.string().trim().min(3).max(16).default("USD"),
  customer_email: z.string().trim().email(),
  customer_name: z.string().trim().max(120).optional().default(""),
  plan_code: z.string().trim().min(3).max(32).default("basic"),
  duration_days: z.number().int().min(1).max(3650).optional(),
  metadata: z.record(z.any()).optional().default({})
});

export const dashboardTokenSchema = z.object({
  token: z.string().trim().min(20).max(256)
});

