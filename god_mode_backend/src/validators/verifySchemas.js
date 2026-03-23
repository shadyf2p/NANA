import { z } from "zod";

export const verifyEnvelopeSchema = z.object({
  kid: z.string().trim().min(1).max(32).optional().default("v1"),
  encrypted_payload: z.string().min(16).max(12000),
  timestamp: z.union([z.string(), z.number()]),
  nonce: z.string().min(8).max(128),
  signature: z.string().regex(/^[0-9a-f]{64}$/i)
});

