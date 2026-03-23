import { z } from "zod";

export const createKeySchema = z.object({
  licenseKeyPlain: z.string().trim().min(16).max(128),
  expireAt: z.string().datetime(),
  planCode: z.string().trim().min(3).max(32).default("basic")
});

export const banKeySchema = z.object({
  licenseKeyPlain: z.string().trim().min(16).max(128)
});

