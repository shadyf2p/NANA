import { z } from "zod";

export const createKeySchema = z.object({
  expireAt: z.string().datetime(),
  prefix: z.string().trim().min(2).max(12).optional()
});

export const verifyKeySchema = z.object({
  key: z.string().trim().min(12).max(128),
  hwid: z.string().trim().min(6).max(128)
});

export const banKeySchema = z.object({
  key: z.string().trim().min(12).max(128)
});

export const deleteKeySchema = z.object({
  key: z.string().trim().min(12).max(128)
});

