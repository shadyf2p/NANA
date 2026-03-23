import { z } from "zod";

export const loginSchema = z.object({
  username: z.string().trim().min(3).max(64),
  password: z.string().min(8).max(128)
});

