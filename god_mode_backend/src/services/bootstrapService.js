import bcrypt from "bcrypt";
import { env } from "../config/env.js";
import { createAdmin, getAdminByUsername } from "../models/adminModel.js";

export async function ensureSeedAdmin() {
  const existing = await getAdminByUsername(env.seedAdminUsername);
  if (existing) return;
  const hash = await bcrypt.hash(env.seedAdminPassword, 12);
  await createAdmin({
    username: env.seedAdminUsername,
    passwordHash: hash,
    role: env.seedAdminRole
  });
  console.log(`[BOOT] Seed admin created: ${env.seedAdminUsername}`);
}

