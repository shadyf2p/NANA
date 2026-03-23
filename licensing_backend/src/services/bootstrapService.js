import bcrypt from "bcrypt";
import { env } from "../config/env.js";
import { createAdmin, findAdminByUsername } from "../models/adminModel.js";

export async function ensureSeedAdmin() {
  const username = env.seedAdminUsername;
  const existing = await findAdminByUsername(username);
  if (existing) return;

  const passwordHash = await bcrypt.hash(env.seedAdminPassword, 12);
  await createAdmin(username, passwordHash);
  console.log(`[BOOTSTRAP] Seed admin created: ${username}`);
}

