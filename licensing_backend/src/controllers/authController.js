import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { env } from "../config/env.js";
import { findAdminByUsername } from "../models/adminModel.js";

export async function loginAdmin(req, res) {
  const { username, password } = req.body;
  const admin = await findAdminByUsername(username);

  if (!admin || Number(admin.is_active) !== 1) {
    return res.status(401).json({ message: "Invalid credentials" });
  }

  const isPasswordValid = await bcrypt.compare(password, admin.password_hash);
  if (!isPasswordValid) {
    return res.status(401).json({ message: "Invalid credentials" });
  }

  const token = jwt.sign(
    { username: admin.username },
    env.jwtSecret,
    {
      subject: String(admin.id),
      expiresIn: env.jwtExpiresIn
    }
  );

  return res.json({
    token,
    expiresIn: env.jwtExpiresIn
  });
}

