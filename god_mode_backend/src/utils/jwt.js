import jwt from "jsonwebtoken";
import { env } from "../config/env.js";

export function signAccessToken(admin) {
  return jwt.sign(
    { username: admin.username, role: admin.role },
    env.jwtAccessSecret,
    {
      subject: String(admin.id),
      expiresIn: env.jwtAccessExpires
    }
  );
}

export function signRefreshToken(admin) {
  return jwt.sign(
    { username: admin.username, role: admin.role, typ: "refresh" },
    env.jwtRefreshSecret,
    {
      subject: String(admin.id),
      expiresIn: env.jwtRefreshExpires
    }
  );
}

export function verifyRefreshToken(token) {
  return jwt.verify(token, env.jwtRefreshSecret);
}

