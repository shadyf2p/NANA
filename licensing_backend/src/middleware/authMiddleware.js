import jwt from "jsonwebtoken";
import { env } from "../config/env.js";

export function requireAdminAuth(req, res, next) {
  const authHeader = String(req.headers.authorization || "");
  if (!authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ message: "Missing Bearer token" });
  }

  const token = authHeader.slice("Bearer ".length).trim();
  try {
    const payload = jwt.verify(token, env.jwtSecret);
    req.admin = {
      id: payload.sub,
      username: payload.username
    };
    return next();
  } catch (_error) {
    return res.status(401).json({ message: "Invalid or expired token" });
  }
}

