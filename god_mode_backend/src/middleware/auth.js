import jwt from "jsonwebtoken";
import { env } from "../config/env.js";

export function requireAccessToken(req, res, next) {
  const auth = String(req.headers.authorization || "");
  if (!auth.startsWith("Bearer ")) {
    return res.status(401).json({ message: "Missing access token" });
  }
  const token = auth.slice(7).trim();
  try {
    const payload = jwt.verify(token, env.jwtAccessSecret);
    req.admin = {
      id: Number(payload.sub),
      username: String(payload.username || ""),
      role: String(payload.role || "viewer")
    };
    return next();
  } catch (_err) {
    return res.status(401).json({ message: "Invalid access token" });
  }
}

export function requireRole(roles) {
  const allow = new Set(roles);
  return (req, res, next) => {
    const role = String(req.admin?.role || "");
    if (!allow.has(role)) {
      return res.status(403).json({ message: "Forbidden" });
    }
    return next();
  };
}

