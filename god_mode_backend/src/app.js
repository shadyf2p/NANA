import express from "express";
import helmet from "helmet";
import cors from "cors";
import { env } from "./config/env.js";
import authRoutes from "./routes/authRoutes.js";
import adminRoutes from "./routes/adminRoutes.js";
import verifyRoutes from "./routes/verifyRoutes.js";
import publicRoutes from "./routes/publicRoutes.js";
import { errorHandler, notFound } from "./middleware/error.js";

const app = express();
app.set("trust proxy", true);
app.use(helmet());
app.use(express.json({ limit: "64kb" }));

app.use(
  cors({
    origin(origin, callback) {
      if (!origin) return callback(null, true);
      if (env.corsOrigins.includes(origin)) return callback(null, true);
      return callback(new Error("CORS blocked"));
    }
  })
);

app.get("/health", (_req, res) => {
  res.json({ ok: true, service: "god_mode_backend" });
});

app.use("/api/auth", authRoutes);
app.use("/api/admin", adminRoutes);
app.use("/api", verifyRoutes);
app.use("/api/public", publicRoutes);

app.use(notFound);
app.use(errorHandler);

export default app;

