import express from "express";
import cors from "cors";
import helmet from "helmet";
import { env } from "./config/env.js";
import authRoutes from "./routes/authRoutes.js";
import keyRoutes from "./routes/keyRoutes.js";
import { errorHandler, notFoundHandler } from "./middleware/errorHandler.js";

const app = express();

app.set("trust proxy", true);
app.use(helmet());
app.use(express.json({ limit: "64kb" }));
app.use(
  cors({
    origin(origin, callback) {
      if (!origin) return callback(null, true);
      if (env.corsOrigins.includes(origin)) return callback(null, true);
      return callback(new Error("Blocked by CORS"));
    }
  })
);

app.get("/health", (_req, res) => {
  res.json({ ok: true, service: "mmo-licensing-backend" });
});

app.use("/api", authRoutes);
app.use("/api", keyRoutes);

app.use(notFoundHandler);
app.use(errorHandler);

export default app;

