import app from "./app.js";
import { env } from "./config/env.js";
import { pool } from "./config/mysql.js";
import { redis } from "./config/redis.js";
import { ensureSeedAdmin } from "./services/bootstrapService.js";

async function boot() {
  try {
    await pool.query("SELECT 1");
    await redis.ping();
    await ensureSeedAdmin();
    app.listen(env.port, () => {
      console.log(`[BOOT] GOD MODE backend listening on :${env.port}`);
    });
  } catch (err) {
    console.error("[BOOT] Failed", err);
    process.exit(1);
  }
}

boot();

