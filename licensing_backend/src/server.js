import app from "./app.js";
import { env } from "./config/env.js";
import { ensureSeedAdmin } from "./services/bootstrapService.js";
import { dbPool } from "./config/db.js";

async function startServer() {
  try {
    await dbPool.query("SELECT 1");
    await ensureSeedAdmin();

    app.listen(env.port, () => {
      console.log(`[SERVER] Licensing backend running on port ${env.port}`);
    });
  } catch (error) {
    console.error("[BOOT] Failed to start server", error);
    process.exit(1);
  }
}

startServer();

