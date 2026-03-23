import { redis } from "../config/redis.js";
import { env } from "../config/env.js";

export async function consumeNonceOnce(nonce) {
  const key = `nonce:verify:${nonce}`;
  const ok = await redis.set(key, "1", "EX", env.nonceTtlSeconds, "NX");
  return ok === "OK";
}

