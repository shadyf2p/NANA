import Redis from "ioredis";
import { env } from "./env.js";

export const redis = new Redis(env.redisUrl, {
  maxRetriesPerRequest: 2,
  enableReadyCheck: true
});

