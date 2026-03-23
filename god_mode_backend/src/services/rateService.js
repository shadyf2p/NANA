import { redis } from "../config/redis.js";

export async function hitRateLimit({ scope, key, windowSeconds, max }) {
  const bucket = Math.floor(Date.now() / (windowSeconds * 1000));
  const redisKey = `rl:${scope}:${key}:${bucket}`;
  const current = await redis.incr(redisKey);
  if (current === 1) {
    await redis.expire(redisKey, windowSeconds + 2);
  }
  return { limited: current > max, current };
}

export async function readRateWindowCount({ scope, key, windowSeconds }) {
  const bucket = Math.floor(Date.now() / (windowSeconds * 1000));
  const redisKey = `rl:${scope}:${key}:${bucket}`;
  const raw = await redis.get(redisKey);
  return Number(raw || 0);
}

export async function incrementFailureCounter({ dim, key, windowSeconds }) {
  const redisKey = `vf:${dim}:${key}`;
  const current = await redis.incr(redisKey);
  if (current === 1) {
    await redis.expire(redisKey, windowSeconds);
  }
  return current;
}

export async function getFailureCounter({ dim, key }) {
  const redisKey = `vf:${dim}:${key}`;
  const raw = await redis.get(redisKey);
  return Number(raw || 0);
}

