import { Redis } from '@upstash/redis';

/**
 * Clean environment variables that may have been pasted with variable names, quotes, or whitespace.
 */
export function cleanEnvVar(val: string | undefined, varName?: string): string | undefined {
  if (!val) return undefined;
  let cleaned = String(val).trim();
  cleaned = cleaned.replace(/^["']+|["']+$/g, '').trim();
  if (varName) {
    const prefixRegex = new RegExp(`^${varName}\\s*[:=]\\s*`, 'i');
    cleaned = cleaned.replace(prefixRegex, '').trim();
  }
  cleaned = cleaned.replace(/^[A-Z0-9_]+\s*[:=]\s*/i, '').trim();
  cleaned = cleaned.replace(/^["']+|["']+$/g, '').trim();
  return cleaned || undefined;
}

/**
 * Clean and normalize Upstash Redis REST URL.
 */
export function cleanRedisUrl(rawUrl: string | undefined): string | undefined {
  const cleaned = cleanEnvVar(rawUrl, 'UPSTASH_REDIS_REST_URL');
  if (!cleaned) return undefined;
  let urlCandidate = cleaned;
  if (!/^https?:\/\//i.test(urlCandidate)) {
    urlCandidate = `https://${urlCandidate}`;
  }
  try {
    const parsed = new URL(urlCandidate);
    if (!parsed.protocol.startsWith('http')) {
      return undefined;
    }
    return parsed.origin;
  } catch {
    return undefined;
  }
}

let redisInstance: Redis | null = null;
let initialized = false;

/**
 * Get or initialize the shared Upstash Redis client.
 */
export function getRedisClient(): Redis | null {
  if (initialized) {
    return redisInstance;
  }
  initialized = true;

  const rawUrl = process.env.UPSTASH_REDIS_REST_URL;
  const rawToken = process.env.UPSTASH_REDIS_REST_TOKEN;

  const url = cleanRedisUrl(rawUrl);
  const token = cleanEnvVar(rawToken, 'UPSTASH_REDIS_REST_TOKEN');

  if (!url || !token || token.trim() === '' || token.includes('***')) {
    console.warn('[RedisClient] Redis URL or token not configured, using in-memory store.');
    redisInstance = null;
    return null;
  }

  try {
    redisInstance = new Redis({ url, token });
    console.log(`[RedisClient] Upstash Redis client successfully initialized for ${url}`);
  } catch (err) {
    console.warn('[RedisClient] Failed to initialize Upstash Redis client, using in-memory store:', err);
    redisInstance = null;
  }

  return redisInstance;
}
