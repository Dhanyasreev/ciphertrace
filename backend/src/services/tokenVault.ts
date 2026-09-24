import { Redis } from '@upstash/redis';
import { getRedisClient } from './redisClient.js';
import { TokenRecord, SanitizedTokenRecord, DetectionType, Severity } from '../types.js';

const KEY_PREFIX = 'ciphertrace:vault:';
const INDEX_KEY = 'ciphertrace:vault:index';
export const DEFAULT_TTL_SECONDS = 300; // 5 minutes

class TokenVaultService {
  private memoryVault: Map<string, TokenRecord> = new Map();

  private get redis(): Redis | null {
    return getRedisClient();
  }

  private isRedisConfigured(): boolean {
    return this.redis !== null;
  }

  /**
   * Store a sensitive token record with Redis TTL.
   * Original value is kept isolated in the vault for quarantine audit.
   */
  async store(
    token: string,
    originalValue: string,
    maskedValue: string,
    type: DetectionType,
    requestId: string,
    severity: Severity = 'HIGH',
    ttlSeconds: number = DEFAULT_TTL_SECONDS,
    detectedBy?: string[]
  ): Promise<TokenRecord> {
    const now = Date.now();
    const expiresAt = now + ttlSeconds * 1000;

    const record: TokenRecord = {
      token,
      originalValue,
      maskedValue,
      type,
      requestId,
      createdAt: now,
      expiresAt,
      severity,
      revoked: false,
      detectedBy,
    };

    // Always update memory copy for safety and offline support
    // Store by both request-scoped compound key and token key
    if (requestId) {
      this.memoryVault.set(`${requestId}:${token}`, record);
    }
    this.memoryVault.set(token, record);

    if (this.redis) {
      try {
        const redisKey = `${KEY_PREFIX}${token}`;
        await this.redis.set(redisKey, JSON.stringify(record), { ex: ttlSeconds });
        if (requestId) {
          const reqScopedRedisKey = `${KEY_PREFIX}${requestId}:${token}`;
          await this.redis.set(reqScopedRedisKey, JSON.stringify(record), { ex: ttlSeconds });
        }
        await this.redis.sadd(INDEX_KEY, token);
      } catch (err) {
        console.warn('[TokenVault] Redis store error, fell back to in-memory store:', err);
      }
    }

    return record;
  }

  /**
   * Look up a token record for verification and quarantine audit.
   * Returns null if token does not exist, is expired, or was revoked.
   * If requestId is provided, enforces request scoping (token must belong to this requestId).
   */
  async lookup(token: string, requestId?: string): Promise<TokenRecord | null> {
    if (this.redis) {
      try {
        // First check request-scoped key if requestId is supplied
        if (requestId) {
          const reqScopedRedisKey = `${KEY_PREFIX}${requestId}:${token}`;
          const rawScoped = await this.redis.get<string | TokenRecord>(reqScopedRedisKey);
          if (rawScoped) {
            const record: TokenRecord = typeof rawScoped === 'string' ? JSON.parse(rawScoped) : rawScoped;
            if (!record.revoked && Date.now() <= record.expiresAt) {
              return record;
            }
          }
        }

        // Check standard token key
        const redisKey = `${KEY_PREFIX}${token}`;
        const raw = await this.redis.get<string | TokenRecord>(redisKey);
        if (raw) {
          const record: TokenRecord = typeof raw === 'string' ? JSON.parse(raw) : raw;
          if (record.revoked || Date.now() > record.expiresAt) {
            return null;
          }
          if (requestId && record.requestId && record.requestId !== requestId) {
            // Check in-memory before giving up
          } else {
            return record;
          }
        }
      } catch (err) {
        console.warn('[TokenVault] Redis lookup error, checking memory vault:', err);
      }
    }

    // Check request-scoped in-memory record first
    if (requestId) {
      const scopedMem = this.memoryVault.get(`${requestId}:${token}`);
      if (scopedMem && !scopedMem.revoked && Date.now() <= scopedMem.expiresAt) {
        return scopedMem;
      }
    }

    const memRecord = this.memoryVault.get(token);
    if (!memRecord) return null;
    if (memRecord.revoked || Date.now() > memRecord.expiresAt) {
      return null;
    }
    if (requestId && memRecord.requestId && memRecord.requestId !== requestId) {
      return null;
    }
    return memRecord;
  }

  /**
   * Revoke an active token so it is invalidated.
   */
  async revoke(token: string): Promise<boolean> {
    let success = false;
    const memRecord = this.memoryVault.get(token);
    if (memRecord) {
      memRecord.revoked = true;
      if (memRecord.requestId) {
        const scoped = this.memoryVault.get(`${memRecord.requestId}:${token}`);
        if (scoped) scoped.revoked = true;
      }
      success = true;
    }

    if (this.redis) {
      try {
        const redisKey = `${KEY_PREFIX}${token}`;
        const raw = await this.redis.get<string | TokenRecord>(redisKey);
        if (raw) {
          const record: TokenRecord = typeof raw === 'string' ? JSON.parse(raw) : raw;
          record.revoked = true;
          const ttlRemaining = Math.max(1, Math.round((record.expiresAt - Date.now()) / 1000));
          await this.redis.set(redisKey, JSON.stringify(record), { ex: ttlRemaining });
          if (record.requestId) {
            await this.redis.set(`${KEY_PREFIX}${record.requestId}:${token}`, JSON.stringify(record), { ex: ttlRemaining });
          }
          success = true;
        }
      } catch (err) {
        console.warn('[TokenVault] Redis revoke error:', err);
      }
    }

    return success;
  }

  /**
   * Purge expired tokens from indices.
   */
  async purgeExpired(): Promise<number> {
    let purged = 0;
    const now = Date.now();
    for (const [token, record] of this.memoryVault.entries()) {
      if (now > record.expiresAt) {
        this.memoryVault.delete(token);
        purged++;
      }
    }

    if (this.redis) {
      try {
        const tokens = await this.redis.smembers(INDEX_KEY);
        for (const token of tokens) {
          const exists = await this.redis.exists(`${KEY_PREFIX}${token}`);
          if (!exists) {
            await this.redis.srem(INDEX_KEY, token);
            purged++;
          }
        }
      } catch (err) {
        console.warn('[TokenVault] Redis purgeExpired error:', err);
      }
    }
    return purged;
  }

  /**
   * Inspection API list: NEVER includes originalValue!
   * Returns sanitized metadata for frontend vault inspection.
   */
  async getSanitizedList(): Promise<SanitizedTokenRecord[]> {
    const tokenMap = new Map<string, TokenRecord>();
    const now = Date.now();

    for (const [token, record] of this.memoryVault.entries()) {
      tokenMap.set(token, record);
    }

    if (this.redis) {
      try {
        const tokens = await this.redis.smembers(INDEX_KEY);
        for (const token of tokens) {
          const raw = await this.redis.get<string | TokenRecord>(`${KEY_PREFIX}${token}`);
          if (raw) {
            const record: TokenRecord = typeof raw === 'string' ? JSON.parse(raw) : raw;
            tokenMap.set(token, record);
          } else {
            await this.redis.srem(INDEX_KEY, token);
          }
        }
      } catch (err) {
        console.warn('[TokenVault] Redis getSanitizedList error:', err);
      }
    }

    const sanitizedList: SanitizedTokenRecord[] = [];
    for (const record of tokenMap.values()) {
      const isExpired = now > record.expiresAt || record.revoked;
      const ttlSecondsRemaining = isExpired ? 0 : Math.max(0, Math.round((record.expiresAt - now) / 1000));
      sanitizedList.push({
        token: record.token,
        maskedValue: record.maskedValue,
        type: record.type,
        requestId: record.requestId,
        createdAt: record.createdAt,
        expiresAt: record.expiresAt,
        ttlSecondsRemaining,
        isExpired,
        severity: record.severity,
        revoked: record.revoked,
        detectedBy: record.detectedBy,
      });
    }

    return sanitizedList.sort((a, b) => b.createdAt - a.createdAt);
  }

  /**
   * Aggregated stats for the security dashboard.
   */
  async getStats(): Promise<{ active: number; revoked: number; total: number; redisConnected: boolean }> {
    const list = await this.getSanitizedList();
    const active = list.filter(t => !t.isExpired && !t.revoked).length;
    const revoked = list.filter(t => t.revoked).length;
    return {
      active,
      revoked,
      total: list.length,
      redisConnected: this.isRedisConfigured(),
    };
  }

  /**
   * Clear all records (useful for test resets).
   */
  async clear(): Promise<void> {
    this.memoryVault.clear();
    if (this.redis) {
      try {
        const tokens = await this.redis.smembers(INDEX_KEY);
        for (const token of tokens) {
          await this.redis.del(`${KEY_PREFIX}${token}`);
        }
        await this.redis.del(INDEX_KEY);
      } catch (err) {
        console.warn('[TokenVault] Redis clear error:', err);
      }
    }
  }
}

export const TokenVault = new TokenVaultService();
