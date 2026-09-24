import { EmployeeProfile } from '../types.js';
import { Redis } from '@upstash/redis';
import { getRedisClient } from './redisClient.js';

const PROFILE_KEY_PREFIX = 'ciphertrace:profile:';

class ProfileService {
  private memoryProfiles: Map<string, EmployeeProfile> = new Map();

  private get redis(): Redis | null {
    return getRedisClient();
  }

  async getProfile(userId: string): Promise<EmployeeProfile | null> {
    if (this.redis) {
      try {
        const raw = await this.redis.get<string | EmployeeProfile>(`${PROFILE_KEY_PREFIX}${userId}`);
        if (raw) {
          const profile: EmployeeProfile = typeof raw === 'string' ? JSON.parse(raw) : raw;
          this.memoryProfiles.set(userId, profile);
          return profile;
        }
      } catch (err) {
        console.warn('[ProfileService] Redis getProfile error, falling back to memory:', err);
      }
    }
    return this.memoryProfiles.get(userId) || null;
  }

  async saveProfile(
    userId: string,
    data: {
      fullName: string;
      jobTitle: string;
      companyName: string;
      department: string;
      employeeId: string;
    }
  ): Promise<EmployeeProfile> {
    const existing = await this.getProfile(userId);
    const profile: EmployeeProfile = {
      userId,
      fullName: data.fullName.trim(),
      jobTitle: data.jobTitle.trim(),
      companyName: data.companyName.trim(),
      department: data.department.trim(),
      employeeId: data.employeeId.trim(),
      promptsScreened: existing ? existing.promptsScreened : 0,
      leaksMitigated: existing ? existing.leaksMitigated : 0,
      securityClearance: existing?.securityClearance || 'Level 3 - Enterprise Confidential',
      activePolicies: existing?.activePolicies || [
        'PII Redaction v2.4 + Presidio Engine',
        'Secret & Credential Masking',
        'Zero-Exposure Token Vault',
        'Zero-Leak Secret Sanitization',
      ],
    };

    this.memoryProfiles.set(userId, profile);

    if (this.redis) {
      try {
        await this.redis.set(`${PROFILE_KEY_PREFIX}${userId}`, JSON.stringify(profile));
      } catch (err) {
        console.warn('[ProfileService] Redis saveProfile error:', err);
      }
    }

    return profile;
  }

  async incrementStats(userId: string, prompts: number, leaks: number): Promise<void> {
    const profile = await this.getProfile(userId);
    if (profile) {
      profile.promptsScreened += prompts;
      profile.leaksMitigated += leaks;
      this.memoryProfiles.set(userId, profile);
      if (this.redis) {
        try {
          await this.redis.set(`${PROFILE_KEY_PREFIX}${userId}`, JSON.stringify(profile));
        } catch (err) {
          console.warn('[ProfileService] Redis updateStats error:', err);
        }
      }
    }
  }

  async hasProfile(userId: string): Promise<boolean> {
    const p = await this.getProfile(userId);
    return p !== null;
  }
}

export const profileService = new ProfileService();
