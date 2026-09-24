import { SecurityMetrics } from '../types.js';
import { TokenVault } from './tokenVault.js';

class MetricsService {
  private promptsScreened = 18;
  private leaksMitigated = 27;
  private criticalDetections = 4;
  private highDetections = 14;
  private mediumDetections = 8;
  private lowDetections = 1;
  private presidioAvailable = true;

  public setPresidioAvailable(available: boolean) {
    this.presidioAvailable = available;
  }

  public recordScan(
    detectionsCount: number,
    severities: { critical: number; high: number; medium: number; low: number }
  ) {
    this.promptsScreened += 1;
    this.leaksMitigated += detectionsCount;
    this.criticalDetections += severities.critical;
    this.highDetections += severities.high;
    this.mediumDetections += severities.medium;
    this.lowDetections += severities.low;
  }

  public async getMetrics(): Promise<SecurityMetrics> {
    const vaultStats = await TokenVault.getStats();
    return {
      promptsScreened: this.promptsScreened,
      leaksMitigated: this.leaksMitigated,
      activeTokensCount: vaultStats.active,
      criticalDetections: this.criticalDetections,
      highDetections: this.highDetections,
      mediumDetections: this.mediumDetections,
      lowDetections: this.lowDetections,
      presidioAvailable: this.presidioAvailable,
    };
  }
}

export const metricsService = new MetricsService();
