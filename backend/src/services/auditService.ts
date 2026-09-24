import { AuditLogEntry, DetectionType, Severity } from '../types.js';

class AuditService {
  private logs: AuditLogEntry[] = [
    {
      id: 'aud-seed-001',
      timestamp: Date.now() - 3600000 * 2,
      userId: 'usr-test-001',
      userEmail: 'test@example.com',
      action: 'PROMPT_SECURITY_SCAN',
      promptLength: 142,
      detectionsCount: 2,
      detections: [
        { type: 'EMAIL', token: '[EMAIL_1]', severity: 'MEDIUM', confidence: 0.99, detectedBy: ['CipherTrace', 'Presidio'] },
        { type: 'API_KEY', token: '[API_KEY_1]', severity: 'HIGH', confidence: 0.98, detectedBy: ['CipherTrace'] },
      ],
      riskLevel: 'HIGH',
      status: 'REDACTED',
    },
    {
      id: 'aud-seed-002',
      timestamp: Date.now() - 3600000 * 4,
      userId: 'usr-test-001',
      userEmail: 'test@example.com',
      action: 'TOKEN_VAULT_INSPECTION',
      promptLength: 0,
      detectionsCount: 0,
      detections: [],
      riskLevel: 'LOW',
      status: 'ALLOWED',
    },
  ];

  public logEvent(entry: Omit<AuditLogEntry, 'id' | 'timestamp'>): AuditLogEntry {
    const newEntry: AuditLogEntry = {
      id: `aud-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`,
      timestamp: Date.now(),
      ...entry,
    };
    // Prepend and keep last 200 logs
    this.logs.unshift(newEntry);
    if (this.logs.length > 200) {
      this.logs.pop();
    }
    return newEntry;
  }

  public getLogs(): AuditLogEntry[] {
    return [...this.logs];
  }
}

export const auditService = new AuditService();
