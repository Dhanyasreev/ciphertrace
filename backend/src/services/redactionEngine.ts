import { SensitiveDataScanner } from './sensitiveDataScanner.js';
import { TokenVault } from './tokenVault.js';
import { DetectionResult, SanitizedTokenRecord, SecurityGateResult, PerformanceMetrics } from '../types.js';

export interface RedactionResult {
  originalLength: number;
  sanitizedText: string;
  detections: DetectionResult[];
  tokensCreated: SanitizedTokenRecord[];
  requestId: string;
  securityGate: SecurityGateResult;
  presidioAvailable: boolean;
  performance: PerformanceMetrics;
}

export class RedactionEngine {
  private static readonly MAX_VALIDATION_PASSES = 3;

  /**
   * Scan and redact sensitive information using merged CipherTrace + Microsoft Presidio detection.
   * Runs second-pass security validation to guarantee zero sensitive data remains.
   * Measures detailed performance metrics across all phases.
   *
   * IMPORTANT ARCHITECTURAL DIRECTIVE:
   * Redaction MUST NOT repair or modify the user's code syntax.
   * It only replaces sensitive span values with placeholder tokens (e.g. [API_KEY_1]).
   */
  public static async redact(text: string, requestId?: string): Promise<RedactionResult> {
    const processStart = Date.now();
    const reqId = requestId || `req-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;

    if (!text || typeof text !== 'string') {
      return {
        originalLength: 0,
        sanitizedText: '',
        detections: [],
        tokensCreated: [],
        requestId: reqId,
        securityGate: { safe: true, remainingDetections: [] },
        presidioAvailable: false,
        performance: {
          cipherTraceDetectionTimeMs: 0,
          presidioDetectionTimeMs: 0,
          mergeTimeMs: 0,
          redactionTimeMs: 0,
          validationTimeMs: 0,
          totalDetectionTimeMs: 0,
          totalProcessingTimeMs: 0,
        },
      };
    }

    const typeCounters = new Map<string, number>();
    const allDetections: DetectionResult[] = [];
    const allTokensCreated: SanitizedTokenRecord[] = [];
    let currentText = text;
    let passes = 0;

    let cipherTraceTimeTotal = 0;
    let presidioTimeTotal = 0;
    let mergeTimeTotal = 0;
    let redactionTimeTotal = 0;
    let validationTimeTotal = 0;
    let presidioAvailable = false;

    // Phase 1: Dual-engine scan (CipherTrace + Presidio) on original text
    const scanResult = await SensitiveDataScanner.scanMerged(text);
    cipherTraceTimeTotal += scanResult.performance.cipherTraceDetectionTimeMs;
    presidioTimeTotal += scanResult.performance.presidioDetectionTimeMs;
    mergeTimeTotal += scanResult.performance.mergeTimeMs;
    if (scanResult.presidioAvailable) {
      presidioAvailable = true;
    }

    // Filter out matches that are already placeholder tokens
    const realDetections = scanResult.detections.filter(
      d => !SensitiveDataScanner.isPlaceholderToken(d.value)
    );

    // Phase 2: Redaction replacement
    const redactStart = Date.now();
    const replacements: {
      start: number;
      end: number;
      token: string;
      originalValue: string;
      detection: DetectionResult;
    }[] = [];

    for (const det of realDetections) {
      const currentCount = (typeCounters.get(det.type) || 0) + 1;
      typeCounters.set(det.type, currentCount);
      const tokenName = `[${det.type}_${currentCount}]`;

      replacements.push({
        start: det.startIndex,
        end: det.endIndex,
        token: tokenName,
        originalValue: det.value,
        detection: det,
      });
    }

    // Sort replacements descending by start position to ensure indexes remain strictly valid
    replacements.sort((a, b) => b.start - a.start);

    for (const r of replacements) {
      currentText = currentText.slice(0, r.start) + r.token + currentText.slice(r.end);
      const masked = SensitiveDataScanner.maskValue(r.originalValue, r.detection.type);

      // Store in ephemeral TokenVault (300s TTL)
      const stored = await TokenVault.store(
        r.token,
        r.originalValue,
        masked,
        r.detection.type,
        reqId,
        r.detection.severity,
        300,
        r.detection.detectedBy
      );

      allTokensCreated.push({
        token: stored.token,
        maskedValue: stored.maskedValue,
        type: stored.type,
        requestId: stored.requestId,
        createdAt: stored.createdAt,
        expiresAt: stored.expiresAt,
        ttlSecondsRemaining: Math.max(0, Math.round((stored.expiresAt - Date.now()) / 1000)),
        isExpired: false,
        severity: stored.severity,
        revoked: false,
        detectedBy: stored.detectedBy,
      });
    }

    allDetections.push(...realDetections);
    redactionTimeTotal += (Date.now() - redactStart);

    // Phase 3: Second-pass security validation scan
    const valStart = Date.now();
    let securityGate = SensitiveDataScanner.validateNoSensitiveDataRemains(currentText);

    // If any unredacted item remained, perform targeted second-pass redaction on remaining detections
    if (!securityGate.safe && securityGate.remainingDetections && securityGate.remainingDetections.length > 0 && passes < RedactionEngine.MAX_VALIDATION_PASSES) {
      passes++;
      const secondaryDetections = securityGate.remainingDetections.filter(
        (d: DetectionResult) => !SensitiveDataScanner.isPlaceholderToken(d.value)
      );

      if (secondaryDetections.length > 0) {
        const secReplacements: {
          start: number;
          end: number;
          token: string;
          originalValue: string;
          detection: DetectionResult;
        }[] = [];

        for (const det of secondaryDetections) {
          const currentCount = (typeCounters.get(det.type) || 0) + 1;
          typeCounters.set(det.type, currentCount);
          const tokenName = `[${det.type}_${currentCount}]`;

          secReplacements.push({
            start: det.startIndex,
            end: det.endIndex,
            token: tokenName,
            originalValue: det.value,
            detection: det,
          });
        }

        secReplacements.sort((a, b) => b.start - a.start);

        for (const r of secReplacements) {
          currentText = currentText.slice(0, r.start) + r.token + currentText.slice(r.end);
          const masked = SensitiveDataScanner.maskValue(r.originalValue, r.detection.type);
          const stored = await TokenVault.store(
            r.token,
            r.originalValue,
            masked,
            r.detection.type,
            reqId,
            r.detection.severity,
            300,
            r.detection.detectedBy
          );

          allTokensCreated.push({
            token: stored.token,
            maskedValue: stored.maskedValue,
            type: stored.type,
            requestId: stored.requestId,
            createdAt: stored.createdAt,
            expiresAt: stored.expiresAt,
            ttlSecondsRemaining: Math.max(0, Math.round((stored.expiresAt - Date.now()) / 1000)),
            isExpired: false,
            severity: stored.severity,
            revoked: false,
            detectedBy: stored.detectedBy,
          });

          allDetections.push(r.detection);
        }

        securityGate = SensitiveDataScanner.validateNoSensitiveDataRemains(currentText);
      }
    }
    validationTimeTotal += (Date.now() - valStart);

    const totalDetectionTimeMs = cipherTraceTimeTotal + presidioTimeTotal + mergeTimeTotal;
    const totalProcessingTimeMs = Date.now() - processStart;

    return {
      originalLength: text.length,
      sanitizedText: currentText,
      detections: allDetections,
      tokensCreated: allTokensCreated,
      requestId: reqId,
      securityGate,
      presidioAvailable,
      performance: {
        cipherTraceDetectionTimeMs: cipherTraceTimeTotal,
        presidioDetectionTimeMs: presidioTimeTotal,
        mergeTimeMs: mergeTimeTotal,
        redactionTimeMs: redactionTimeTotal,
        validationTimeMs: validationTimeTotal,
        totalDetectionTimeMs,
        totalProcessingTimeMs,
      },
    };
  }

  /**
   * Directly validate that no sensitive data remains in sanitized text.
   */
  public static validateNoSensitiveDataRemains(sanitizedText: string): SecurityGateResult {
    return SensitiveDataScanner.validateNoSensitiveDataRemains(sanitizedText);
  }
}
