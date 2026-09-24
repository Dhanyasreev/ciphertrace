export * from '../backend/src/types.js';

export interface ScanResponse {
  promptLength: number;
  detectionsCount: number;
  detections: import('../backend/src/types.js').DetectionResult[];
  presidioAvailable: boolean;
  performance: import('../backend/src/types.js').PerformanceMetrics;
}

export interface RedactResponse {
  originalLength: number;
  sanitizedText: string;
  detections: import('../backend/src/types.js').DetectionResult[];
  tokensCreated: import('../backend/src/types.js').SanitizedTokenRecord[];
  requestId: string;
  securityGate: import('../backend/src/types.js').SecurityGateResult;
  presidioAvailable: boolean;
  performance: import('../backend/src/types.js').PerformanceMetrics;
}

export type ChatResponse = import('../backend/src/types.js').SecureChatResponse;

export interface PresidioHealth {
  available: boolean;
  service: string;
  version?: string;
  latencyMs?: number;
}
