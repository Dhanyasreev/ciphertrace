import { DetectionResult, DetectionType, Severity } from '../types.js';

export interface PresidioRawResult {
  entity: string;
  text: string;
  start: number;
  end: number;
  score: number;
}

export interface PresidioHealthResponse {
  available: boolean;
  service: string;
  version?: string;
  latencyMs?: number;
}

export class PresidioService {
  private static readonly PRESIDIO_API_URL = process.env.PRESIDIO_API_URL || 'http://127.0.0.1:5001';
  private static readonly REQUEST_TIMEOUT_MS = 2500;

  private static readonly STOPWORDS = new Set([
    'NAME', 'CUSTOMER', 'AUTHOR', 'SUPERVISOR', 'PERSON', 'CLIENT',
    'API', 'KEY', 'SECRET', 'SECRET KEY', 'AWS', 'AWS SECRET KEY',
    'SUITE', 'OFFICE', 'DATACENTER', 'PORT', 'SERVER', 'PASSWD', 'SHADOW',
    'DATABASE', 'URL', 'BEARER', 'TOKEN', 'AUTHORIZATION', 'PASSWORD',
    'USER', 'ADMIN', 'ROOT', 'NULL', 'UNDEFINED', 'TRUE', 'FALSE'
  ]);

  private static cleanSpan(text: string, startIndex: number, endIndex: number): { start: number; end: number; value: string } | null {
    let start = Math.max(0, Math.min(text.length, startIndex));
    let end = Math.max(0, Math.min(text.length, endIndex));
    if (start >= end) return null;

    while (start < end) {
      const ch = text[start];
      if (ch === '(' && text.slice(start, end).includes(')')) {
        break;
      }
      if (/[\s\r\n\t"'`\[{<:,]/.test(ch) || ch === '(') {
        start++;
      } else {
        break;
      }
    }

    while (end > start) {
      const ch = text[end - 1];
      if (ch === ')' && text.slice(start, end).includes('(')) {
        break;
      }
      if (/[\s\r\n\t.,;:!?"'`)}\]>)]/.test(ch)) {
        end--;
      } else {
        break;
      }
    }

    if (start >= end) return null;
    const value = text.slice(start, end);
    if (!value || value.length === 0) return null;
    return { start, end, value };
  }

  /**
   * Normalizes Presidio entity types into CipherTrace DetectionType.
   * Contextual evidence is used for DATE_TIME -> DATE_OF_BIRTH conversion.
   */
  public static normalizeEntityType(entity: string, detectedValue: string, fullText: string, start: number, end: number): { type: DetectionType; severity: Severity } | null {
    const upper = (entity || '').toUpperCase();
    switch (upper) {
      case 'ORGANIZATION':
        return null;
      case 'PERSON':
        return { type: 'PERSON', severity: 'MEDIUM' };
      case 'EMAIL_ADDRESS':
      case 'EMAIL':
        return { type: 'EMAIL', severity: 'MEDIUM' };
      case 'PHONE_NUMBER':
      case 'PHONE':
        return { type: 'PHONE', severity: 'MEDIUM' };
      case 'CREDIT_CARD':
        return { type: 'CREDIT_CARD', severity: 'CRITICAL' };
      case 'IP_ADDRESS': {
        // Distinguish IPv4 vs IPv6 if discernible
        if (detectedValue.includes(':')) {
          return { type: 'IPV6', severity: 'LOW' };
        }
        if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(detectedValue)) {
          return { type: 'IPV4', severity: 'LOW' };
        }
        return { type: 'IP_ADDRESS', severity: 'LOW' };
      }
      case 'LOCATION':
        return { type: 'ADDRESS', severity: 'MEDIUM' };
      case 'DATE_TIME': {
        // Inspect surrounding context (35 chars before and after) for DOB evidence
        const contextStart = Math.max(0, start - 35);
        const contextEnd = Math.min(fullText.length, end + 35);
        const context = fullText.slice(contextStart, contextEnd).toLowerCase();
        const hasDobContext = /\b(dob|birth|born|birthday|date\s*of\s*birth)\b/i.test(context);
        if (hasDobContext) {
          return { type: 'DATE_OF_BIRTH', severity: 'HIGH' };
        }
        return null;
      }
      case 'US_SSN':
      case 'SSN':
        return { type: 'SSN', severity: 'CRITICAL' };
      case 'IBAN_CODE':
      case 'IBAN':
        return { type: 'IBAN', severity: 'HIGH' };
      case 'URL': {
        const trimmed = detectedValue.trim();
        // Disallow code invocations or method/property accesses like requests.get, response.json, console.log
        if (!/^(?:https?:\/\/|ftp:\/\/|www\.)/i.test(trimmed)) {
          const after = fullText.slice(end).trimStart();
          if (after.startsWith('(')) return null;
          if (/^[a-zA-Z_][a-zA-Z0-9_]*\.[a-zA-Z_][a-zA-Z0-9_]*$/.test(trimmed)) {
            return null;
          }
        }
        return { type: 'URL', severity: 'LOW' };
      }
      case 'US_PASSPORT':
      case 'PASSPORT':
        return { type: 'PASSPORT', severity: 'HIGH' };
      case 'US_DRIVER_LICENSE':
      case 'DRIVER_LICENSE':
        return { type: 'DRIVER_LICENSE', severity: 'HIGH' };
      case 'US_BANK_NUMBER':
      case 'BANK_NUMBER':
      case 'BANK_ACCOUNT':
        return { type: 'BANK_ACCOUNT', severity: 'HIGH' };
      case 'CRYPTO':
        return { type: 'CRYPTO_WALLET', severity: 'HIGH' };
      case 'NRP':
      case 'NATIONAL_ID':
        return { type: 'NATIONAL_ID', severity: 'HIGH' };
      default:
        return null;
    }
  }

  /**
   * Communicates with local Python Presidio API service to analyze text.
   * Returns CipherTrace formatted DetectionResult[] array.
   * If service is unavailable or errors, returns [] without throwing.
   */
  public static async analyze(text: string, language: string = 'en'): Promise<DetectionResult[]> {
    if (!text || typeof text !== 'string' || text.trim().length === 0) {
      return [];
    }

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), PresidioService.REQUEST_TIMEOUT_MS);

    try {
      const response = await fetch(`${PresidioService.PRESIDIO_API_URL}/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text, language }),
        signal: controller.signal,
      });
      clearTimeout(timeoutId);

      if (!response.ok) {
        return [];
      }

      const data = await response.json() as { results?: PresidioRawResult[] };
      const rawResults = Array.isArray(data?.results) ? data.results : [];
      const detections: DetectionResult[] = [];

      for (const r of rawResults) {
        if (typeof r.start !== 'number' || typeof r.end !== 'number' || r.start >= r.end) {
          continue;
        }

        const cleaned = PresidioService.cleanSpan(text, r.start, r.end);
        if (!cleaned) continue;

        let { start, end, value: detectedValue } = cleaned;

        // Check word boundary: if the detection cuts off inside an alphanumeric word
        if (end < text.length && /[a-zA-Z0-9_]/.test(text[end - 1]) && /[a-zA-Z0-9_]/.test(text[end])) {
          continue;
        }
        if (start > 0 && /[a-zA-Z0-9_]/.test(text[start - 1]) && /[a-zA-Z0-9_]/.test(text[start])) {
          continue;
        }

        // Skip stopwords / labels mistaken for entities
        if (PresidioService.STOPWORDS.has(detectedValue.toUpperCase())) {
          continue;
        }

        // If entity is PERSON and starts with common labels like "Customer ", "Author ", strip it
        if ((r.entity === 'PERSON' || r.entity === 'PERSON_NAME') && /^(?:Customer|Author|Supervisor|Name|Person)[ \t]+([A-Z][a-z]+)/i.test(detectedValue)) {
          const matchPrefix = /^(?:Customer|Author|Supervisor|Name|Person)[ \t]+/i.exec(detectedValue);
          if (matchPrefix) {
            start += matchPrefix[0].length;
            detectedValue = detectedValue.slice(matchPrefix[0].length);
          }
        }

        const postClean = PresidioService.cleanSpan(text, start, end);
        if (!postClean) continue;
        start = postClean.start;
        end = postClean.end;
        detectedValue = postClean.value;

        if (PresidioService.STOPWORDS.has(detectedValue.toUpperCase())) {
          continue;
        }

        // If LOCATION is a Unix file path like /etc/passwd or /var/log, ignore as address
        if (r.entity === 'LOCATION' && /^\/(?:etc|var|usr|bin|proc|dev|tmp)/.test(detectedValue)) {
          continue;
        }

        // Filter false positive PERSON entities that are technical labels/infrastructure terms
        if ((r.entity === 'PERSON' || r.entity === 'PERSON_NAME') && /\b(?:database|cache|log|report|audit|server|config|cluster|auth|system|host|port|route|suite|office|datacenter|header|parameter|input|output|primary|secondary|redis|postgres|mysql|mongo|token|key|secret)\b/i.test(detectedValue)) {
          continue;
        }

        const norm = PresidioService.normalizeEntityType(
          r.entity,
          detectedValue,
          text,
          start,
          end
        );

        if (!norm) {
          continue;
        }

        const { type, severity } = norm;
        const upToStart = text.slice(0, start);
        const line = (upToStart.match(/\n/g) || []).length + 1;
        const lastNl = upToStart.lastIndexOf('\n');
        const column = lastNl === -1 ? start + 1 : start - lastNl;

        detections.push({
          type,
          value: detectedValue,
          index: start,
          length: detectedValue.length,
          startIndex: start,
          endIndex: end,
          line,
          column,
          location: `line ${line}, col ${column}`,
          severity,
          confidence: Math.min(1.0, Math.max(0.1, Number(r.score) || 0.85)),
          description: `Microsoft Presidio detected ${r.entity}`,
          detectedBy: ['Presidio'],
          detectors: ['Presidio'],
        });
      }

      return detections;
    } catch {
      clearTimeout(timeoutId);
      return [];
    }
  }

  /**
   * Health check for GET /api/system/presidio/health
   */
  public static async checkHealth(): Promise<PresidioHealthResponse> {
    const startTime = Date.now();
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 1500);

    try {
      const response = await fetch(`${PresidioService.PRESIDIO_API_URL}/health`, {
        method: 'GET',
        signal: controller.signal,
      });
      clearTimeout(timeoutId);
      const latencyMs = Date.now() - startTime;

      if (response.ok) {
        const data = await response.json().catch(() => ({}));
        return {
          available: true,
          service: 'Microsoft Presidio',
          version: data.version || '2.2.35',
          latencyMs,
        };
      }
      return {
        available: false,
        service: 'Microsoft Presidio',
      };
    } catch {
      clearTimeout(timeoutId);
      return {
        available: false,
        service: 'Microsoft Presidio',
      };
    }
  }
}
