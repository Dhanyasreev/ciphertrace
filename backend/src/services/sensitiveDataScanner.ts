import { DetectionResult, DetectionType, Severity, SecurityGateResult, PerformanceMetrics } from '../types.js';
import { PresidioService } from './presidioService.js';

interface RawDetection {
  type: DetectionType;
  value: string;
  startIndex: number;
  endIndex: number;
  severity: Severity;
  confidence: number;
  description: string;
  priority: number;
  detectedBy: string[];
}

const SEVERITY_WEIGHTS: Record<Severity, number> = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
};

export class SensitiveDataScanner {
  private static readonly NON_SECRET_KEYWORDS = new Set([
    'bearer',
    'basic',
    'digest',
    'ntlm',
    'negotiate',
    'oauth',
    'token',
    'authorization',
    'requests',
    'timeout',
    'api_key',
    'apikey',
    'secret',
    'password',
    'credential',
    'true',
    'false',
    'null',
    'undefined',
    'none',
    'headers',
    'status_code',
  ]);

  /**
   * Helper to check if a value is a standard keyword or scheme rather than a secret
   */
  public static isNonSecretKeyword(val: string): boolean {
    if (!val) return false;
    const trimmed = val.trim().toLowerCase();
    if (SensitiveDataScanner.NON_SECRET_KEYWORDS.has(trimmed)) {
      return true;
    }
    // Also check if it's just 'bearer ' with whitespace
    if (/^bearer\s*$/i.test(val) || /^basic\s*$/i.test(val) || /^token\s*$/i.test(val)) {
      return true;
    }
    return false;
  }

  /**
   * Helper to check if a span is an existing placeholder token like [EMAIL_1] or [API_KEY_2]
   */
  public static isPlaceholderToken(text: string): boolean {
    return /^\[[A-Z0-9_]+_\d+\]$/.test(text.trim());
  }

  /**
   * Universal span trimmer and sanitizer.
   * Ensures that detection bounds never swallow sentence punctuation, trailing newlines, or outer brackets,
   * completely preventing word merging during redaction and tokenization.
   */
  public static cleanSpan(text: string, startIndex: number, endIndex: number): { start: number; end: number; value: string } | null {
    let start = Math.max(0, Math.min(text.length, startIndex));
    let end = Math.max(0, Math.min(text.length, endIndex));
    if (start >= end) return null;

    // Trim leading whitespace and surrounding quotes/delimiters
    while (start < end) {
      const ch = text[start];
      // Do not strip '(' if it has a matching ')' within the span (e.g. phone area code (555) 345-9876)
      if (ch === '(' && text.slice(start, end).includes(')')) {
        break;
      }
      if (/[\s\r\n\t"'`\[{<:,]/.test(ch) || ch === '(') {
        start++;
      } else {
        break;
      }
    }

    // Trim trailing whitespace and sentence-ending punctuation
    while (end > start) {
      const ch = text[end - 1];
      // Do not strip ')' if it closes a balanced '(' within the span
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
   * Synchronous pure CipherTrace rules engine detector.
   */
  public static scanCipherTrace(text: string): DetectionResult[] {
    if (!text || typeof text !== 'string') {
      return [];
    }

    const rawCandidates: RawDetection[] = [];

    // Find all already-existing placeholder tokens to ensure we NEVER treat placeholders as sensitive data
    const placeholderRanges: { start: number; end: number }[] = [];
    const placeholderRegex = /\[[A-Z0-9_]+_\d+\]/g;
    let phMatch: RegExpExecArray | null;
    while ((phMatch = placeholderRegex.exec(text)) !== null) {
      placeholderRanges.push({ start: phMatch.index, end: phMatch.index + phMatch[0].length });
    }

    const isInsidePlaceholder = (start: number, end: number): boolean => {
      return placeholderRanges.some(p => !(end <= p.start || start >= p.end));
    };

    const addCandidate = (cand: Omit<RawDetection, 'detectedBy'> & { detectedBy?: string[] }) => {
      const cleaned = SensitiveDataScanner.cleanSpan(text, cand.startIndex, cand.endIndex);
      if (!cleaned) return;
      if (SensitiveDataScanner.isPlaceholderToken(cleaned.value)) return;
      if (SensitiveDataScanner.isNonSecretKeyword(cleaned.value)) return;
      if (isInsidePlaceholder(cleaned.start, cleaned.end)) return;

      rawCandidates.push({
        ...cand,
        value: cleaned.value,
        startIndex: cleaned.start,
        endIndex: cleaned.end,
        detectedBy: cand.detectedBy || ['CipherTrace'],
      });
    };

    let match: RegExpExecArray | null;

    // 1. INJECTIONS & ATTACKS
    const cmdInjLabeled = /(?:Command\s*Injection(?:\s*Test)?)\s*[:=]\s*([^\r\n]+)/gi;
    while ((match = cmdInjLabeled.exec(text)) !== null) {
      const full = match[0];
      const rawVal = match[1];
      const val = rawVal.trim();
      const valStart = match.index + full.indexOf(rawVal) + rawVal.indexOf(val);
      addCandidate({
        type: 'COMMAND_INJECTION',
        value: val,
        startIndex: valStart,
        endIndex: valStart + val.length,
        severity: 'CRITICAL',
        confidence: 0.99,
        description: 'Command Injection Payload',
        priority: 100,
      });
    }

    const sqlInjLabeled = /(?:SQL\s*Injection(?:\s*Test)?)\s*[:=]\s*([^\r\n]+)/gi;
    while ((match = sqlInjLabeled.exec(text)) !== null) {
      const full = match[0];
      const rawVal = match[1];
      const val = rawVal.trim();
      const valStart = match.index + full.indexOf(rawVal) + rawVal.indexOf(val);
      addCandidate({
        type: 'SQL_INJECTION',
        value: val,
        startIndex: valStart,
        endIndex: valStart + val.length,
        severity: 'CRITICAL',
        confidence: 0.99,
        description: 'SQL Injection Payload',
        priority: 100,
      });
    }

    const sqlPattern = /\b(?:admin'|'\s*OR\s*'1'='1|\bOR\s+1=1\b|\bUNION\s+(?:ALL\s+)?SELECT\b)/gi;
    while ((match = sqlPattern.exec(text)) !== null) {
      addCandidate({
        type: 'SQL_INJECTION',
        value: match[0],
        startIndex: match.index,
        endIndex: match.index + match[0].length,
        severity: 'CRITICAL',
        confidence: 0.95,
        description: 'SQL Injection Signature',
        priority: 95,
      });
    }

    // 2. CRYPTOGRAPHIC KEYS & CERTIFICATES
    const privKeyRegex = /-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY-----[\s\S]*?-----END\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY-----/g;
    while ((match = privKeyRegex.exec(text)) !== null) {
      addCandidate({
        type: 'PRIVATE_KEY',
        value: match[0],
        startIndex: match.index,
        endIndex: match.index + match[0].length,
        severity: 'CRITICAL',
        confidence: 1.0,
        description: 'Private Key Block',
        priority: 95,
      });
    }

    // 3. DATABASE & REDIS CONNECTION STRINGS
    const dbUrlRegex = /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis(?:s)?|cockroachdb|mariadb|mssql|amqp(?:s)?):\/\/[^\s"'`<>]+(?:\/[^\s"'`<>]*)?/gi;
    while ((match = dbUrlRegex.exec(text)) !== null) {
      const url = match[0];
      const isRedis = url.startsWith('redis:') || url.startsWith('rediss:');
      addCandidate({
        type: isRedis ? 'REDIS_URL' : 'DATABASE_URL',
        value: url,
        startIndex: match.index,
        endIndex: match.index + url.length,
        severity: 'CRITICAL',
        confidence: 0.99,
        description: isRedis ? 'Redis Connection String with Credentials' : 'Database Connection URI with Credentials',
        priority: 90,
      });
    }

    // 4. CREDENTIALS & SECRETS
    // Google API Key
    const googleLabeledPattern = /(?:Google\s*API\s*Key)\s*[:=]\s*["']?([A-Za-z0-9_-]{20,})["']?/gi;
    while ((match = googleLabeledPattern.exec(text)) !== null) {
      const full = match[0];
      const val = match[1];
      const valStart = match.index + full.indexOf(val);
      addCandidate({
        type: 'GOOGLE_API_KEY',
        value: val,
        startIndex: valStart,
        endIndex: valStart + val.length,
        severity: 'HIGH',
        confidence: 0.99,
        description: 'Google Cloud / AI API Key',
        priority: 88,
      });
    }

    const googleKeyPattern = /\b(AIza[0-9A-Za-z-_]{35})\b/g;
    while ((match = googleKeyPattern.exec(text)) !== null) {
      addCandidate({
        type: 'GOOGLE_API_KEY',
        value: match[1],
        startIndex: match.index,
        endIndex: match.index + match[1].length,
        severity: 'HIGH',
        confidence: 0.99,
        description: 'Google Cloud / Maps API Key',
        priority: 88,
      });
    }

    // AWS Access Key ID
    const awsAccessLabeled = /(?:AWS\s*Access\s*Key(?:\s*ID)?)\s*[:=]\s*["']?([A-Za-z0-9_-]{16,32})["']?/gi;
    while ((match = awsAccessLabeled.exec(text)) !== null) {
      const full = match[0];
      const val = match[1];
      const valStart = match.index + full.indexOf(val);
      addCandidate({
        type: 'AWS_ACCESS_KEY',
        value: val,
        startIndex: valStart,
        endIndex: valStart + val.length,
        severity: 'HIGH',
        confidence: 0.99,
        description: 'AWS Access Key ID',
        priority: 88,
      });
    }

    const awsAccessPattern = /\b(AKIA[0-9A-Z]{12,28})\b/g;
    while ((match = awsAccessPattern.exec(text)) !== null) {
      addCandidate({
        type: 'AWS_ACCESS_KEY',
        value: match[1],
        startIndex: match.index,
        endIndex: match.index + match[1].length,
        severity: 'HIGH',
        confidence: 0.99,
        description: 'AWS Access Key ID',
        priority: 88,
      });
    }

    // AWS Secret Key labeled
    const awsSecretPattern = /(?:AWS\s*Secret(?:\s*Access)?\s*Key|aws_secret_access_key|aws_secret_key)\s*[:=]\s*["']?([A-Za-z0-9/+=_-]{16,64})["']?/gi;
    while ((match = awsSecretPattern.exec(text)) !== null) {
      const full = match[0];
      const val = match[1];
      const valStart = match.index + full.indexOf(val);
      addCandidate({
        type: 'AWS_SECRET_KEY',
        value: val,
        startIndex: valStart,
        endIndex: valStart + val.length,
        severity: 'CRITICAL',
        confidence: 0.96,
        description: 'AWS Secret Access Key',
        priority: 88,
      });
    }

    // GitHub Token
    const ghTokenPattern = /\b(gh[pousr]_[A-Za-z0-9_]{36,255}|github_pat_[A-Za-z0-9_]{22,})\b/g;
    while ((match = ghTokenPattern.exec(text)) !== null) {
      addCandidate({
        type: 'GITHUB_TOKEN',
        value: match[1],
        startIndex: match.index,
        endIndex: match.index + match[1].length,
        severity: 'HIGH',
        confidence: 0.99,
        description: 'GitHub Access Token',
        priority: 85,
      });
    }

    // JWT Token
    const jwtPattern = /\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b/g;
    while ((match = jwtPattern.exec(text)) !== null) {
      addCandidate({
        type: 'JWT',
        value: match[1],
        startIndex: match.index,
        endIndex: match.index + match[1].length,
        severity: 'HIGH',
        confidence: 0.98,
        description: 'JSON Web Token (JWT)',
        priority: 85,
      });
    }

    // Bearer Token
    const bearerPattern = /(?:Authorization|auth)\s*[:=]\s*Bearer\s+([A-Za-z0-9_.-]{12,})/gi;
    while ((match = bearerPattern.exec(text)) !== null) {
      const full = match[0];
      const val = match[1];
      const valStart = match.index + full.lastIndexOf(val);
      addCandidate({
        type: 'BEARER_TOKEN',
        value: val,
        startIndex: valStart,
        endIndex: valStart + val.length,
        severity: 'CRITICAL',
        confidence: 0.98,
        description: 'Bearer Authorization Token',
        priority: 87,
      });
    }

    // JWT Secret
    const jwtSecretPattern = /(?:JWT\s*Secret|jwt_secret)\s*[:=]\s*["']?([^\s"']{8,64})["']?/gi;
    while ((match = jwtSecretPattern.exec(text)) !== null) {
      const full = match[0];
      const val = match[1];
      const valStart = match.index + full.indexOf(val);
      addCandidate({
        type: 'JWT_SECRET',
        value: val,
        startIndex: valStart,
        endIndex: valStart + val.length,
        severity: 'CRITICAL',
        confidence: 0.95,
        description: 'JWT Signing Secret',
        priority: 88,
      });
    }

    // Password
    const passwordPattern = /(?:Password|passwd|pwd)\s*[:=]\s*["']?([^\s"']{4,64})["']?/gi;
    while ((match = passwordPattern.exec(text)) !== null) {
      const full = match[0];
      const val = match[1];
      const valStart = match.index + full.indexOf(val);
      addCandidate({
        type: 'PASSWORD',
        value: val,
        startIndex: valStart,
        endIndex: valStart + val.length,
        severity: 'CRITICAL',
        confidence: 0.95,
        description: 'Plaintext Password',
        priority: 82,
      });
    }

    // Generic API Key
    const apiKeyLabeled = /(?<!Google\s+)\b(?:API\s*Key|apikey|api_key|client_secret|clientSecret)\s*[:=]\s*["']?([A-Za-z0-9_.-]{10,80})["']?/gi;
    while ((match = apiKeyLabeled.exec(text)) !== null) {
      const full = match[0];
      const val = match[1];
      const valStart = match.index + full.indexOf(val);
      addCandidate({
        type: 'API_KEY',
        value: val,
        startIndex: valStart,
        endIndex: valStart + val.length,
        severity: 'HIGH',
        confidence: 0.95,
        description: 'API Key / Secret Token',
        priority: 80,
      });
    }

    // Standalone sk_... or sk-... keys (Stripe, OpenAI, etc.)
    const skKeyPattern = /\b(sk_(?:test|live)_[A-Za-z0-9_]{8,}|sk-[a-zA-Z0-9_-]{8,})\b/g;
    while ((match = skKeyPattern.exec(text)) !== null) {
      addCandidate({
        type: 'API_KEY',
        value: match[1],
        startIndex: match.index,
        endIndex: match.index + match[1].length,
        severity: 'HIGH',
        confidence: 0.98,
        description: 'API Key / Secret Token',
        priority: 82,
      });
    }

    // Code Variable Assignments (Python, JavaScript, TypeScript, Go, Java, C#, PHP, Shell, etc.)
    const codeAssignPattern = /(?:(?:const|let|var|val|final|String|export|\$)\s+)?([A-Za-z0-9_]+)\s*(?::=|=)\s*["']([^"']+)["']/g;
    while ((match = codeAssignPattern.exec(text)) !== null) {
      const varName = match[1].toUpperCase();
      const val = match[2];
      const full = match[0];
      const valStart = match.index + full.indexOf(val);
      if (val.length >= 4 && !SensitiveDataScanner.isNonSecretKeyword(val)) {
        if (varName.includes('DB') || varName.includes('DATABASE')) {
          addCandidate({
            type: 'DATABASE_URL',
            value: val,
            startIndex: valStart,
            endIndex: valStart + val.length,
            severity: 'CRITICAL',
            confidence: 0.99,
            description: 'Code-embedded Database URL',
            priority: 86,
          });
        } else if (varName.includes('PASS')) {
          addCandidate({
            type: 'PASSWORD',
            value: val,
            startIndex: valStart,
            endIndex: valStart + val.length,
            severity: 'CRITICAL',
            confidence: 0.95,
            description: 'Code-embedded Password',
            priority: 83,
          });
        } else if (varName.includes('KEY') || varName.includes('TOKEN') || varName.includes('SECRET') || varName.includes('AUTH') || varName.includes('CREDENTIAL') || varName.includes('API')) {
          addCandidate({
            type: 'API_KEY',
            value: val,
            startIndex: valStart,
            endIndex: valStart + val.length,
            severity: 'HIGH',
            confidence: 0.95,
            description: 'Code-embedded API Secret',
            priority: 83,
          });
        }
      }
    }

    // Code Dictionary / Config / JSON Key-Values (e.g. "api_key": "...", headers={"Authorization": "..."})
    const dictAssignPattern = /["']?([A-Za-z0-9_]*(?:KEY|SECRET|TOKEN|PASS(?:WORD)?|CREDENTIAL|AUTH|DATABASE|DB_URL)[A-Za-z0-9_]*)["']?\s*:\s*["']([^"']+)["']/gi;
    while ((match = dictAssignPattern.exec(text)) !== null) {
      const keyName = match[1].toUpperCase();
      const val = match[2];
      const full = match[0];
      const valStart = match.index + full.lastIndexOf(val);
      if (val.length >= 4 && !SensitiveDataScanner.isNonSecretKeyword(val)) {
        if (keyName.includes('PASS')) {
          addCandidate({
            type: 'PASSWORD',
            value: val,
            startIndex: valStart,
            endIndex: valStart + val.length,
            severity: 'CRITICAL',
            confidence: 0.95,
            description: 'Config-embedded Password',
            priority: 83,
          });
        } else {
          addCandidate({
            type: 'API_KEY',
            value: val,
            startIndex: valStart,
            endIndex: valStart + val.length,
            severity: 'HIGH',
            confidence: 0.95,
            description: 'Config-embedded Secret / Key',
            priority: 83,
          });
        }
      }
    }

    // 5. PII & IDENTIFIERS
    // Person Name labeled: Name: Rahul Sharma, Author: Rahul Sharma
    const nameLabeled = /(?:Name|Full[ \t]*Name|Person|Customer[ \t]*Name|Author|Supervisor)[ \t]*[:=][ \t]*([A-Z][a-z]+(?:[ \t]+[A-Z][a-z]+)+)/g;
    while ((match = nameLabeled.exec(text)) !== null) {
      const full = match[0];
      const rawVal = match[1];
      const val = rawVal.trim();
      const valStart = match.index + full.indexOf(rawVal) + rawVal.indexOf(val);
      addCandidate({
        type: 'PERSON_NAME',
        value: val,
        startIndex: valStart,
        endIndex: valStart + val.length,
        severity: 'MEDIUM',
        confidence: 0.9,
        description: 'Person Name',
        priority: 72,
      });
    }

    // Physical Address Labeled
    const addressLabeled = /(?:Office[ \t]*Address|Billing[ \t]*Address|Shipping[ \t]*Address|Street[ \t]*Address|Address)[ \t]*[:=][ \t]*([^\r\n]+)/gi;
    while ((match = addressLabeled.exec(text)) !== null) {
      const full = match[0];
      const rawVal = match[1];
      const val = rawVal.trim();
      const valStart = match.index + full.indexOf(rawVal) + rawVal.indexOf(val);
      addCandidate({
        type: 'ADDRESS',
        value: val,
        startIndex: valStart,
        endIndex: valStart + val.length,
        severity: 'MEDIUM',
        confidence: 0.95,
        description: 'Physical Street Address',
        priority: 73,
      });
    }

    // Date of Birth
    const dobLabeled = /(?:Date[ \t]*of[ \t]*Birth|DOB|Birthdate)[ \t]*[:=][ \t]*([0-9]{1,2}[/-][0-9]{1,2}[/-][0-9]{2,4}|[0-9]{4}[/-][0-9]{1,2}[/-][0-9]{1,2})/gi;
    while ((match = dobLabeled.exec(text)) !== null) {
      const full = match[0];
      const rawVal = match[1];
      const val = rawVal.trim();
      const valStart = match.index + full.indexOf(rawVal) + rawVal.indexOf(val);
      addCandidate({
        type: 'DATE_OF_BIRTH',
        value: val,
        startIndex: valStart,
        endIndex: valStart + val.length,
        severity: 'HIGH',
        confidence: 0.95,
        description: 'Date of Birth (DOB)',
        priority: 76,
      });
    }

    // User ID & Username
    const userIdLabeled = /(?:User[ \t]*ID|user_id|userId|Username|username)[ \t]*[:=][ \t]*["']?([A-Za-z0-9_.-]{4,32})["']?/gi;
    while ((match = userIdLabeled.exec(text)) !== null) {
      const full = match[0];
      const rawVal = match[1];
      const val = rawVal.trim();
      const valStart = match.index + full.indexOf(rawVal) + rawVal.indexOf(val);
      addCandidate({
        type: 'USER_ID',
        value: val,
        startIndex: valStart,
        endIndex: valStart + val.length,
        severity: 'MEDIUM',
        confidence: 0.92,
        description: 'User Identifier / Username',
        priority: 74,
      });
    }

    // Account Number
    const accNumLabeled = /(?:Account[ \t]*Number|account_number|acc_no|acc_num)[ \t]*[:=][ \t]*["']?([A-Za-z0-9_-]{6,32})["']?/gi;
    while ((match = accNumLabeled.exec(text)) !== null) {
      const full = match[0];
      const rawVal = match[1];
      const val = rawVal.trim();
      const valStart = match.index + full.indexOf(rawVal) + rawVal.indexOf(val);
      addCandidate({
        type: 'ACCOUNT_NUMBER',
        value: val,
        startIndex: valStart,
        endIndex: valStart + val.length,
        severity: 'HIGH',
        confidence: 0.95,
        description: 'Account Number Identifier',
        priority: 74,
      });
    }

    // Employee ID
    const empIdLabeled = /(?:Employee[ \t]*ID|employee_id|emp_id)[ \t]*[:=][ \t]*["']?([A-Za-z0-9_-]{4,32})["']?/gi;
    while ((match = empIdLabeled.exec(text)) !== null) {
      const full = match[0];
      const rawVal = match[1];
      const val = rawVal.trim();
      const valStart = match.index + full.indexOf(rawVal) + rawVal.indexOf(val);
      addCandidate({
        type: 'EMPLOYEE_ID',
        value: val,
        startIndex: valStart,
        endIndex: valStart + val.length,
        severity: 'MEDIUM',
        confidence: 0.95,
        description: 'Employee Identifier',
        priority: 74,
      });
    }

    // Customer ID
    const custIdLabeled = /(?:Customer[ \t]*ID|customer_id|cust_id)[ \t]*[:=][ \t]*["']?([A-Za-z0-9_-]{4,32})["']?/gi;
    while ((match = custIdLabeled.exec(text)) !== null) {
      const full = match[0];
      const rawVal = match[1];
      const val = rawVal.trim();
      const valStart = match.index + full.indexOf(rawVal) + rawVal.indexOf(val);
      addCandidate({
        type: 'CUSTOMER_ID',
        value: val,
        startIndex: valStart,
        endIndex: valStart + val.length,
        severity: 'MEDIUM',
        confidence: 0.95,
        description: 'Customer Identifier',
        priority: 74,
      });
    }

    // Standalone IDs (EMP-..., ACC-..., CUST-...)
    const standaloneIds = /\b(EMP-\d{4}-\d{3,5}|EMP-[A-Z0-9]{3,8}|ACC-[A-Z0-9_-]{4,16}|CUST-[A-Z0-9_-]{4,16})\b/g;
    while ((match = standaloneIds.exec(text)) !== null) {
      const val = match[1];
      const type: DetectionType = val.startsWith('EMP-')
        ? 'EMPLOYEE_ID'
        : val.startsWith('CUST-')
        ? 'CUSTOMER_ID'
        : 'ACCOUNT_NUMBER';
      addCandidate({
        type,
        value: val,
        startIndex: match.index,
        endIndex: match.index + val.length,
        severity: 'MEDIUM',
        confidence: 0.9,
        description: `${type.replace('_', ' ')} Identifier`,
        priority: 70,
      });
    }

    // Email Address
    const emailPattern = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;
    while ((match = emailPattern.exec(text)) !== null) {
      addCandidate({
        type: 'EMAIL',
        value: match[0],
        startIndex: match.index,
        endIndex: match.index + match[0].length,
        severity: 'MEDIUM',
        confidence: 0.99,
        description: 'Email Address',
        priority: 65,
      });
    }

    // Phone Number
    const phoneLabeled = /(?:Phone(?:\s*Number)?|Mobile|Cell)[ \t]*[:=][ \t]*([+\d ().-]{7,25})/gi;
    while ((match = phoneLabeled.exec(text)) !== null) {
      const full = match[0];
      const rawVal = match[1];
      const val = rawVal.trim();
      const valStart = match.index + full.indexOf(rawVal) + rawVal.indexOf(val);
      const digitsCount = (val.match(/\d/g) || []).length;
      if (digitsCount >= 7) {
        addCandidate({
          type: 'PHONE',
          value: val,
          startIndex: valStart,
          endIndex: valStart + val.length,
          severity: 'MEDIUM',
          confidence: 0.95,
          description: 'Phone / Mobile Number',
          priority: 66,
        });
      }
    }

    const phoneStandalone = /(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g;
    while ((match = phoneStandalone.exec(text)) !== null) {
      if (!match[0].includes('/') && (match[0].match(/\d/g) || []).length >= 10) {
        addCandidate({
          type: 'PHONE',
          value: match[0],
          startIndex: match.index,
          endIndex: match.index + match[0].length,
          severity: 'MEDIUM',
          confidence: 0.85,
          description: 'Phone / Mobile Number',
          priority: 60,
        });
      }
    }

    // Passport
    const passportLabeled = /(?:Passport(?:[ \t]*Number)?)[ \t]*[:=][ \t]*["']?([A-Z0-9]{6,12})["']?/gi;
    while ((match = passportLabeled.exec(text)) !== null) {
      const full = match[0];
      const rawVal = match[1];
      const val = rawVal.trim();
      const valStart = match.index + full.indexOf(rawVal) + rawVal.indexOf(val);
      addCandidate({
        type: 'PASSPORT',
        value: val,
        startIndex: valStart,
        endIndex: valStart + val.length,
        severity: 'HIGH',
        confidence: 0.95,
        description: 'Passport Number',
        priority: 77,
      });
    }

    // National ID / SSN
    const nationalIdLabeled = /(?:National[ \t]*ID|National[ \t]*Identity)[ \t]*[:=][ \t]*["']?([A-Za-z0-9_-]{6,20})["']?/gi;
    while ((match = nationalIdLabeled.exec(text)) !== null) {
      const full = match[0];
      const rawVal = match[1];
      const val = rawVal.trim();
      const valStart = match.index + full.indexOf(rawVal) + rawVal.indexOf(val);
      addCandidate({
        type: 'NATIONAL_ID',
        value: val,
        startIndex: valStart,
        endIndex: valStart + val.length,
        severity: 'HIGH',
        confidence: 0.95,
        description: 'National Identification Document',
        priority: 77,
      });
    }

    const ssnPattern = /\b\d{3}-\d{2}-\d{4}\b/g;
    while ((match = ssnPattern.exec(text)) !== null) {
      addCandidate({
        type: 'SSN',
        value: match[0],
        startIndex: match.index,
        endIndex: match.index + match[0].length,
        severity: 'CRITICAL',
        confidence: 0.99,
        description: 'US Social Security Number (SSN)',
        priority: 84,
      });
    }

    // 6. FINANCIAL
    // Credit Card (Spaced or dashed formatted: 4111 1111 1111 5678)
    const ccSpacedPattern = /\b(?:4[0-9]{3}[ -][0-9]{4}[ -][0-9]{4}[ -][0-9]{1,4}|5[1-5][0-9]{2}[ -][0-9]{4}[ -][0-9]{4}[ -][0-9]{4}|3[47][0-9]{2}[ -][0-9]{6}[ -][0-9]{5}|6(?:011|5[0-9]{2})[ -][0-9]{4}[ -][0-9]{4}[ -][0-9]{4})\b/g;
    while ((match = ccSpacedPattern.exec(text)) !== null) {
      addCandidate({
        type: 'CREDIT_CARD',
        value: match[0],
        startIndex: match.index,
        endIndex: match.index + match[0].length,
        severity: 'CRITICAL',
        confidence: 0.99,
        description: 'Payment Card Number',
        priority: 88,
      });
    }

    // Credit Card (contiguous digits)
    const ccPattern = /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12})\b/g;
    while ((match = ccPattern.exec(text)) !== null) {
      addCandidate({
        type: 'CREDIT_CARD',
        value: match[0],
        startIndex: match.index,
        endIndex: match.index + match[0].length,
        severity: 'CRITICAL',
        confidence: 0.99,
        description: 'Payment Card Number',
        priority: 85,
      });
    }

    // CVV
    const cvvLabeled = /(?:CVV|CVC|Security[ \t]*Code)[ \t]*[:=][ \t]*["']?(\d{3,4})["']?/gi;
    while ((match = cvvLabeled.exec(text)) !== null) {
      const full = match[0];
      const rawVal = match[1];
      const val = rawVal.trim();
      const valStart = match.index + full.indexOf(rawVal) + rawVal.indexOf(val);
      addCandidate({
        type: 'CVV',
        value: val,
        startIndex: valStart,
        endIndex: valStart + val.length,
        severity: 'CRITICAL',
        confidence: 0.95,
        description: 'Card Verification Value (CVV)',
        priority: 85,
      });
    }

    // Bank Account
    const bankAccLabeled = /(?:Bank[ \t]*Account(?:[ \t]*Number)?|account_number)[ \t]*[:=][ \t]*["']?(\d{9,18})["']?/gi;
    while ((match = bankAccLabeled.exec(text)) !== null) {
      const full = match[0];
      const rawVal = match[1];
      const val = rawVal.trim();
      const valStart = match.index + full.indexOf(rawVal) + rawVal.indexOf(val);
      addCandidate({
        type: 'BANK_ACCOUNT',
        value: val,
        startIndex: valStart,
        endIndex: valStart + val.length,
        severity: 'HIGH',
        confidence: 0.95,
        description: 'Bank Account Number',
        priority: 80,
      });
    }

    // IFSC Code
    const ifscPattern = /\b([A-Z]{4}0[A-Z0-9]{6})\b/g;
    while ((match = ifscPattern.exec(text)) !== null) {
      addCandidate({
        type: 'IFSC',
        value: match[1],
        startIndex: match.index,
        endIndex: match.index + match[1].length,
        severity: 'HIGH',
        confidence: 0.95,
        description: 'Indian Financial System Code (IFSC)',
        priority: 78,
      });
    }

    // IBAN
    const ibanPattern = /\b([A-Z]{2}\d{2}[A-Z0-9]{12,30})\b/g;
    while ((match = ibanPattern.exec(text)) !== null) {
      addCandidate({
        type: 'IBAN',
        value: match[1],
        startIndex: match.index,
        endIndex: match.index + match[1].length,
        severity: 'HIGH',
        confidence: 0.95,
        description: 'International Bank Account Number (IBAN)',
        priority: 79,
      });
    }

    // Aadhaar & PAN
    const aadhaarPattern = /\b([2-9]\d{3}[ ]\d{4}[ ]\d{4})\b/g;
    while ((match = aadhaarPattern.exec(text)) !== null) {
      addCandidate({
        type: 'AADHAAR',
        value: match[1],
        startIndex: match.index,
        endIndex: match.index + match[1].length,
        severity: 'HIGH',
        confidence: 0.9,
        description: 'Indian Aadhaar Identification Number',
        priority: 75,
      });
    }

    const panPattern = /\b([A-Z]{5}[0-9]{4}[A-Z]{1})\b/g;
    while ((match = panPattern.exec(text)) !== null) {
      addCandidate({
        type: 'PAN',
        value: match[1],
        startIndex: match.index,
        endIndex: match.index + match[1].length,
        severity: 'HIGH',
        confidence: 0.92,
        description: 'Indian Permanent Account Number (PAN)',
        priority: 75,
      });
    }

    // 7. LOCATION & NETWORK
    // GPS Coordinates
    const gpsLabeled = /(?:GPS\s*Coordinates|Coordinates|GPS|Location)\s*[:=]\s*["']?([-+]?\d{1,3}\.\d+,\s*[-+]?\d{1,3}\.\d+)["']?/gi;
    while ((match = gpsLabeled.exec(text)) !== null) {
      const full = match[0];
      const val = match[1].trim();
      const valStart = match.index + full.indexOf(match[1]);
      addCandidate({
        type: 'GPS_COORDINATES',
        value: val,
        startIndex: valStart,
        endIndex: valStart + val.length,
        severity: 'LOW',
        confidence: 0.98,
        description: 'Geographic GPS Coordinates',
        priority: 70,
      });
    }

    const gpsStandalone = /[-+]?([1-8]?\d(?:\.\d{3,})|90(?:\.0{3,})),\s*[-+]?(180(?:\.0{3,})|((?:1[0-7]\d)|(?:[1-9]?\d))(?:\.\d{3,}))/g;
    while ((match = gpsStandalone.exec(text)) !== null) {
      addCandidate({
        type: 'GPS_COORDINATES',
        value: match[0],
        startIndex: match.index,
        endIndex: match.index + match[0].length,
        severity: 'LOW',
        confidence: 0.9,
        description: 'Geographic GPS Coordinates',
        priority: 68,
      });
    }

    // IPv6
    const ipv6Labeled = /(?:IPv6)\s*[:=]\s*([0-9a-fA-F:]{3,45})/gi;
    while ((match = ipv6Labeled.exec(text)) !== null) {
      const full = match[0];
      const val = match[1].trim();
      const valStart = match.index + full.indexOf(match[1]);
      if ((val.match(/:/g) || []).length >= 2) {
        addCandidate({
          type: 'IPV6',
          value: val,
          startIndex: valStart,
          endIndex: valStart + val.length,
          severity: 'LOW',
          confidence: 0.99,
          description: 'IPv6 Address',
          priority: 64,
        });
      }
    }

    const ipv6Pattern = /\b(?:[0-9a-fA-F]{1,4}:)+(?::[0-9a-fA-F]{1,4})+\b|\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b/gi;
    while ((match = ipv6Pattern.exec(text)) !== null) {
      if ((match[0].match(/:/g) || []).length >= 2) {
        addCandidate({
          type: 'IPV6',
          value: match[0],
          startIndex: match.index,
          endIndex: match.index + match[0].length,
          severity: 'LOW',
          confidence: 0.98,
          description: 'IPv6 Address',
          priority: 62,
        });
      }
    }

    // IPv4
    const ipv4Pattern = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g;
    while ((match = ipv4Pattern.exec(text)) !== null) {
      addCandidate({
        type: 'IPV4',
        value: match[0],
        startIndex: match.index,
        endIndex: match.index + match[0].length,
        severity: 'LOW',
        confidence: 0.92,
        description: 'IPv4 Address',
        priority: 55,
      });
    }

    // MAC Address
    const macPattern = /\b(?:[0-9A-Fa-f]{2}[:-]){5}(?:[0-9A-Fa-f]{2})\b/g;
    while ((match = macPattern.exec(text)) !== null) {
      addCandidate({
        type: 'MAC_ADDRESS',
        value: match[0],
        startIndex: match.index,
        endIndex: match.index + match[0].length,
        severity: 'LOW',
        confidence: 0.95,
        description: 'MAC Hardware Address',
        priority: 76,
      });
    }

    // URLs (HTTP / HTTPS)
    const urlPattern = /\bhttps?:\/\/[^\s"'`<>]+/gi;
    while ((match = urlPattern.exec(text)) !== null) {
      addCandidate({
        type: 'URL',
        value: match[0],
        startIndex: match.index,
        endIndex: match.index + match[0].length,
        severity: 'LOW',
        confidence: 0.95,
        description: 'Uniform Resource Locator (URL)',
        priority: 50,
      });
    }

    // Sort candidates by priority DESC, length DESC, startIndex ASC
    rawCandidates.sort((a, b) => {
      if (b.priority !== a.priority) return b.priority - a.priority;
      if (b.value.length !== a.value.length) return b.value.length - a.value.length;
      return a.startIndex - b.startIndex;
    });

    const accepted: RawDetection[] = [];
    for (const cand of rawCandidates) {
      const overlaps = accepted.some(acc => !(cand.endIndex <= acc.startIndex || cand.startIndex >= acc.endIndex));
      if (!overlaps) {
        accepted.push(cand);
      }
    }

    accepted.sort((a, b) => a.startIndex - b.startIndex);

    return accepted.map(item => {
      const upToStart = text.slice(0, item.startIndex);
      const line = (upToStart.match(/\n/g) || []).length + 1;
      const lastNl = upToStart.lastIndexOf('\n');
      const column = lastNl === -1 ? item.startIndex + 1 : item.startIndex - lastNl;
      return {
        type: item.type,
        value: item.value,
        index: item.startIndex,
        length: item.value.length,
        startIndex: item.startIndex,
        endIndex: item.endIndex,
        line,
        column,
        location: `line ${line}, col ${column}`,
        severity: item.severity,
        confidence: item.confidence,
        description: item.description,
        detectedBy: ['CipherTrace'],
        detectors: ['CipherTrace'],
      };
    });
  }

  /**
   * Helper to determine which detection type is more specific.
   */
  private static isMoreSpecificType(candidate: DetectionType, baseline: DetectionType): boolean {
    if (candidate === baseline) return false;
    if (baseline === 'CONFIDENTIAL_DATA') return true;
    if (candidate === 'CONFIDENTIAL_DATA') return false;

    // Composite database and cache URLs supersede internal parts (e.g. user:pass@host)
    if (candidate === 'DATABASE_URL' || candidate === 'REDIS_URL') {
      if (['EMAIL', 'URL', 'IP_ADDRESS', 'IPV4', 'IPV6', 'PASSWORD', 'API_KEY', 'USER_ID', 'ADDRESS'].includes(baseline)) {
        return true;
      }
    }
    if (baseline === 'DATABASE_URL' || baseline === 'REDIS_URL') {
      if (['EMAIL', 'URL', 'IP_ADDRESS', 'IPV4', 'IPV6', 'PASSWORD', 'API_KEY', 'USER_ID', 'ADDRESS'].includes(candidate)) {
        return false;
      }
    }

    const specificSecretTypes: DetectionType[] = [
      'GOOGLE_API_KEY',
      'AWS_ACCESS_KEY',
      'AWS_SECRET_KEY',
      'AZURE_KEY',
      'GITHUB_TOKEN',
      'JWT',
      'JWT_SECRET',
      'BEARER_TOKEN',
      'PASSWORD',
      'DATABASE_URL',
      'REDIS_URL',
      'PRIVATE_KEY',
      'SSH_KEY',
    ];

    if (specificSecretTypes.includes(candidate) && (baseline === 'API_KEY' || baseline === 'URL' || baseline === 'EMAIL')) {
      return true;
    }
    if (specificSecretTypes.includes(baseline) && (candidate === 'API_KEY' || candidate === 'URL' || candidate === 'EMAIL')) {
      return false;
    }

    // PII & Identifiers
    if (candidate === 'PERSON_NAME' && baseline === 'PERSON') return true;
    if (['IPV4', 'IPV6', 'MAC_ADDRESS'].includes(candidate) && baseline === 'IP_ADDRESS') return true;
    if (['CREDIT_CARD', 'IBAN', 'SSN', 'PASSPORT', 'DRIVER_LICENSE', 'AADHAAR'].includes(candidate) && baseline === 'ACCOUNT_NUMBER') return true;

    return false;
  }

  /**
   * Deduplicate and merge detections from CipherTrace and Microsoft Presidio.
   */
  public static mergeDetections(
    cipherTraceDetections: DetectionResult[],
    presidioDetections: DetectionResult[],
    text?: string
  ): DetectionResult[] {
    const all = [
      ...cipherTraceDetections.map(d => ({ ...d, detectedBy: d.detectedBy || ['CipherTrace'], detectors: d.detectors || ['CipherTrace'] })),
      ...presidioDetections.map(d => ({ ...d, detectedBy: d.detectedBy || ['Presidio'], detectors: d.detectors || ['Presidio'] })),
    ];

    if (all.length === 0) {
      return [];
    }

    // Sort candidates: most specific first, then confidence DESC, then length DESC, then startIndex ASC
    all.sort((a, b) => {
      const aSpecific = SensitiveDataScanner.isMoreSpecificType(a.type, b.type);
      const bSpecific = SensitiveDataScanner.isMoreSpecificType(b.type, a.type);
      if (aSpecific && !bSpecific) return -1;
      if (bSpecific && !aSpecific) return 1;
      if (b.confidence !== a.confidence) return b.confidence - a.confidence;
      if (b.length !== a.length) return b.length - a.length;
      return a.startIndex - b.startIndex;
    });

    const merged: DetectionResult[] = [];

    for (const item of all) {
      // Check if item overlaps with any already merged detection
      const overlapIndex = merged.findIndex(m => !(item.endIndex <= m.startIndex || item.startIndex >= m.endIndex));

      if (overlapIndex === -1) {
        if (text) {
          const cleaned = SensitiveDataScanner.cleanSpan(text, item.startIndex, item.endIndex);
          if (cleaned && !SensitiveDataScanner.isNonSecretKeyword(cleaned.value)) {
            merged.push({
              ...item,
              startIndex: cleaned.start,
              endIndex: cleaned.end,
              index: cleaned.start,
              length: cleaned.value.length,
              value: cleaned.value,
            });
          }
        } else if (!SensitiveDataScanner.isNonSecretKeyword(item.value)) {
          merged.push({ ...item });
        }
      } else {
        // Overlapping detection detected
        const existing = merged[overlapIndex];

        // 1. Preserve highest confidence
        const maxConfidence = Math.max(existing.confidence, item.confidence);

        // 2. Preserve highest severity
        const existingWeight = SEVERITY_WEIGHTS[existing.severity] || 1;
        const itemWeight = SEVERITY_WEIGHTS[item.severity] || 1;
        const highestSeverity: Severity = itemWeight > existingWeight ? item.severity : existing.severity;

        // 3. Determine final type, span, and value
        let finalType: DetectionType = existing.type;
        let finalStart = existing.startIndex;
        let finalEnd = existing.endIndex;
        let finalValue = existing.value;
        let finalDesc = existing.description;

        if (SensitiveDataScanner.isMoreSpecificType(item.type, existing.type)) {
          finalType = item.type;
          finalStart = item.startIndex;
          finalEnd = item.endIndex;
          finalValue = item.value;
          finalDesc = item.description;
        } else if (SensitiveDataScanner.isMoreSpecificType(existing.type, item.type)) {
          finalType = existing.type;
          finalStart = existing.startIndex;
          finalEnd = existing.endIndex;
          finalValue = existing.value;
          finalDesc = existing.description;
        } else {
          // Both types have equal specificity
          if (item.type === existing.type) {
            finalStart = Math.min(existing.startIndex, item.startIndex);
            finalEnd = Math.max(existing.endIndex, item.endIndex);
            finalValue = text ? text.slice(finalStart, finalEnd) : (item.length > existing.length ? item.value : existing.value);
          } else if (item.confidence > existing.confidence) {
            finalType = item.type;
            finalStart = item.startIndex;
            finalEnd = item.endIndex;
            finalValue = item.value;
            finalDesc = item.description;
          }
        }

        // Clean span if text is provided
        if (text) {
          const cleaned = SensitiveDataScanner.cleanSpan(text, finalStart, finalEnd);
          if (!cleaned) continue;
          finalStart = cleaned.start;
          finalEnd = cleaned.end;
          finalValue = cleaned.value;
        }

        // 4. Combine detectedBy sources
        const combinedSources = Array.from(new Set([...(existing.detectedBy || []), ...(item.detectedBy || [])]));

        merged[overlapIndex] = {
          ...existing,
          type: finalType,
          startIndex: finalStart,
          endIndex: finalEnd,
          index: finalStart,
          length: finalValue.length,
          value: finalValue,
          confidence: Number(maxConfidence.toFixed(4)),
          severity: highestSeverity,
          description: existing.description.includes(finalType) ? existing.description : finalDesc,
          detectedBy: combinedSources,
          detectors: combinedSources,
        };
      }
    }

    // Final sort by start index
    return merged.sort((a, b) => a.startIndex - b.startIndex);
  }

  /**
   * Main scan method covering CipherTrace and Presidio in parallel.
   * Returns merged detections and performance telemetry.
   */
  public static async scanMerged(text: string): Promise<{
    detections: DetectionResult[];
    presidioAvailable: boolean;
    performance: PerformanceMetrics;
  }> {
    const t0 = Date.now();

    // Run CipherTrace detector
    const ctStart = Date.now();
    const ctDetections = SensitiveDataScanner.scanCipherTrace(text);
    const ctTime = Date.now() - ctStart;

    // Run Presidio detector with failure handling
    const presidioStart = Date.now();
    let presidioDetections: DetectionResult[] = [];
    let presidioAvailable = false;

    try {
      presidioDetections = await PresidioService.analyze(text);
      presidioAvailable = presidioDetections.length > 0;
      if (!presidioAvailable) {
        const health = await PresidioService.checkHealth();
        presidioAvailable = health.available;
      }
    } catch {
      presidioAvailable = false;
      presidioDetections = [];
    }
    const presidioTime = Date.now() - presidioStart;

    // Merge & deduplicate
    const mergeStart = Date.now();
    const merged = SensitiveDataScanner.mergeDetections(ctDetections, presidioDetections, text);
    const mergeTime = Date.now() - mergeStart;

    const totalDetectionTime = Date.now() - t0;

    return {
      detections: merged,
      presidioAvailable,
      performance: {
        cipherTraceDetectionTimeMs: ctTime,
        presidioDetectionTimeMs: presidioTime,
        mergeTimeMs: mergeTime,
        redactionTimeMs: 0,
        validationTimeMs: 0,
        totalDetectionTimeMs: totalDetectionTime,
        totalProcessingTimeMs: totalDetectionTime,
      },
    };
  }

  /**
   * Synchronous scan fallback for backward compatibility.
   */
  public static scan(text: string): DetectionResult[] {
    return SensitiveDataScanner.scanCipherTrace(text);
  }

  /**
   * Final security gate: verifies that no unredacted sensitive values remain in the sanitized text.
   */
  public static validateNoSensitiveDataRemains(sanitizedText: string): SecurityGateResult {
    const remainingDetections = SensitiveDataScanner.scanCipherTrace(sanitizedText);
    return {
      safe: remainingDetections.length === 0,
      remainingDetections,
    };
  }

  /**
   * Produce a safe, non-sensitive masked representation for UI inspection.
   */
  public static maskValue(value: string, type: DetectionType): string {
    if (!value) return '***';

    switch (type) {
      case 'EMAIL': {
        const parts = value.split('@');
        if (parts.length === 2) {
          const user = parts[0];
          const domain = parts[1];
          const maskedUser = user.length <= 2 ? user[0] + '***' : user[0] + '***' + user[user.length - 1];
          return `${maskedUser}@${domain}`;
        }
        return value[0] + '***' + value.slice(-2);
      }
      case 'API_KEY':
      case 'GOOGLE_API_KEY':
      case 'AWS_SECRET_KEY':
      case 'AWS_ACCESS_KEY':
      case 'GITHUB_TOKEN':
      case 'BEARER_TOKEN':
      case 'AUTHORIZATION_TOKEN':
      case 'JWT_SECRET': {
        if (value.startsWith('sk-') || value.startsWith('sk_')) {
          const suffix = value.slice(-4);
          const prefix = value.slice(0, 4);
          return `${prefix}***${suffix}`;
        }
        if (value.length > 8) {
          return `${value.slice(0, 4)}***${value.slice(-4)}`;
        }
        return '***REDACTED***';
      }
      case 'CREDIT_CARD': {
        const clean = value.replace(/[-\s]/g, '');
        return `****-****-****-${clean.slice(-4)}`;
      }
      case 'CVV':
        return '***';
      case 'BANK_ACCOUNT': {
        if (value.length > 4) {
          return `****${value.slice(-4)}`;
        }
        return '****';
      }
      case 'PHONE':
      case 'PHONE_NUMBER': {
        const clean = value.replace(/\D/g, '');
        return clean.length > 4 ? `(***) ***-${clean.slice(-4)}` : '***-****';
      }
      case 'DATABASE_URL':
      case 'POSTGRES_URL':
      case 'MYSQL_URL':
      case 'MONGODB_URL':
      case 'REDIS_URL':
        return 'db://****:****@****/****';
      case 'PRIVATE_KEY':
      case 'SSH_KEY':
        return '-----BEGIN PRIVATE KEY-----\n[...SECURE KEY DATA REDACTED...]\n-----END PRIVATE KEY-----';
      case 'PASSWORD':
        return '********';
      case 'SQL_INJECTION':
      case 'COMMAND_INJECTION':
        return '[MALICIOUS_PAYLOAD_QUARANTINED]';
      case 'GPS_COORDINATES':
        return '**.*, **.*';
      case 'IPV4':
      case 'IPV6':
      case 'IP_ADDRESS': {
        const dot = value.lastIndexOf('.');
        if (dot !== -1) {
          return `${value.slice(0, dot)}.***`;
        }
        return '***.***.***.***';
      }
      case 'PERSON_NAME':
      case 'PERSON': {
        const parts = value.split(/\s+/);
        return parts.map(p => p[0] + '***').join(' ');
      }
      default: {
        if (value.length <= 4) return '***';
        return `${value.slice(0, 2)}***${value.slice(-2)}`;
      }
    }
  }
}
