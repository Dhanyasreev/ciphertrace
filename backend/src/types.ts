export type DetectionType =
  // PII
  | 'PERSON'
  | 'PERSON_NAME'
  | 'DATE_OF_BIRTH'
  | 'DOB'
  | 'EMAIL'
  | 'PHONE_NUMBER'
  | 'PHONE'
  | 'ADDRESS'
  | 'POSTAL_CODE'
  | 'CONFIDENTIAL_DATA'
  // NETWORK
  | 'IPV4'
  | 'IPV6'
  | 'IP_ADDRESS'
  | 'MAC_ADDRESS'
  | 'CIDR_RANGE'
  | 'CIDR'
  | 'DOMAIN'
  | 'URL'
  // IDENTIFIERS
  | 'USER_ID'
  | 'ACCOUNT_NUMBER'
  | 'EMPLOYEE_ID'
  | 'CUSTOMER_ID'
  | 'PASSPORT_NUMBER'
  | 'PASSPORT'
  | 'DRIVER_LICENSE'
  | 'NATIONAL_ID'
  | 'SSN'
  | 'AADHAAR'
  | 'PAN'
  // CREDENTIALS
  | 'API_KEY'
  | 'GOOGLE_API_KEY'
  | 'AWS_ACCESS_KEY'
  | 'AWS_SECRET_KEY'
  | 'AZURE_KEY'
  | 'GITHUB_TOKEN'
  | 'JWT'
  | 'JWT_SECRET'
  | 'BEARER_TOKEN'
  | 'PASSWORD'
  | 'SECRET'
  | 'PRIVATE_KEY'
  | 'SSH_KEY'
  | 'CLIENT_SECRET'
  | 'CLIENT_ID'
  | 'ACCESS_TOKEN'
  | 'REFRESH_TOKEN'
  | 'AUTH_TOKEN'
  | 'AUTHORIZATION_TOKEN'
  | 'OAUTH_TOKEN'
  | 'HARDCODED_SECRET'
  | 'SOURCE_CODE_SECRET'
  // DATABASE
  | 'DATABASE_URL'
  | 'POSTGRES_URL'
  | 'MYSQL_URL'
  | 'MONGODB_URL'
  | 'REDIS_URL'
  | 'DATABASE_USERNAME'
  | 'DATABASE_PASSWORD'
  | 'CONNECTION_STRING'
  // FINANCIAL
  | 'CREDIT_CARD'
  | 'CVV'
  | 'BANK_ACCOUNT'
  | 'IFSC'
  | 'IBAN'
  | 'SWIFT_BIC'
  | 'ROUTING_NUMBER'
  | 'UPI'
  | 'CRYPTO_WALLET'
  // LOCATION
  | 'GPS_COORDINATES'
  | 'LATITUDE'
  | 'LONGITUDE'
  // SECURITY
  | 'SQL_INJECTION'
  | 'COMMAND_INJECTION';

export type Severity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export interface DetectionResult {
  type: DetectionType;
  value: string;
  index: number;
  length: number;
  startIndex: number;
  endIndex: number;
  line: number;
  column: number;
  location?: string;
  severity: Severity;
  confidence: number;
  description: string;
  detectedBy?: string[];
  detectors?: string[];
}

export interface SecurityGateResult {
  safe: boolean;
  remainingDetections: DetectionResult[];
}

export interface PerformanceMetrics {
  cipherTraceDetectionTimeMs: number;
  presidioDetectionTimeMs: number;
  mergeTimeMs: number;
  redactionTimeMs: number;
  validationTimeMs: number;
  totalDetectionTimeMs: number;
  totalProcessingTimeMs: number;
}

export interface TokenRecord {
  token: string;
  originalValue: string;
  maskedValue: string;
  type: DetectionType;
  requestId: string;
  createdAt: number;
  expiresAt: number;
  severity: Severity;
  revoked: boolean;
  detectedBy?: string[];
}

export interface SanitizedTokenRecord {
  token: string;
  maskedValue: string;
  type: DetectionType;
  requestId: string;
  createdAt: number;
  expiresAt: number;
  ttlSecondsRemaining: number;
  isExpired: boolean;
  severity: Severity;
  revoked: boolean;
  detectedBy?: string[];
}

export interface EmployeeProfile {
  userId: string;
  fullName: string;
  jobTitle: string;
  companyName: string;
  department: string;
  employeeId: string;
  promptsScreened: number;
  leaksMitigated: number;
  securityClearance: string;
  activePolicies: string[];
}

export interface AuditLogEntry {
  id: string;
  timestamp: number;
  userId: string;
  userEmail: string;
  action: string;
  promptLength: number;
  detectionsCount: number;
  detections: {
    type: DetectionType;
    token: string;
    severity: Severity;
    confidence?: number;
    detectedBy?: string[];
  }[];
  riskLevel: Severity;
  status: 'BLOCKED' | 'REDACTED' | 'ALLOWED';
}

export interface VaultStats {
  totalTokens: number;
  activeTokens: number;
  expiredTokens: number;
  revokedTokens: number;
  backend: 'redis' | 'memory';
}

export interface SecurityMetrics {
  promptsScreened: number;
  leaksMitigated: number;
  activeTokensCount: number;
  criticalDetections: number;
  highDetections: number;
  mediumDetections: number;
  lowDetections: number;
  presidioAvailable?: boolean;
}

export interface User {
  id: string;
  email: string;
  passwordHash: string;
}

export type TaskMode = 'CODE_CORRECTION' | 'CODE_SUMMARY' | 'CODE_EXPLANATION' | 'GENERAL_REASONING';

export interface SecureChatResponse {
  sanitizedPrompt: string;
  tokens: SanitizedTokenRecord[];
  detections: DetectionResult[];
  geminiResponse: string;
  detokenizedResponse: string;
  aiResponse: string; // backward compat: points to detokenizedResponse if detokenized else geminiResponse
  rawAiWithTokens: string; // backward compat: points to geminiResponse
  detokenized: boolean;
  restoredTokensCount: number;
  restoredTokens: string[];
  unresolvedTokens: string[];
  warnings?: string[];
  taskMode: TaskMode;
  model: string;
  requestId: string;
  presidioAvailable: boolean;
  performance: PerformanceMetrics;
  securityGuard?: {
    passed: boolean;
    vaultSecretsProtected: boolean;
    tokensIntact: boolean;
    codeGatewayActive: boolean;
  };
  isCode?: boolean;
}
