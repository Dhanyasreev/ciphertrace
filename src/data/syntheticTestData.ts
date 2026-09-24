export const SYNTHETIC_TEST_PAYLOAD = `--- ENTERPRISE INCIDENT REPORT & AUDIT PAYLOAD ---
Author: Rahul Sharma
Date of Birth: 15/08/1998
Contact Email: rahul.sharma@cybercorp-internal.com
Direct Phone: +91 98765 43210
Office Address: 123 Innovation Boulevard, Suite 400, Bengaluru 560100

-- Network Infrastructure & Endpoints --
Server IPv4: 192.168.1.105
Gateway IPv6: 2001:0db8:85a3:0000:0000:8a2e:0370:7334
Physical MAC Address: 00:1A:2B:3C:4D:5E
Documentation URL: https://internal.corp.network/v1/auth/gateway
Datacenter GPS Coordinates: 12.9716, 77.5946

-- Identity & Compliance Documents --
Passport Number: P84729104
National ID: ID-99884422
Aadhaar Number: 4321 8765 2109
Tax PAN Number: ABCDE1234F
Employee ID: EMP-2026-8812
Customer ID: CUST-90214-X

-- Banking & Payment Information --
Credit Card: 4111 1111 1111 1234
Card CVV: 842
Bank Account: 987654321098
Bank IFSC: HDFC0001234
International IBAN: GB29NWBK60161331926819

-- Cloud Infrastructure, Keys & Secrets --
Google API Key: AIzaSyA1b2C3d4E5f6G7h8I9j0KlMnOpQrStUvW
AWS Access Key: AKIAIOSFODNN7EXAMPLE
AWS Secret Key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
API Key: sk-live-99a8b7c6d5e4f3a2b1c0998877665544
Bearer Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkbWluIFVzZXIiLCJpYXQiOjE1MTYyMzkwMjJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
JWT Secret: SuperSecretJwtKey2026!@#
Admin Username: sysadmin_root
Admin Password: ProductionPassword2026!#

-- Database & Cache Connection URIs --
Database URL: postgresql://postgres_admin:dbPassw0rdSecure!@db.internal.cluster:5432/enterprise_production
Redis URL: rediss://default:redisKeyAuthToken99@cache.internal.cluster:6380

-- Code Snippet with Embedded Secrets --
const API_KEY = "sk-live-4433221100aabbccddeeff00";
const DB_CONN = "mongodb+srv://admin_user:MongoPass123@cluster0.abcde.mongodb.net/testdb";

-- Quarantined Injections & Attack Probes --
SQL Injection: admin' OR '1'='1
Command Injection: ; cat /etc/passwd

-- Cryptographic Material --
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Yv+Zg9c6a7B8c9D0e1F2g3H4i5J6k7L8m9N0o1P2q3R4s5T
6u7V8w9X0y1Z2a3B4c5D6e7F8g9H0i1J2k3L4m5N6o7P8q9R0s1T2u3V4w5X6y7Z
-----END RSA PRIVATE KEY-----`;

export const PRESET_PROMPTS = [
  {
    id: 'code-python-required-spec',
    label: 'Required Spec: Python Requests with Secret & Broken Syntax',
    text: `import requests

API_KEY = "SECRET_VALUE"

def get_user():
    headers = {
        "Authorization": "Bearer " + API_KEY
    }

    response = requests.get(
        "https://example.com/user",
        headers=headers
        timeout=10
    )

    if response.status_code = 200:
        return response.json(`,
  },
  {
    id: 'code-8-vectors',
    label: '8-Vector Security Audit (API, AWS, DB, JWT, Password, Email, Phone)',
    text: `# Enterprise Database & Cloud Sync Service
import os
import requests
import psycopg2

# Cloud & API Credentials
API_KEY = "sk-ant-api03-live99887766554433221100aabbccddeeff"
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
JWT_SECRET = "ProductionJwtSigningSecretKey2026!@#"

# Database Connection & Admin Authentication
DATABASE_URL = "postgresql://postgres_admin:dbSuperPass2026!@db.internal.cluster:5432/production"
ADMIN_PASSWORD = "EnterpriseMasterAdminPassword2026!#"

# Security Response Contacts
SECURITY_EMAIL = "security-incident@enterprise-cybercorp.internal"
SECURITY_PHONE = "+1-415-555-0199"

def sync_cloud_service():
    connection = psycopg2.connect(DATABASE_URL)
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM audit_logs WHERE status = 'PENDING'")
    connection.commit()
    print("Sync complete")`,
  },
  {
    id: 'synthetic-full',
    label: 'Complete Synthetic Test Payload (30+ Data Types)',
    text: SYNTHETIC_TEST_PAYLOAD,
  },
  {
    id: 'customer-support',
    label: 'Customer Support Escalation with PII & Card',
    text: `Customer Rahul Sharma (DOB: 12/04/1990) called regarding failed transaction on credit card 4111 1111 1111 5678, CVV: 452. Contact email: rahul.support@example.com, phone: (555) 345-9876. Employee ID: EMP-2026-4421 escalated this to supervisor.`,
  },
  {
    id: 'devops-incident',
    label: 'DevOps Incident with Cloud Keys & DB Connection',
    text: `Production server 10.0.4.15 crashed. Please run diagnostic with AWS Access Key AKIAIOSFODNN7EXAMPLE and secret key wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY. Also connect to PostgreSQL replica at postgresql://read_user:SecretPass99@db-replica.internal:5432/analytics. Google Maps API Key: AIzaSyA1b2C3d4E5f6G7h8I9j0KlMnOpQrStUvW`,
  },
  {
    id: 'code-python-api',
    label: 'Code Gateway: Python Requests with API Secret & Syntax Bug',
    text: `API_KEY = "sk_test_REAL_SECRET_123"
def get_data():
    response = requests.get(
        "https://api.example.com",
        headers={"Authorization": API_KEY}
    )
    return response.json(`,
  },
  {
    id: 'code-node-db',
    label: 'Code Gateway: Node.js PostgreSQL Client & SQL Query Bug',
    text: `const { Pool } = require('pg');
const pool = new Pool({
  connectionString: "postgresql://postgres_admin:SuperSecretDbPass99@prod-db.internal:5432/main_db"
});

async function findUser(id) {
  const client = await pool.connect();
  // Please debug and fix potential connection leaks and syntax
  const res = await client.query("SELECT * FROM users WHERE id = $1", [id]);
  return res.rows[0];
}`,
  },
  {
    id: 'code-aws-boto3',
    label: 'Code Gateway: Python Boto3 S3 Upload with Cloud Credentials',
    text: `import boto3

AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

def backup_data(filepath, bucket_name):
    s3 = boto3.client(
        's3',
        aws_access_key_id=AWS_ACCESS_KEY,
        aws_secret_access_key=AWS_SECRET_KEY
    )
    # Please debug unclosed call
    s3.upload_file(filepath, bucket_name, filepath`,
  },
  {
    id: 'clean-query',
    label: 'Clean Query (Zero Sensitive Data)',
    text: `Can you explain the mathematical difference between symmetrical and asymmetrical encryption algorithms, focusing on AES-256 vs RSA-4096 performance characteristics?`,
  },
];
