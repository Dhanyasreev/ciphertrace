import { Router, Request, Response } from 'express';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import { profileService } from '../services/profileService.js';
import { User } from '../types.js';

export const JWT_SECRET = process.env.JWT_SECRET || 'ciphertrace-enterprise-jwt-secret-token-key-2025';

export const authRouter = Router();

// In-memory users store
const usersMap = new Map<string, User>([
  [
    'test@example.com',
    {
      id: 'usr-test-001',
      email: 'test@example.com',
      // SHA-256 for 'test123'
      passwordHash: crypto.createHash('sha256').update('test123').digest('hex'),
    },
  ],
]);

interface OtpRecord {
  otpHash: string;
  expiresAt: number;
  attempts: number;
}

// In-memory OTP records
const otpRecords = new Map<string, OtpRecord>();

/**
 * POST /api/auth/login
 * Validates credentials and generates a 6-digit OTP.
 */
authRouter.post('/login', async (req: Request, res: Response): Promise<void> => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      res.status(400).json({ error: 'Email and password are required' });
      return;
    }

    const normalizedEmail = String(email).trim().toLowerCase();
    let user = usersMap.get(normalizedEmail);
    const inputHash = crypto.createHash('sha256').update(String(password)).digest('hex');

    // If user doesn't exist yet, allow auto-registration for convenience
    if (!user) {
      user = {
        id: `usr-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`,
        email: normalizedEmail,
        passwordHash: inputHash,
      };
      usersMap.set(normalizedEmail, user);
    } else {
      // Validate password
      if (user.passwordHash !== inputHash) {
        res.status(401).json({ error: 'Invalid email or password' });
        return;
      }
    }

    // Generate 6-digit numeric OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const otpHash = crypto.createHash('sha256').update(otp).digest('hex');

    otpRecords.set(normalizedEmail, {
      otpHash,
      expiresAt: Date.now() + 5 * 60 * 1000, // 5 minutes validity
      attempts: 0,
    });

    console.log(`[Auth] OTP generated for ${normalizedEmail}: ${otp}`);

    res.json({
      success: true,
      message: 'OTP sent to registered email address',
      email: normalizedEmail,
      otpDebug: otp,
    });
  } catch (error) {
    console.error('[Auth] Login error:', error);
    res.status(500).json({ error: 'Internal server error during authentication' });
  }
});

/**
 * POST /api/auth/verify-otp
 * Verifies SHA-256 hashed OTP and issues JWT session token.
 */
authRouter.post('/verify-otp', async (req: Request, res: Response): Promise<void> => {
  try {
    const { email, otp } = req.body;
    if (!email || !otp) {
      res.status(400).json({ error: 'Email and OTP code are required' });
      return;
    }

    const normalizedEmail = String(email).trim().toLowerCase();
    const record = otpRecords.get(normalizedEmail);

    if (!record) {
      res.status(401).json({ error: 'No active OTP request found for this email. Please request a new code.' });
      return;
    }

    if (Date.now() > record.expiresAt) {
      otpRecords.delete(normalizedEmail);
      res.status(401).json({ error: 'OTP has expired. Please request a new code.' });
      return;
    }

    const inputHash = crypto.createHash('sha256').update(String(otp).trim()).digest('hex');
    if (inputHash !== record.otpHash) {
      record.attempts += 1;
      if (record.attempts >= 5) {
        otpRecords.delete(normalizedEmail);
        res.status(401).json({ error: 'Too many failed attempts. Please request a new OTP.' });
        return;
      }
      res.status(401).json({ error: 'Invalid OTP verification code' });
      return;
    }

    // OTP verified successfully, invalidate record
    otpRecords.delete(normalizedEmail);

    let user = usersMap.get(normalizedEmail);
    if (!user) {
      user = {
        id: `usr-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`,
        email: normalizedEmail,
        passwordHash: '',
      };
      usersMap.set(normalizedEmail, user);
    }

    // Generate JWT
    const sessionToken = jwt.sign(
      {
        userId: user.id,
        email: user.email,
      },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    const profile = await profileService.getProfile(user.id);
    const hasProfile = profile !== null;

    res.json({
      success: true,
      sessionToken,
      userId: user.id,
      email: user.email,
      hasProfile,
      profile,
    });
  } catch (error) {
    console.error('[Auth] Verify OTP error:', error);
    res.status(500).json({ error: 'Internal server error during OTP verification' });
  }
});

/**
 * GET /api/auth/session
 * Validates JWT session token and returns hasProfile + stored profile.
 */
authRouter.get('/session', async (req: Request, res: Response): Promise<void> => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      res.status(401).json({ authenticated: false, error: 'Missing or invalid Authorization header' });
      return;
    }

    const token = authHeader.substring(7);
    let decoded: any;
    try {
      decoded = jwt.verify(token, JWT_SECRET);
    } catch {
      res.status(401).json({ authenticated: false, error: 'Session token expired or invalid' });
      return;
    }

    const userId = decoded.userId;
    const email = decoded.email;
    const profile = await profileService.getProfile(userId);
    const hasProfile = profile !== null;

    res.json({
      authenticated: true,
      userId,
      email,
      hasProfile,
      profile: profile || null,
    });
  } catch (error) {
    console.error('[Auth] Session error:', error);
    res.status(500).json({ error: 'Internal server error while resolving session' });
  }
});
