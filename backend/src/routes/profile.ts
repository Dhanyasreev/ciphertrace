import { Router, Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import { JWT_SECRET } from './auth.js';
import { profileService } from '../services/profileService.js';

export const profileRouter = Router();

function authenticateToken(req: Request, res: Response): { userId: string; email: string } | null {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    res.status(401).json({ error: 'Missing or invalid Authorization header' });
    return null;
  }
  const token = authHeader.substring(7);
  try {
    const decoded = jwt.verify(token, JWT_SECRET) as { userId: string; email: string };
    return decoded;
  } catch {
    res.status(401).json({ error: 'Invalid or expired session token' });
    return null;
  }
}

/**
 * GET /api/profile
 */
profileRouter.get('/', async (req: Request, res: Response): Promise<void> => {
  try {
    const auth = authenticateToken(req, res);
    if (!auth) return;
    const profile = await profileService.getProfile(auth.userId);
    if (!profile) {
      res.status(404).json({ error: 'Profile not found for this user' });
      return;
    }
    res.json({ profile });
  } catch (error) {
    console.error('[Profile] GET error:', error);
    res.status(500).json({ error: 'Internal server error fetching profile' });
  }
});

/**
 * POST /api/profile
 */
profileRouter.post('/', async (req: Request, res: Response): Promise<void> => {
  try {
    const auth = authenticateToken(req, res);
    if (!auth) return;
    const { fullName, jobTitle, companyName, department, employeeId } = req.body;
    if (!fullName || !jobTitle || !companyName || !department || !employeeId) {
      res.status(400).json({
        error: 'Missing required profile fields. Expected fullName, jobTitle, companyName, department, employeeId.',
      });
      return;
    }
    const savedProfile = await profileService.saveProfile(auth.userId, {
      fullName,
      jobTitle,
      companyName,
      department,
      employeeId,
    });
    res.status(200).json({ profile: savedProfile });
  } catch (error) {
    console.error('[Profile] POST error:', error);
    res.status(500).json({ error: 'Internal server error saving profile' });
  }
});
