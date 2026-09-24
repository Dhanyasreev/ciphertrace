import { Router, Request, Response } from 'express';
import { TokenVault } from '../services/tokenVault.js';

export const vaultRouter = Router();

/**
 * GET /api/vault/tokens
 * Returns sanitized token metadata.
 * CRITICAL SECURITY: originalValue is NEVER returned!
 */
vaultRouter.get('/tokens', async (_req: Request, res: Response): Promise<void> => {
  try {
    const tokens = await TokenVault.getSanitizedList();
    res.json({ tokens });
  } catch (error) {
    console.error('[Vault] GET tokens error:', error);
    res.status(500).json({ error: 'Failed to retrieve vault tokens' });
  }
});

/**
 * GET /api/vault/stats
 * Returns aggregate vault statistics.
 */
vaultRouter.get('/stats', async (_req: Request, res: Response): Promise<void> => {
  try {
    const stats = await TokenVault.getStats();
    res.json(stats);
  } catch (error) {
    console.error('[Vault] GET stats error:', error);
    res.status(500).json({ error: 'Failed to retrieve vault stats' });
  }
});

/**
 * POST /api/vault/tokens/:token/revoke
 * Revokes an active token.
 */
vaultRouter.post('/tokens/:token/revoke', async (req: Request, res: Response): Promise<void> => {
  try {
    const { token } = req.params;
    if (!token) {
      res.status(400).json({ error: 'Token parameter is required' });
      return;
    }

    const success = await TokenVault.revoke(token);
    res.json({
      success,
      message: success ? `Token ${token} revoked` : `Token ${token} not found or already revoked`,
    });
  } catch (error) {
    console.error('[Vault] Revoke token error:', error);
    res.status(500).json({ error: 'Failed to revoke token' });
  }
});
