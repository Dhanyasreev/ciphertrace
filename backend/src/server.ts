import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { authRouter } from './routes/auth.js';
import { profileRouter } from './routes/profile.js';
import { vaultRouter } from './routes/vault.js';
import { securityRouter } from './routes/security.js';

dotenv.config();

export function createBackendApp() {
  const app = express();

  app.use(cors());
  app.use(express.json({ limit: '10mb' }));
  app.use(express.urlencoded({ extended: true, limit: '10mb' }));

  // API Routes
  app.use('/api/auth', authRouter);
  app.use('/api/profile', profileRouter);
  app.use('/api/vault', vaultRouter);
  app.use('/api', securityRouter);

  // Health check
  app.get('/api/health', (_req, res) => {
    res.json({ status: 'ok', service: 'CipherTrace Backend API', version: '2.2.0' });
  });

  return app;
}

const app = createBackendApp();

const isDirectEntry = process.argv[1] && (
  process.argv[1].includes('backend/src/server') ||
  process.argv[1].includes('backend/dist/server')
);

if (isDirectEntry) {
  const BACKEND_PORT = Number(process.env.BACKEND_PORT) || 3001;
  app.listen(BACKEND_PORT, '0.0.0.0', () => {
    console.log(`[CipherTrace Backend] Running standalone on http://0.0.0.0:${BACKEND_PORT}`);
  });
}

export default app;
