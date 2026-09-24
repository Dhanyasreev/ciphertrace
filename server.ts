import express from 'express';
import path from 'path';
import fs from 'fs';
import { spawn, ChildProcess } from 'child_process';
import { createServer as createViteServer } from 'vite';
import { createBackendApp } from './backend/src/server.js';

const PORT = Number(process.env.PORT) || 3000;

function getRootDir(): string {
  if (fs.existsSync(path.join(process.cwd(), 'backend', 'presidio', 'app.py'))) {
    return process.cwd();
  }
  if (typeof __dirname !== 'undefined') {
    const parentDir = path.resolve(__dirname, '..');
    if (fs.existsSync(path.join(parentDir, 'backend', 'presidio', 'app.py'))) {
      return parentDir;
    }
  }
  return process.cwd();
}

let pythonProc: ChildProcess | null = null;

function startPythonPresidioService() {
  const rootDir = getRootDir();
  const pythonScript = path.join(rootDir, 'backend', 'presidio', 'app.py');
  if (!fs.existsSync(pythonScript)) {
    console.warn('[PresidioLauncher] Python presidio script not found at:', pythonScript);
    return;
  }

  try {
    console.log('[PresidioLauncher] Launching Microsoft Presidio service on port 5001...');
    pythonProc = spawn('python3', [pythonScript], {
      env: {
        ...process.env,
        PRESIDIO_PORT: '5001',
        PYTHONUNBUFFERED: '1',
      },
      cwd: path.join(rootDir, 'backend', 'presidio'),
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    pythonProc.stdout?.on('data', (data) => {
      const msg = data.toString().trim();
      if (msg) console.log(`[PresidioService] ${msg}`);
    });

    pythonProc.stderr?.on('data', (data) => {
      const msg = data.toString().trim();
      if (msg) console.warn(`[PresidioService stderr] ${msg}`);
    });

    pythonProc.on('error', (err) => {
      console.warn('[PresidioLauncher] Could not launch Python service directly:', err.message);
    });

    pythonProc.on('exit', (code, signal) => {
      console.log(`[PresidioLauncher] Python process exited with code ${code}, signal ${signal}`);
      pythonProc = null;
    });
  } catch (err: any) {
    console.warn('[PresidioLauncher] Exception spawning Python Presidio service:', err.message);
  }
}

function serveStatic(app: express.Express) {
  const rootDir = getRootDir();
  const distPath = path.join(rootDir, 'dist');
  app.use(express.static(distPath));
  app.get('*', (_req, res) => {
    const indexPath = path.join(distPath, 'index.html');
    if (fs.existsSync(indexPath)) {
      res.sendFile(indexPath);
    } else {
      res.status(404).send('Application build not found.');
    }
  });
}

async function startServer() {
  // Start Python Presidio service
  startPythonPresidioService();

  const app = createBackendApp();

  const isProduction =
    process.env.NODE_ENV === 'production' ||
    Boolean(process.argv[1]?.endsWith('server.cjs')) ||
    Boolean(process.argv[1]?.endsWith('server.js'));

  // In development, hook up Vite dev server middleware
  if (!isProduction) {
    try {
      const vite = await createViteServer({
        server: { middlewareMode: true },
        appType: 'spa',
      });
      app.use(vite.middlewares);
    } catch (err) {
      console.warn('[Vite] Failed to start Vite dev middleware, serving static build:', err);
      serveStatic(app);
    }
  } else {
    // Production static serving
    serveStatic(app);
  }

  const server = app.listen(PORT, '0.0.0.0', () => {
    console.log(`[CipherTrace Gateway] Server running on http://0.0.0.0:${PORT}`);
  });

  const shutdown = () => {
    console.log('[CipherTrace Gateway] Shutting down...');
    if (pythonProc) {
      try {
        pythonProc.kill('SIGTERM');
      } catch {
        // ignore
      }
    }
    server.close(() => {
      process.exit(0);
    });
  };

  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

startServer().catch((err) => {
  console.error('[CipherTrace Gateway] Fatal error starting server:', err);
  process.exit(1);
});
