import { defineConfig } from '@playwright/test';
import { loadEnv } from 'vite';

// End-to-end tests run the real frontend against the real backend (SJSU-112 "Connect and test end to end").
// Start the backend first (backend/README.md); the frontend dev server is started here if it isn't running.
const env = loadEnv('development', process.cwd(), '');
process.env.E2E_API_URL ??= env.VITE_API_BASE_URL || 'http://localhost:8000';
process.env.E2E_API_KEY ??= env.VITE_API_KEY || '';

export default defineConfig({
  testDir: './e2e',
  fullyParallel: false,
  workers: 1, // the tests share one replay on the backend
  timeout: 60_000,
  reporter: [['list'], ['html', { open: 'never' }]],
  use: {
    baseURL: 'http://localhost:5173',
    viewport: { width: 1440, height: 900 },
    screenshot: 'only-on-failure',
    trace: 'retain-on-failure',
  },
  webServer: {
    command: 'npm run dev',
    url: 'http://localhost:5173',
    reuseExistingServer: true,
    timeout: 60_000,
  },
});
