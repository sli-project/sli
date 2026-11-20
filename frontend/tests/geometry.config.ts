import { defineConfig } from '@playwright/test';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../../', import.meta.url));

// UI02 is opt-in; it never imports the historical parity suite.
export default defineConfig({
  testDir: './geometry',
  testMatch: '**/*.spec.ts',
  workers: 1,
  fullyParallel: false,
  timeout: 60_000,
  retries: 0,
  outputDir: `${root}/artifacts/ui02/results`,
  reporter: [['list'], ['html', { outputFolder: `${root}/artifacts/ui02/report`, open: 'never' }]],
  use: {
    baseURL: 'http://127.0.0.1:4173',
    browserName: 'chromium', locale: 'ru-RU', timezoneId: 'UTC',
    reducedMotion: 'reduce', trace: 'retain-on-failure', screenshot: 'only-on-failure',
  },
  webServer: {
    command: 'npm --prefix frontend run dev -- --port 4173 --strictPort',
    cwd: root, url: 'http://127.0.0.1:4173/app/', reuseExistingServer: false,
  },
});
