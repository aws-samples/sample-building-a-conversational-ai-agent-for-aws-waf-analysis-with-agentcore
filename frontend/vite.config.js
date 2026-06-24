import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { readFileSync } from 'fs';

const changelog = readFileSync('../CHANGELOG.md', 'utf-8');
const version = changelog.match(/^## (\d+\.\d+\.\d+)/m)?.[1] || '0.0.0';

export default defineConfig({
  plugins: [react()],
  define: {
    __APP_VERSION__: JSON.stringify(version),
    // amazon-cognito-identity-js references Node's `global`, which doesn't exist
    // in the browser. Vite 7+ no longer shims it, so map it to globalThis or the
    // app throws "global is not defined" at runtime (white screen).
    global: 'globalThis',
  },
});
