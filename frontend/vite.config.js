import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { readFileSync } from 'fs';

const changelog = readFileSync('../CHANGELOG.md', 'utf-8');
const version = changelog.match(/^## (\d+\.\d+\.\d+)/m)?.[1] || '0.0.0';

export default defineConfig({
  plugins: [react()],
  define: {
    __APP_VERSION__: JSON.stringify(version),
  },
});
