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
  // `renderMarkdown` needs a DOM, because DOMPurify parses HTML in order to decide what to strip.
  // Measured on dompurify 3.4.13: with `--environment node` the default export has no `sanitize`
  // method at all, so all nine cases in `render.test.js` error rather than passing on unsanitized
  // output. The environment therefore cannot degrade quietly, and this line is what keeps it set.
  test: {
    environment: 'jsdom',
    include: ['src/**/*.test.js'],
  },
});
