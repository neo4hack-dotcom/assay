import react from '@vitejs/plugin-react';
import { defineConfig } from 'vite';

const FRONT_PORT = Number(process.env.ASSAY_FRONT_PORT ?? 3100);
const BACKEND_URL = process.env.ASSAY_BACKEND_URL ?? 'http://127.0.0.1:3101';

export default defineConfig({
  plugins: [react()],
  server: { port: FRONT_PORT, host: true, proxy: { '/api': { target: BACKEND_URL, changeOrigin: true } } },
  build: { chunkSizeWarningLimit: 900 },
});
