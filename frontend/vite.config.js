import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// Port 5173 is already in the backend's CORS_ORIGINS list.
export default defineConfig({
  plugins: [react()],
  server: { port: 5173 },
});
