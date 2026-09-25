import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  build: {
    outDir: '../dashboard/dist',
    emptyOutDir: true,
  },
  server: {
    port: 5173,
    proxy: {
      // Proxy API and WebSocket calls to the Go server during development
      '/api': {
        target: 'http://127.0.0.1:9090',
        changeOrigin: true,
      },
      '/ws': {
        target: 'http://127.0.0.1:9090',
        ws: true,
        changeOrigin: true,
      },
    },
  },
})
