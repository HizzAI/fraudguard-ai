import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      // Optional proxy — App.jsx calls the backend directly with an absolute URL,
      // but having a proxy means you can also call /upload-apk from the same origin.
      '/upload-apk': 'http://127.0.0.1:8000',
      '/health':     'http://127.0.0.1:8000',
    },
  },
})
