import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vitejs.dev/config/
export default defineConfig(({ command }) => ({
  plugins: [react()],
  build: {
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (!id.includes('node_modules')) {
            return undefined
          }
          if (id.includes('/react') || id.includes('react-dom') || id.includes('react-router-dom')) {
            return 'react'
          }
          if (id.includes('@mui/material') || id.includes('@emotion/')) {
            return 'mui'
          }
          if (id.includes('@mui/icons-material')) {
            return 'icons'
          }
          return 'vendor'
        },
      },
    },
  },
  server: {
    port: 3000,
    host: '0.0.0.0',
    watch: {
      // Docker Desktop bind mounts on Windows require polling for reliable HMR.
      usePolling: command === 'serve',
      interval: 500,
    },
  },
}))
