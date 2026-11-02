import { defineConfig } from 'vite'

export default defineConfig({
  server: {
    proxy: {
      '/v1': 'http://127.0.0.1:8765',
      '/healthz': 'http://127.0.0.1:8765',
    },
  },
})
