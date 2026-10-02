import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    // 개발 중에는 /api 요청을 Django 서버로 넘긴다 (브라우저 입장에서는 같은 주소라 CORS 설정이 필요 없다).
    // localhost 대신 127.0.0.1: 윈도우에서 localhost는 먼저 IPv6로 시도하다 거절당해 요청마다 약 2초가 걸린다.
    proxy: {
      '/api': 'http://127.0.0.1:8000',
    },
  },
})
