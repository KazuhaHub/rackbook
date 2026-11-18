import path from 'node:path'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import { defineConfig, type PluginOption } from 'vite'

const backend = 'http://127.0.0.1:8080'

export default defineConfig(async ({ mode }) => {
  const plugins: PluginOption[] = [react(), tailwindcss()]
  // The mock API only exists in `npm run dev:mock`; it is never imported by a build.
  if (mode === 'mock') {
    const { mockApi } = await import('./dev/mock.ts')
    plugins.push(mockApi(path.resolve(import.meta.dirname, '../examples/homelab')))
  }
  const proxy = Object.fromEntries(
    ['/api', '/branding', '/mcp', '/export.', '/llms'].map((p) => [p, { target: backend, changeOrigin: true }]),
  )
  return {
    plugins,
    resolve: { alias: { '@': path.resolve(import.meta.dirname, 'src') } },
    server: mode === 'mock' ? {} : { proxy },
    build: {
      outDir: 'dist',
      emptyOutDir: true,
      chunkSizeWarningLimit: 700,
    },
  }
})
