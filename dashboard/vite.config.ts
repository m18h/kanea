// defineConfig comes from vitest rather than vite so the `test` block is
// typed. It is the same function, re-exported with the test schema added.
import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'
import path from 'node:path'
import { mockApi } from './mock/api'

// MOCK_API=1 (npm run dev:mock) serves the whole /v1 surface from the
// in-process mock daemon instead of proxying to a real kanead: dashboard
// development with no Linux node in sight.
const useMock = process.env.MOCK_API === '1'

// The build output goes straight into the Go package that embeds it, so
// `make build` after `make dashboard` produces a binary with the current UI
// and there is no copy step to forget.
export default defineConfig({
  plugins: [react(), ...(useMock ? [mockApi()] : [])],
  resolve: {
    alias: { '@': path.resolve(__dirname, './src') },
  },
  build: {
    outDir: '../internal/dashboard/dist',
    // Never empty the directory: it holds a committed placeholder that makes
    // the go:embed compile before the dashboard has ever been built.
    emptyOutDir: false,
    // PRD §21 budgets 1.5 MiB gzipped. Warn well before that so a dependency
    // that blows the budget is noticed in the build that added it.
    chunkSizeWarningLimit: 700,
  },
  server: {
    // With the mock in place the proxy must be off: both want /v1, and the
    // proxy's websocket upgrade handler would race the mock's.
    ...(useMock
      ? {}
      : {
          proxy: {
            '/v1': { target: 'http://127.0.0.1:8600', ws: true },
          },
        }),
  },
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/test/setup.ts'],
    coverage: {
      provider: 'v8',
      // Ratchet, not aspiration: the floor is where the suite stands today,
      // and it should be raised whenever a page gains tests.
      thresholds: { statements: 51, branches: 36, functions: 37, lines: 52 },
    },
  },
})
