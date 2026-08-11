// defineConfig comes from vitest rather than vite so the `test` block is
// typed. It is the same function, re-exported with the test schema added.
import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'
import path from 'node:path'

// The build output goes straight into the Go package that embeds it, so
// `make build` after `make dashboard` produces a binary with the current UI
// and there is no copy step to forget.
export default defineConfig({
  plugins: [react()],
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
    proxy: {
      '/v1': { target: 'http://127.0.0.1:8600', ws: true },
    },
  },
  test: {
    environment: 'jsdom',
    globals: true,
    coverage: {
      provider: 'v8',
      // Ratchet, not aspiration: the floor is where the suite stands today,
      // and it should be raised whenever a page gains tests.
      thresholds: { statements: 51, branches: 36, functions: 37, lines: 52 },
    },
  },
})
