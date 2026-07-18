import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// The built app is embedded into the Go binary (internal/admin, go:embed dist)
// and served from the admin port's root. During `npm run dev`, proxy the API
// calls to a locally running thorngate admin server on :9000.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  // Build straight into the Go package that embeds it (internal/admin, via
  // go:embed all:dist), so a single `npm run build` refreshes what the binary
  // serves. go:embed can't reach across directories, hence the output lives
  // next to admin.go rather than in web/dist.
  build: {
    outDir: '../internal/admin/dist',
    emptyOutDir: true,
  },
  server: {
    proxy: {
      '/admin': 'http://localhost:9000',
    },
  },
})
