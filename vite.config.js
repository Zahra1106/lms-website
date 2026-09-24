// Ignore any stray postcss.config.js in parent folders, and forward /api to the Express server.
export default {
  css: { postcss: { plugins: [] } },
  server: { proxy: { '/api': 'http://localhost:4000' } }
}
