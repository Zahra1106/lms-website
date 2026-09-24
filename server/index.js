// Local / self-hosted entry (Vercel uses api/index.js instead)
import express from 'express';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import app from './app.js';

const dist = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'dist');
if (fs.existsSync(dist)) {
  app.use(express.static(dist));
  app.use((req, res, next) => req.path.startsWith('/api') ? next() : res.sendFile(path.join(dist, 'index.html')));
}
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log(`Ilmora API on http://localhost:${PORT}`));
