'use strict';

const config = require('./src/config');
const { createApp } = require('./src/app');
const db = require('./src/db');

const app = createApp();

const server = app.listen(config.port, '0.0.0.0', async () => {
  console.log(`[cirs] CIRS API listening on port ${config.port} (${config.env})`);
  const healthy = await db.health();
  if (healthy) {
    console.log(`[cirs] MySQL connected: ${config.db.host}:${config.db.port}/${config.db.database}`);
  } else {
    console.error('[cirs] MySQL is not reachable. The API is up, but data endpoints will fail until the database is available.');
  }
  const intel = require('./src/services/threatIntel').providerStatus();
  console.log(`[cirs] Threat intelligence: ${intel.configured ? intel.providers.filter((p) => p.configured).map((p) => p.name).join(', ') : 'not configured (heuristic-only scanning)'}`);
});

function shutdown(signal) {
  console.log(`[cirs] ${signal} received, shutting down`);
  server.close(async () => {
    await db.close().catch(() => {});
    process.exit(0);
  });
  setTimeout(() => process.exit(1), 10_000).unref();
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
