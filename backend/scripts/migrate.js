'use strict';

/**
 * Idempotent migration runner.
 *
 * - Creates the database if it does not exist.
 * - Runs every .sql file in db/migrations in order (all additive).
 * - Adds columns/indexes/keys that MySQL cannot express as IF NOT EXISTS.
 *
 * Safe to run repeatedly against a database that already holds data.
 */

const fs = require('fs');
const path = require('path');
const mysql = require('mysql2/promise');
const config = require('../src/config');

const MIGRATIONS_DIR = path.join(__dirname, '..', 'db', 'migrations');

async function columnExists(conn, database, table, column) {
  const [rows] = await conn.query(
    'SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ? AND COLUMN_NAME = ? LIMIT 1',
    [database, table, column],
  );
  return rows.length > 0;
}

async function indexExists(conn, database, table, index) {
  const [rows] = await conn.query(
    'SELECT 1 FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ? AND INDEX_NAME = ? LIMIT 1',
    [database, table, index],
  );
  return rows.length > 0;
}

async function constraintExists(conn, database, table, constraint) {
  const [rows] = await conn.query(
    'SELECT 1 FROM information_schema.TABLE_CONSTRAINTS WHERE CONSTRAINT_SCHEMA = ? AND TABLE_NAME = ? AND CONSTRAINT_NAME = ? LIMIT 1',
    [database, table, constraint],
  );
  return rows.length > 0;
}

async function ensureColumn(conn, database, table, column, definition) {
  if (await columnExists(conn, database, table, column)) return false;
  await conn.query(`ALTER TABLE \`${table}\` ADD COLUMN \`${column}\` ${definition}`);
  console.log(`  + ${table}.${column}`);
  return true;
}

async function ensureIndex(conn, database, table, name, definition) {
  if (await indexExists(conn, database, table, name)) return false;
  await conn.query(`ALTER TABLE \`${table}\` ADD INDEX \`${name}\` (${definition})`);
  console.log(`  + index ${table}.${name}`);
  return true;
}

async function ensureForeignKey(conn, database, table, name, definition) {
  if (await constraintExists(conn, database, table, name)) return false;
  await conn.query(`ALTER TABLE \`${table}\` ADD CONSTRAINT \`${name}\` ${definition}`);
  console.log(`  + foreign key ${table}.${name}`);
  return true;
}

async function runSqlFile(conn, file) {
  const sql = fs.readFileSync(file, 'utf8');
  const statements = sql
    .split(/;\s*(?:\r?\n|$)/)
    .map((statement) => statement.replace(/^\s*--.*$/gm, '').trim())
    .filter(Boolean);
  for (const statement of statements) {
    await conn.query(statement);
  }
}

async function main() {
  console.log(`[migrate] target ${config.db.host}:${config.db.port}/${config.db.database}`);
  const conn = await mysql.createConnection({
    host: config.db.host,
    port: config.db.port,
    user: config.db.user,
    password: config.db.password,
    multipleStatements: false,
    ssl: config.db.ssl,
  });

  try {
    await conn.query(
      `CREATE DATABASE IF NOT EXISTS \`${config.db.database}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci`,
    );
    await conn.query(`USE \`${config.db.database}\``);

    await conn.query(`CREATE TABLE IF NOT EXISTS SchemaMigration (
      migration_id INT AUTO_INCREMENT PRIMARY KEY,
      filename VARCHAR(200) NOT NULL UNIQUE,
      applied_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB`);

    const files = fs.readdirSync(MIGRATIONS_DIR).filter((file) => file.endsWith('.sql')).sort();
    for (const file of files) {
      console.log(`[migrate] applying ${file}`);
      await runSqlFile(conn, path.join(MIGRATIONS_DIR, file));
      await conn.query('INSERT IGNORE INTO SchemaMigration (filename) VALUES (?)', [file]);
    }

    console.log('[migrate] adding columns required by the extension workflows');
    await ensureColumn(conn, config.db.database, 'Analyst', 'password_hash', 'VARCHAR(255) NULL');
    await ensureColumn(conn, config.db.database, 'Analyst', 'is_active', 'TINYINT(1) NOT NULL DEFAULT 1');
    await ensureColumn(conn, config.db.database, 'Analyst', 'last_login', 'DATETIME NULL');
    await ensureColumn(conn, config.db.database, 'Analyst', 'created_at', 'DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP');
    await ensureColumn(conn, config.db.database, 'SecurityEvent', 'report_id', 'INT NULL');
    await ensureColumn(conn, config.db.database, 'Alert', 'report_id', 'INT NULL');

    await ensureIndex(conn, config.db.database, 'SecurityEvent', 'idx_event_report', '`report_id`');
    await ensureIndex(conn, config.db.database, 'Alert', 'idx_alert_report', '`report_id`');
    await ensureForeignKey(
      conn,
      config.db.database,
      'SecurityEvent',
      'fk_event_report',
      'FOREIGN KEY (`report_id`) REFERENCES WebsiteReport(report_id) ON DELETE SET NULL',
    );
    await ensureForeignKey(
      conn,
      config.db.database,
      'Alert',
      'fk_alert_report',
      'FOREIGN KEY (`report_id`) REFERENCES WebsiteReport(report_id) ON DELETE SET NULL',
    );

    console.log('[migrate] done. Existing records were preserved.');
  } finally {
    await conn.end();
  }
}

main().catch((err) => {
  console.error('[migrate] failed:', err.message);
  if (err.code === 'ECONNREFUSED') {
    console.error('[migrate] The MySQL server is not reachable. Check DB_HOST / DB_PORT / DB_USER / DB_PASSWORD in backend/.env');
  }
  process.exit(1);
});
