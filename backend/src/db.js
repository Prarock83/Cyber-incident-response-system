'use strict';

const mysql = require('mysql2/promise');
const config = require('./config');

let pool = null;
let injectedPool = null;

function buildPool() {
  return mysql.createPool({
    host: config.db.host,
    port: config.db.port,
    user: config.db.user,
    password: config.db.password,
    database: config.db.database,
    waitForConnections: true,
    connectionLimit: config.db.connectionLimit,
    queueLimit: 0,
    charset: 'utf8mb4_unicode_ci',
    dateStrings: false,
    ssl: config.db.ssl,
  });
}

async function getPool() {
  if (injectedPool) return injectedPool;
  if (!pool) pool = buildPool();
  return pool;
}

/** Run a query and return rows (SELECT) or the OkPacket (writes). */
async function query(sql, params = []) {
  const active = await getPool();
  const [rows] = await active.query(sql, params);
  return rows;
}

/** Return the first row or null. */
async function one(sql, params = []) {
  const rows = await query(sql, params);
  return Array.isArray(rows) && rows.length ? rows[0] : null;
}

/** Run a write and return the driver result (insertId / affectedRows). */
async function execute(sql, params = []) {
  return query(sql, params);
}

/**
 * Run `fn` inside a transaction. `fn` receives helpers bound to one connection.
 * All work commits together or rolls back together.
 */
async function withTransaction(fn) {
  const active = await getPool();
  const conn = await active.getConnection();
  const tx = {
    query: async (sql, params = []) => {
      const [rows] = await conn.query(sql, params);
      return rows;
    },
    one: async (sql, params = []) => {
      const [rows] = await conn.query(sql, params);
      return Array.isArray(rows) && rows.length ? rows[0] : null;
    },
  };
  try {
    await conn.beginTransaction();
    const result = await fn(tx);
    await conn.commit();
    return result;
  } catch (err) {
    try {
      await conn.rollback();
    } catch (rollbackErr) {
      console.error('[cirs] rollback failed:', rollbackErr.message);
    }
    throw err;
  } finally {
    conn.release();
  }
}

async function health() {
  try {
    await query('SELECT 1 AS ok');
    return true;
  } catch {
    return false;
  }
}

/** Test hook: swap in a fake pool without touching production code paths. */
function __setPoolForTesting(fakePool) {
  injectedPool = fakePool;
}

async function close() {
  if (pool) {
    await pool.end();
    pool = null;
  }
}

module.exports = { query, one, execute, withTransaction, getPool, health, close, __setPoolForTesting };
