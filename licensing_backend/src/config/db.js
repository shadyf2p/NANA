import mysql from "mysql2/promise";
import { env } from "./env.js";

export const dbPool = mysql.createPool({
  host: env.dbHost,
  port: env.dbPort,
  user: env.dbUser,
  password: env.dbPassword,
  database: env.dbName,
  connectionLimit: env.dbConnLimit,
  waitForConnections: true,
  namedPlaceholders: true
});

export async function query(sql, params = {}) {
  const [rows] = await dbPool.execute(sql, params);
  return rows;
}

export async function withTransaction(fn) {
  const conn = await dbPool.getConnection();
  try {
    await conn.beginTransaction();
    const result = await fn(conn);
    await conn.commit();
    return result;
  } catch (error) {
    await conn.rollback();
    throw error;
  } finally {
    conn.release();
  }
}

