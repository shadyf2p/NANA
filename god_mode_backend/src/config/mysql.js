import mysql from "mysql2/promise";
import { env } from "./env.js";

export const pool = mysql.createPool({
  host: env.mysqlHost,
  port: env.mysqlPort,
  user: env.mysqlUser,
  password: env.mysqlPassword,
  database: env.mysqlDatabase,
  connectionLimit: env.mysqlPoolSize,
  waitForConnections: true,
  namedPlaceholders: true
});

export async function dbQuery(sql, params = {}) {
  const [rows] = await pool.execute(sql, params);
  return rows;
}

