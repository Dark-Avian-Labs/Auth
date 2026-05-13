import fs from 'fs';
import path from 'path';

import Database, { type Database as DatabaseType } from 'better-sqlite3';

import { CENTRAL_DB_PATH } from '../config.js';

if (!fs.existsSync(path.dirname(CENTRAL_DB_PATH))) {
  fs.mkdirSync(path.dirname(CENTRAL_DB_PATH), { recursive: true });
}

export const db: DatabaseType = new Database(CENTRAL_DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

export function createSchema(): void {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL UNIQUE COLLATE NOCASE,
      password_hash TEXT NOT NULL,
      is_admin INTEGER NOT NULL DEFAULT 0,
      display_name TEXT NOT NULL DEFAULT '',
      email TEXT NOT NULL DEFAULT '',
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS user_game_access (
      user_id INTEGER NOT NULL,
      game_id TEXT NOT NULL,
      PRIMARY KEY (user_id, game_id),
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS sessions (
      sid TEXT PRIMARY KEY,
      sess TEXT NOT NULL,
      expire TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS user_app_roles (
      user_id INTEGER NOT NULL,
      app_id TEXT NOT NULL,
      role TEXT NOT NULL CHECK (role IN ('user', 'admin')),
      PRIMARY KEY (user_id, app_id),
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS audit_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      actor_user_id INTEGER,
      event_type TEXT NOT NULL,
      target_type TEXT,
      target_id TEXT,
      details_json TEXT,
      ip TEXT,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

    CREATE INDEX IF NOT EXISTS idx_user_game_access_user_id
      ON user_game_access(user_id);
    CREATE INDEX IF NOT EXISTS idx_user_app_roles_user_id
      ON user_app_roles(user_id);
    CREATE INDEX IF NOT EXISTS idx_audit_log_created_at
      ON audit_log(created_at);
  `);
}

export function migrateSchema(): void {
  const columns = db.prepare('PRAGMA table_info(users)').all() as Array<{ name: string }>;
  if (!columns.some((c) => c.name === 'avatar')) {
    return;
  }
  try {
    db.exec('ALTER TABLE users DROP COLUMN avatar');
  } catch (err) {
    console.warn('[authDb] Failed to DROP COLUMN users.avatar (needs SQLite 3.35+)', err);
  }
}

export type UserRow = {
  id: number;
  username: string;
  password_hash: string;
  is_admin: number;
  display_name: string;
  email: string;
  created_at: string;
};

export function getUserByUsername(username: string): UserRow | undefined {
  return db
    .prepare(
      'SELECT id, username, password_hash, is_admin, display_name, email, created_at FROM users WHERE username = ? COLLATE NOCASE',
    )
    .get(username.trim()) as UserRow | undefined;
}

export function getUserById(userId: number): UserRow | undefined {
  return db
    .prepare(
      'SELECT id, username, password_hash, is_admin, display_name, email, created_at FROM users WHERE id = ?',
    )
    .get(userId) as UserRow | undefined;
}

export function getGamesForUser(userId: number): string[] {
  const rows = db
    .prepare('SELECT game_id FROM user_game_access WHERE user_id = ?')
    .all(userId) as Array<{ game_id: string }>;
  return rows.map((row) => row.game_id);
}

function queryAndGroupByUserId<TRow extends { user_id: number }, TValue>(
  userIds: number[],
  buildSql: (placeholders: string) => string,
  mapRow: (row: TRow) => TValue,
): Record<number, TValue[]> {
  const uniqueUserIds = Array.from(
    new Set(userIds.filter((value) => Number.isInteger(value) && value > 0)),
  );
  const groupedByUserId: Record<number, TValue[]> = {};
  for (const userId of uniqueUserIds) {
    groupedByUserId[userId] = [];
  }
  if (uniqueUserIds.length === 0) {
    return groupedByUserId;
  }

  const placeholders = uniqueUserIds.map(() => '?').join(', ');
  const rows = db.prepare(buildSql(placeholders)).all(...uniqueUserIds) as TRow[];

  for (const row of rows) {
    groupedByUserId[row.user_id] ??= [];
    groupedByUserId[row.user_id].push(mapRow(row));
  }
  return groupedByUserId;
}

export function getGamesForUsers(userIds: number[]): Record<number, string[]> {
  return queryAndGroupByUserId<{ user_id: number; game_id: string }, string>(
    userIds,
    (placeholders) => `SELECT user_id, game_id
       FROM user_game_access
       WHERE user_id IN (${placeholders})
       ORDER BY user_id, game_id`,
    (row) => row.game_id,
  );
}

export function hasAppAccess(userId: number, appId: string): boolean {
  const row = db
    .prepare('SELECT 1 FROM user_game_access WHERE user_id = ? AND game_id = ?')
    .get(userId, appId);
  return Boolean(row);
}

export function setAppAccess(userId: number, appId: string, enabled: boolean): void {
  if (enabled) {
    db.prepare('INSERT OR IGNORE INTO user_game_access (user_id, game_id) VALUES (?, ?)').run(
      userId,
      appId,
    );
    return;
  }
  db.prepare('DELETE FROM user_game_access WHERE user_id = ? AND game_id = ?').run(userId, appId);
  db.prepare('DELETE FROM user_app_roles WHERE user_id = ? AND app_id = ?').run(userId, appId);
}

export type AppRole = 'user' | 'admin';

export function listAppRolesForUser(userId: number): Array<{ app_id: string; role: AppRole }> {
  return db
    .prepare('SELECT app_id, role FROM user_app_roles WHERE user_id = ? ORDER BY app_id')
    .all(userId) as Array<{ app_id: string; role: AppRole }>;
}

export function listAppRolesForUsers(
  userIds: number[],
): Record<number, Array<{ app_id: string; role: AppRole }>> {
  return queryAndGroupByUserId<
    { user_id: number; app_id: string; role: string },
    { app_id: string; role: AppRole }
  >(
    userIds,
    (placeholders) => `SELECT user_id, app_id, role
       FROM user_app_roles
       WHERE user_id IN (${placeholders})
       ORDER BY user_id, app_id`,
    (row) => ({
      app_id: row.app_id,
      role: row.role === 'admin' ? 'admin' : 'user',
    }),
  );
}

export function getAppRoleAssignmentsForUser(
  userId: number,
): Array<{ app_id: string; role: AppRole }> {
  const games = getGamesForUser(userId);
  const rows = listAppRolesForUser(userId);
  const byApp = new Map(rows.map((r) => [r.app_id, r.role]));
  return games.map((app_id) => ({
    app_id,
    role: byApp.get(app_id) === 'admin' ? 'admin' : 'user',
  }));
}

export function setUserAppRole(userId: number, appId: string, role: AppRole | null): void {
  if (role === null || role === 'user') {
    db.prepare('DELETE FROM user_app_roles WHERE user_id = ? AND app_id = ?').run(userId, appId);
    return;
  }
  db.prepare('INSERT OR REPLACE INTO user_app_roles (user_id, app_id, role) VALUES (?, ?, ?)').run(
    userId,
    appId,
    role,
  );
}

export function appendAuditLog(params: {
  actorUserId: number | null;
  eventType: string;
  targetType?: string;
  targetId?: string;
  detailsJson?: string;
  ip?: string;
}): void {
  db.prepare(
    `INSERT INTO audit_log (
      actor_user_id,
      event_type,
      target_type,
      target_id,
      details_json,
      ip
    ) VALUES (?, ?, ?, ?, ?, ?)`,
  ).run(
    params.actorUserId,
    params.eventType,
    params.targetType ?? null,
    params.targetId ?? null,
    params.detailsJson ?? null,
    params.ip ?? null,
  );
}
