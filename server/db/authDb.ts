import Database from 'better-sqlite3';
import fs from 'fs';
import path from 'path';

import { CENTRAL_DB_PATH } from '../config.js';

if (!fs.existsSync(path.dirname(CENTRAL_DB_PATH))) {
  fs.mkdirSync(path.dirname(CENTRAL_DB_PATH), { recursive: true });
}

export const db = new Database(CENTRAL_DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

function normalizeUsersSchema(): void {
  const rows = db.prepare('PRAGMA table_info(users)').all() as Array<{
    name: string;
  }>;
  if (rows.length === 0) return;

  const hasDisplayName = rows.some((row) => row.name === 'display_name');
  const hasEmail = rows.some((row) => row.name === 'email');
  const hasAvatar = rows.some((row) => row.name === 'avatar');

  if (!hasDisplayName) {
    db.exec(
      "ALTER TABLE users ADD COLUMN display_name TEXT NOT NULL DEFAULT ''",
    );
  }
  if (!hasEmail) {
    db.exec("ALTER TABLE users ADD COLUMN email TEXT NOT NULL DEFAULT ''");
  }
  if (!hasAvatar) {
    db.exec('ALTER TABLE users ADD COLUMN avatar INTEGER NOT NULL DEFAULT 1');
  }
}

function normalizeSessionsSchema(): void {
  const rows = db.prepare('PRAGMA table_info(sessions)').all() as Array<{
    name: string;
  }>;
  if (rows.length === 0) return;

  const hasExpire = rows.some((row) => row.name === 'expire');
  const hasExpired = rows.some((row) => row.name === 'expired');
  if (!hasExpire && hasExpired) {
    db.exec('ALTER TABLE sessions RENAME COLUMN expired TO expire');
  }
}

export function createSchema(): void {
  normalizeUsersSchema();
  normalizeSessionsSchema();
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL UNIQUE COLLATE NOCASE,
      password_hash TEXT NOT NULL,
      is_admin INTEGER NOT NULL DEFAULT 0,
      display_name TEXT NOT NULL DEFAULT '',
      email TEXT NOT NULL DEFAULT '',
      avatar INTEGER NOT NULL DEFAULT 1,
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

    CREATE TABLE IF NOT EXISTS user_app_permissions (
      user_id INTEGER NOT NULL,
      app_id TEXT NOT NULL,
      permission TEXT NOT NULL,
      PRIMARY KEY (user_id, app_id, permission),
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
    CREATE INDEX IF NOT EXISTS idx_user_app_permissions_user_app
      ON user_app_permissions(user_id, app_id);
    CREATE INDEX IF NOT EXISTS idx_audit_log_created_at
      ON audit_log(created_at);
  `);
}

export type UserRow = {
  id: number;
  username: string;
  password_hash: string;
  is_admin: number;
  display_name: string;
  email: string;
  avatar: number;
  created_at: string;
};

export function getUserByUsername(username: string): UserRow | undefined {
  return db
    .prepare(
      'SELECT id, username, password_hash, is_admin, display_name, email, avatar, created_at FROM users WHERE username = ?',
    )
    .get(username.trim()) as UserRow | undefined;
}

export function getUserById(userId: number): UserRow | undefined {
  return db
    .prepare(
      'SELECT id, username, password_hash, is_admin, display_name, email, avatar, created_at FROM users WHERE id = ?',
    )
    .get(userId) as UserRow | undefined;
}

export function getGamesForUser(userId: number): string[] {
  const rows = db
    .prepare('SELECT game_id FROM user_game_access WHERE user_id = ?')
    .all(userId) as Array<{ game_id: string }>;
  return rows.map((row) => row.game_id);
}

export function getGamesForUsers(userIds: number[]): Record<number, string[]> {
  const uniqueUserIds = Array.from(
    new Set(userIds.filter((value) => Number.isInteger(value) && value > 0)),
  );
  const gamesByUserId: Record<number, string[]> = {};
  for (const userId of uniqueUserIds) {
    gamesByUserId[userId] = [];
  }
  if (uniqueUserIds.length === 0) {
    return gamesByUserId;
  }

  const placeholders = uniqueUserIds.map(() => '?').join(', ');
  const rows = db
    .prepare(
      `SELECT user_id, game_id
       FROM user_game_access
       WHERE user_id IN (${placeholders})
       ORDER BY user_id, game_id`,
    )
    .all(...uniqueUserIds) as Array<{ user_id: number; game_id: string }>;

  for (const row of rows) {
    gamesByUserId[row.user_id] ??= [];
    gamesByUserId[row.user_id].push(row.game_id);
  }
  return gamesByUserId;
}

export function hasAppAccess(userId: number, appId: string): boolean {
  const row = db
    .prepare('SELECT 1 FROM user_game_access WHERE user_id = ? AND game_id = ?')
    .get(userId, appId);
  return Boolean(row);
}

export function setAppAccess(
  userId: number,
  appId: string,
  enabled: boolean,
): void {
  if (enabled) {
    db.prepare(
      'INSERT OR IGNORE INTO user_game_access (user_id, game_id) VALUES (?, ?)',
    ).run(userId, appId);
    return;
  }
  db.prepare(
    'DELETE FROM user_game_access WHERE user_id = ? AND game_id = ?',
  ).run(userId, appId);
}

export function listPermissions(
  userId: number,
  appId?: string,
): Array<{ app_id: string; permission: string }> {
  if (!appId) {
    return db
      .prepare(
        'SELECT app_id, permission FROM user_app_permissions WHERE user_id = ? ORDER BY app_id, permission',
      )
      .all(userId) as Array<{ app_id: string; permission: string }>;
  }
  return db
    .prepare(
      'SELECT app_id, permission FROM user_app_permissions WHERE user_id = ? AND (app_id = ? OR app_id = ?) ORDER BY app_id, permission',
    )
    .all(userId, appId, '*') as Array<{ app_id: string; permission: string }>;
}

export function listPermissionsForUsers(
  userIds: number[],
): Record<number, Array<{ app_id: string; permission: string }>> {
  const uniqueUserIds = Array.from(
    new Set(userIds.filter((value) => Number.isInteger(value) && value > 0)),
  );
  const permissionsByUserId: Record<
    number,
    Array<{ app_id: string; permission: string }>
  > = {};
  for (const userId of uniqueUserIds) {
    permissionsByUserId[userId] = [];
  }
  if (uniqueUserIds.length === 0) {
    return permissionsByUserId;
  }

  const placeholders = uniqueUserIds.map(() => '?').join(', ');
  const rows = db
    .prepare(
      `SELECT user_id, app_id, permission
       FROM user_app_permissions
       WHERE user_id IN (${placeholders})
       ORDER BY user_id, app_id, permission`,
    )
    .all(...uniqueUserIds) as Array<{
    user_id: number;
    app_id: string;
    permission: string;
  }>;

  for (const row of rows) {
    permissionsByUserId[row.user_id] ??= [];
    permissionsByUserId[row.user_id].push({
      app_id: row.app_id,
      permission: row.permission,
    });
  }
  return permissionsByUserId;
}

export function replacePermissions(
  userId: number,
  appId: string,
  permissions: string[],
): void {
  const tx = db.transaction(() => {
    db.prepare(
      'DELETE FROM user_app_permissions WHERE user_id = ? AND app_id = ?',
    ).run(userId, appId);
    const insert = db.prepare(
      'INSERT OR IGNORE INTO user_app_permissions (user_id, app_id, permission) VALUES (?, ?, ?)',
    );
    for (const permission of permissions) {
      insert.run(userId, appId, permission);
    }
  });
  tx();
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
