import argon2 from 'argon2';

import {
  db,
  createSchema,
  getUserByUsername,
  replacePermissions,
  setAppAccess,
} from './db.js';

/**
 * One-time bootstrap script:
 * 1) Edit ADMIN_USERNAME / ADMIN_PASSWORD below
 * 2) Run: npm run bootstrap:admin
 */
const ADMIN_USERNAME: string = 'replace_me_admin';
const ADMIN_PASSWORD: string = 'replace_me_password_please_change';
const APPS = ['parametric', 'corpus'];
const CORPUS_SUB_PERMISSIONS = ['corpus.*'];

if (
  ADMIN_USERNAME === 'replace_me_admin' ||
  ADMIN_PASSWORD === 'replace_me_password_please_change'
) {
  throw new Error(
    'Set ADMIN_USERNAME and ADMIN_PASSWORD in src/bootstrap-admin.ts before running.',
  );
}

if (ADMIN_PASSWORD.length < 8) {
  throw new Error('ADMIN_PASSWORD must be at least 8 characters.');
}

async function run(): Promise<void> {
  createSchema();
  const passwordHash = await argon2.hash(ADMIN_PASSWORD, {
    type: argon2.argon2id,
    memoryCost: 19 * 1024,
    timeCost: 2,
    parallelism: 1,
  });

  const existing = getUserByUsername(ADMIN_USERNAME);
  let userId: number;
  if (existing) {
    userId = existing.id;
    db.prepare(
      'UPDATE users SET password_hash = ?, is_admin = 1 WHERE id = ?',
    ).run(passwordHash, userId);
  } else {
    const result = db
      .prepare(
        'INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, 1)',
      )
      .run(ADMIN_USERNAME, passwordHash);
    userId = Number(result.lastInsertRowid);
  }

  for (const appId of APPS) {
    setAppAccess(userId, appId, true);
  }

  replacePermissions(userId, '*', ['*']);
  replacePermissions(userId, 'corpus', CORPUS_SUB_PERMISSIONS);

  console.log(
    `Bootstrap complete. Admin "${ADMIN_USERNAME}" (id ${userId}) has full app access and permissions.`,
  );
}

run().catch((err) => {
  console.error('[bootstrap-admin] failed:', err);
  process.exitCode = 1;
});
