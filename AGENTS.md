# Auth

## Cursor Cloud specific instructions

### Overview

Auth is the central authentication/authorization service for Dark Avian Labs. It manages users, sessions, app access, and roles via a SQLite database (`central.db`). Armory and Codex depend on it.

### Running the service

See `README.md` for standard scripts (`pnpm run build`, `pnpm start`, `pnpm run validate`, etc.).

To start in development mode after building:

```bash
NODE_ENV=development node --env-file=.env dist/server/index.js
```

The server listens on port 3000 by default.

### Key gotchas

- **Node >= 25 and pnpm >= 11 required.** The VM ships with Node 22; use `nvm install 25` and `npm install -g pnpm@11.1.3`.
- **Encrypted `.env.development` / `.env.production` files.** These are encrypted with dotenvx and cannot be decrypted without `DOTENV_PRIVATE_KEY_DEVELOPMENT` / `DOTENV_PRIVATE_KEY_PRODUCTION`. For local dev, create a plain `.env` file from `.env.example` and run with `node --env-file=.env`. The `--env-file` flag pre-loads env vars before dotenvx runs, so the correct values take precedence over garbled encrypted values.
- **Database must exist before first start.** `server/auth/service.ts` calls `db.prepare()` at import time (before `createSchema()` in `index.ts`). On a fresh setup, you must pre-create the schema. A quick way:
  ```bash
  mkdir -p data
  node -e "const D=require('better-sqlite3');const db=new D('./data/central.db');db.pragma('journal_mode=WAL');db.exec('CREATE TABLE IF NOT EXISTS sessions(sid TEXT PRIMARY KEY,sess TEXT NOT NULL,expire TEXT NOT NULL);CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT,username TEXT NOT NULL UNIQUE COLLATE NOCASE,password_hash TEXT NOT NULL,is_admin INTEGER NOT NULL DEFAULT 0,display_name TEXT NOT NULL DEFAULT \\'\\',email TEXT NOT NULL DEFAULT \\'\\',created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);CREATE TABLE IF NOT EXISTS user_game_access(user_id INTEGER NOT NULL,game_id TEXT NOT NULL,PRIMARY KEY(user_id,game_id),FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE);CREATE TABLE IF NOT EXISTS user_app_roles(user_id INTEGER NOT NULL,app_id TEXT NOT NULL,role TEXT NOT NULL CHECK(role IN(\\'user\\',\\'admin\\')),PRIMARY KEY(user_id,app_id),FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE);CREATE TABLE IF NOT EXISTS audit_log(id INTEGER PRIMARY KEY AUTOINCREMENT,actor_user_id INTEGER,event_type TEXT NOT NULL,target_type TEXT,target_id TEXT,details_json TEXT,ip TEXT,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)');db.close()"
  ```
  Subsequent starts reuse the existing database.
- **Vite build picks up encrypted `.env.production`** for `VITE_BASE_PATH`, producing garbled asset paths in `dist/client/index.html`. Fix by rebuilding the client with: `npx vite build --mode devbuild` (uses only `.env`, not the encrypted mode-specific files).
- **No public registration endpoint.** Users are created via the admin API (`POST /api/admin/users`), which requires an existing admin session. For initial dev setup, insert a user directly into SQLite.
- **Session cookies use `Domain=.example.test`** in dev, so browser-based login only works when the request host matches (e.g. via `/etc/hosts`). CLI-based auth via curl with manual cookie handling works without host mapping.
