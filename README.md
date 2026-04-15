# Auth

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
[![Cursor](https://img.shields.io/badge/Cursor-IDE-141414?logo=cursor&logoColor=white)](https://cursor.com)
![Node](https://img.shields.io/badge/Node-%3E%3D25-339933?logo=node.js&logoColor=white)
![TypeScript](https://img.shields.io/badge/TypeScript-6.x-3178C6?logo=typescript&logoColor=white)
![React](https://img.shields.io/badge/React-19.x-61DAFB?logo=react&logoColor=black)
![Vite](https://img.shields.io/badge/Vite-8.x-646CFF?logo=vite&logoColor=white)
![Tailwind CSS](https://img.shields.io/badge/Tailwind_CSS-4.x-06B6D4?logo=tailwindcss&logoColor=white)

Auth is the shared authentication and authorization service used by the other Dark Avian Labs apps.
It manages users, sessions, app access, and permission assignments through a central SQLite database.
Auth is the single point of truth for user-related concerns for apps that integrate with it.

## Requirements

- Node.js 25+
- pnpm 11+

## Setup

1. Install Node.js and pnpm using your preferred method for your OS.

2. Install dependencies:

   ```bash
   pnpm install
   ```

3. Copy and edit the environment file:

   ```bash
   cp .env.example .env
   nano .env
   ```

4. Build and run:

   ```bash
   pnpm run build
   pnpm start
   ```

## dotenvx and encrypted env files

This project supports `dotenvx` for local `.env` loading and can optionally use encrypted env artifacts.

- Use `pnpm dlx dotenvx encrypt` to encrypt your local `.env` file when you want it safe to commit.
- That flow also creates a `.env.keys` file with your private encryption key, which must **never** be committed.
- To change variables, use `pnpm dlx dotenvx decrypt` with the key in `.env.keys` to restore a plain `.env`.
- Re-encrypt afterward (keys are reused) and commit only the encrypted artifacts.
- Store private keys in your secrets manager the same way you would an SSH deploy key.

Suggested secret naming when vault is enabled:

- `DOTENV_PRIVATE_KEY_DEVELOPMENT`
- `DOTENV_PRIVATE_KEY_PRODUCTION`

Use one key per environment to reduce blast radius.

## Environment variables

Server and client read from `.env.production` / `.env.development` / `.env.test` (see `server/config.ts`). Common variables:

| Variable                     | Description                                                                        |
| ---------------------------- | ---------------------------------------------------------------------------------- |
| `PORT`, `HOST`               | Server bind address (defaults: `3000`, `127.0.0.1`).                               |
| `NODE_ENV`                   | `development`, `test`, or `production`.                                            |
| `SESSION_SECRET`             | Required in production; 32+ characters recommended.                                |
| `TRUST_PROXY`                | Set to `1` behind a reverse proxy.                                                 |
| `SECURE_COOKIES`             | Set to `1` for HTTPS-only cookie behavior in production.                           |
| `CENTRAL_DB_PATH`            | Path to the central SQLite database (default: `./data/central.db` under data dir). |
| `BASE_DOMAIN`                | Required. Apex domain used to build per-app URLs (e.g. `example.com`).             |
| `BASE_PROTOCOL`              | `http` or `https` (default: `https` in production, `http` otherwise).              |
| `AUTH_SUBDOMAIN`             | Subdomain for this service (default: `auth`). Builds public auth base URL.         |
| `APP_LIST`                   | Comma-separated app ids (`corpus`, `parametric`, …); drives allowed app origins.   |
| `COOKIE_DOMAIN`              | Cookie domain for shared session (default: `.<BASE_DOMAIN>`).                      |
| `AUTH_COOKIE_DOMAIN`         | Override for auth cookies (defaults to `COOKIE_DOMAIN`).                           |
| `AUTH_COOKIE_NAME`           | Auth session cookie name.                                                          |
| `SESSION_COOKIE_NAME`        | Session store cookie name (defaults to `AUTH_COOKIE_NAME`).                        |
| `SHARED_THEME_COOKIE_DOMAIN` | Domain for shared theme cookie.                                                    |
| `AUTH_API_RATE_LIMIT_*`      | Optional API rate limit window / max requests.                                     |

Client `VITE_*` variables are documented in `.env.example`.

## Scripts

| Script                   | Description                                       |
| ------------------------ | ------------------------------------------------- |
| `pnpm run build`         | Typecheck, compile server, and Vite client build. |
| `pnpm start`             | Run production server from `dist/`.               |
| `pnpm run typecheck`     | Typecheck server and client.                      |
| `pnpm run lint`          | Run Oxlint.                                       |
| `pnpm run lint:fix`      | Run Oxlint with `--fix`.                          |
| `pnpm run format`        | Run Oxfmt.                                        |
| `pnpm run check-format`  | Verify Oxfmt formatting.                          |
| `pnpm run validate`      | Format check, lint, typecheck, and tests.         |
| `pnpm run test`          | Run Vitest once.                                  |
| `pnpm run test:watch`    | Run Vitest in watch mode.                         |
| `pnpm run test:coverage` | Run Vitest with coverage.                         |

## License

GPL-3.0-or-later
