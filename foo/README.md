# Auth

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
![Node](https://img.shields.io/badge/Node-%3E%3D25-339933?logo=node.js&logoColor=white)
![TypeScript](https://img.shields.io/badge/TypeScript-5.x-3178C6?logo=typescript&logoColor=white)

Auth is the shared authentication and authorization service used by Parametric and Corpus. It manages users, sessions, app access, and permission assignment through a central SQLite database.

## Requirements

- Node.js 25+
- npm

## Setup

1. Install dependencies:

   ```bash
   npm install
   ```

2. Copy env file:

   ```bash
   cp .env.example .env
   ```

3. Build and run:

   ```bash
   npm run build
   npm start
   ```

## Environment

| Variable                    | Description                                             |
| --------------------------- | ------------------------------------------------------- |
| `PORT`, `HOST`              | Server bind address (defaults: `3010`, `127.0.0.1`).    |
| `SESSION_SECRET`            | Required; 32+ characters.                               |
| `TRUST_PROXY`               | Set to `1` behind reverse proxy.                        |
| `CENTRAL_DB_PATH`           | Central SQLite DB path (shared with Parametric/Corpus). |
| `AUTH_COOKIE_DOMAIN`        | Cookie domain for shared auth session.                  |
| `AUTH_COOKIE_NAME`          | Auth session cookie name.                               |
| `AUTH_PUBLIC_BASE_URL`      | Public base URL for login redirects.                    |
| `AUTH_ALLOWED_ORIGINS`      | Comma-separated CORS allowlist.                         |
| `AUTH_ALLOWED_NEXT_ORIGINS` | Comma-separated allowlist for `next` redirect URLs.     |

## Scripts

| Script                    | Description                             |
| ------------------------- | --------------------------------------- |
| `npm run build`           | Compile TypeScript to `dist/`.          |
| `npm start`               | Run production server from `dist/`.     |
| `npm run bootstrap:admin` | Build and bootstrap initial admin user. |
| `npm run lint`            | Run ESLint.                             |
| `npm run format`          | Run Prettier formatting.                |

## License

GPL-3.0-or-later
