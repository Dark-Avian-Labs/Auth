import path from 'path';

process.env.NODE_ENV = 'test';
process.env.BASE_PROTOCOL ??= 'https';
process.env.BASE_DOMAIN ??= 'example.test';
process.env.AUTH_SUBDOMAIN ??= 'auth';
process.env.APP_LIST ??= 'armory,codex';
process.env.CENTRAL_DB_PATH = path.join(process.cwd(), 'data', 'auth.test.db');

process.env.APP_PUBLIC_BASE_URL ??= 'https://auth.example.test';

const { createSchema } = await import('../db/authDb.js');
createSchema();
