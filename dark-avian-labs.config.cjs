const path = require('path');

const APPS_ROOT = process.env.DARK_AVIAN_APPS_ROOT || path.join(__dirname, 'applications');

const baseApp = {
  namespace: 'dark-avian-labs',
  script: './dist/server/index.js',
  interpreter: 'node',
  node_args: '--env-file=.env.production',
  instances: 1,
  exec_mode: 'fork',
  watch: false,
  max_memory_restart: '500M',
  error_file: './logs/pm2-error.log',
  out_file: './logs/pm2-out.log',
  log_date_format: 'YYYY-MM-DD HH:mm:ss Z',
  merge_logs: true,
  autorestart: true,
  max_restarts: 3,
  min_uptime: '10s',
  listen_timeout: 10000,
  kill_timeout: 5000,
  env: {
    NODE_ENV: 'production',
  },
};

module.exports = {
  apps: [
    {
      ...baseApp,
      name: 'Auth',
      cwd: path.join(APPS_ROOT, 'auth'),
      env: {
        ...baseApp.env,
        PORT: '3000',
      },
    },
    {
      ...baseApp,
      name: 'Corpus',
      cwd: path.join(APPS_ROOT, 'corpus'),
      env: {
        ...baseApp.env,
        PORT: '3001',
      },
    },
    {
      ...baseApp,
      name: 'Parametric',
      cwd: path.join(APPS_ROOT, 'parametric'),
      env: {
        ...baseApp.env,
        PORT: '3002',
      },
    },
  ],
};
