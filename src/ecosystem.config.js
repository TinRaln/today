module.exports = {
  apps: [{
    name: 'today-gateway',
    script: 'server.js',
    cwd: '/www/today-gateway',
    env: {
      PORT: '7867',
      UPSTREAM: 'http://127.0.0.1:7868',
      UPSTREAM_API_KEY: 'REPLACE_WITH_UPSTREAM_API_KEY',
      ADMIN_TOKEN: 'REPLACE_WITH_RANDOM_HEX',
      ADMIN_PASS: 'REPLACE_WITH_ADMIN_PASSWORD',
      REGCODE: 'REPLACE_WITH_INVITE_CODE',
      CRED_KEY: 'REPLACE_WITH_64HEX_CRED_KEY',
      SESSION_SECRET: 'REPLACE_WITH_RANDOM_HEX',
    },
    max_memory_restart: '300M',
    autorestart: true
  }]
};
