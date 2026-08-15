const { defineConfig } = require('@playwright/test');

const externalDashboard = process.env.DASHBOARD_URL;

module.exports = defineConfig({
  testDir: '.',
  timeout: 30000,
  workers: 1,
  use: { baseURL: externalDashboard || 'http://127.0.0.1:3010' },
  ...(externalDashboard ? {} : {
    webServer: {
      command: 'PATH=/usr/local/go/bin:$PATH go run ./fixture',
      cwd: __dirname,
      url: 'http://127.0.0.1:3010/healthz',
      reuseExistingServer: true,
      timeout: 30000,
    },
  }),
});
