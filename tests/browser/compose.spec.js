const { test, expect } = require('@playwright/test');

const dashboardURL = process.env.DASHBOARD_URL;

test.skip(!dashboardURL, 'requires a running Compose dashboard');

test('Compose dashboard serves private pages without external browser requests', async ({ page }) => {
  const unexpected = [];
  page.on('request', request => {
    if (!request.url().startsWith(dashboardURL)) unexpected.push(request.url());
  });

  const health = await page.request.get('/healthz');
  expect(health.status()).toBe(204);
  await page.goto('/');
  await expect(page.getByRole('main')).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Overview', exact: true })).toBeVisible();
  await page.goto('/policy');
  await expect(page.getByRole('heading', { name: 'Policy', exact: true })).toBeVisible();
  await page.goto('/audit');
  await expect(page.getByRole('heading', { name: 'Audit', exact: true })).toBeVisible();
  expect(unexpected).toEqual([]);
});
