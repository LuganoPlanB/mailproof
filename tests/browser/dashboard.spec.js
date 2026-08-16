const { test, expect } = require('@playwright/test');
const AxeBuilder = require('@axe-core/playwright').default;
const evidenceDir = process.env.BROWSER_EVIDENCE_DIR || 'test-results/evidence';

const shots = async (page, name, sizes) => {
  for (const [width, height, zoom] of sizes) {
    await page.setViewportSize({ width, height });
    await page.locator('html').evaluate((el, n) => { el.style.fontSize = `${n}%`; }, zoom);
    await expect(page.locator('main')).toBeVisible();
    await page.screenshot({ path: `${evidenceDir}/${name}-${width}x${height}-${zoom}.png`, fullPage: true });
  }
};

test('Policy and Audit management journeys are accessible with no JavaScript fallback', async ({ page }) => {
  await page.goto('/policy');
  await expect(page.getByRole('heading', { name: 'Policy', exact: true })).toBeVisible();
  await expect(page.getByLabel('Reason')).toBeVisible();
  await shots(page, 'policy-form', [[1440,900,100],[768,1024,200],[360,800,100]]);
  const a11y = await new AxeBuilder({ page }).analyze();
  expect(a11y.violations.filter(v => ['serious','critical'].includes(v.impact))).toEqual([]);
  await page.locator('select[name=command_type]').selectOption('peer_block_put');
  await page.locator('input[name=value]').fill('192.0.2.0/24');
  await page.locator('textarea[name=reason]').fill('Temporary hostile peer block');
  await page.getByRole('button', { name: 'Preview change' }).click();
  await expect(page.getByRole('heading', { name: 'Review preview' })).toBeVisible();
  await shots(page, 'policy-block-preview', [[1440,900,100],[360,800,100]]);
  await page.goBack().catch(() => null);
  await page.goto('/policy');
  await page.goto('/policy');
  await expect(page.getByRole('button', { name: 'Preview change' })).toBeVisible();
  await page.reload();
  await expect(page.getByRole('heading', { name: 'Policy', exact: true })).toBeVisible();
  await page.locator('select[name=command_type]').selectOption('peer_block_put');
  await page.locator('input[name=value]').fill('192.0.2.0/24');
  await page.locator('textarea[name=reason]').fill('Temporary hostile peer block');
  await page.getByRole('button', { name: 'Preview change' }).click();
  await page.getByRole('button', { name: 'Confirm change' }).click();
  await expect(page.getByText('Command applied.')).toBeVisible();
  await shots(page, 'policy-success', [[1440,900,100]]);
  await page.goto('/policy');
  await page.locator('select[name=command_type]').selectOption('capability_rotate');
  await page.locator('input[name=submitter_id]').fill('fixture-conflict');
  await page.locator('textarea[name=reason]').fill('Conflict recovery assertion');
  await page.getByRole('button', { name: 'Preview change' }).click();
  await expect(page.getByText('Preview unavailable')).toBeVisible();
  await shots(page, 'policy-conflict', [[1440,900,100],[360,800,100]]);
  await page.goto('/policy');
  await page.locator('select[name=command_type]').selectOption('capability_rotate');
  await page.locator('input[name=submitter_id]').fill('fixture-submitter');
  await page.locator('textarea[name=reason]').fill('Rotate compromised capability');
  await page.getByRole('button', { name: 'Preview change' }).click();
  await page.getByRole('button', { name: 'Confirm change' }).click();
  await expect(page.getByRole('heading', { name: 'New capability' })).toBeVisible();
  await page.locator('textarea[aria-label="New capability"]').evaluate(el => { el.value = '[redacted]'; });
  await shots(page, 'policy-rotation-ack', [[1440,900,100],[360,800,100]]);
  await page.setExtraHTTPHeaders({ Origin: 'http://127.0.0.1:3010' });
  await page.getByRole('checkbox').check();
  await page.getByRole('button', { name: 'Continue to audit' }).click();
  await expect(page.getByRole('heading', { name: 'Audit event' })).toBeVisible();
  await expect(page.getByLabel('Audit event detail')).toContainText('fixture-command');
  await expect(page.getByText('verify+one-time-fixture-secret@example.test')).toHaveCount(0);
  await shots(page, 'audit-detail', [[1440,900,100],[768,1024,200]]);
});

test('Policy form remains usable without JavaScript', async ({ browser }) => {
  const context = await browser.newContext({ javaScriptEnabled: false });
  await context.setExtraHTTPHeaders({ Origin: 'http://127.0.0.1:3010', 'Sec-Fetch-Site': 'same-origin' });
  const page = await context.newPage();
  await page.goto('http://127.0.0.1:3010/policy');
  expect(await context.cookies()).toHaveLength(1);
  await page.locator('select[name=command_type]').selectOption('capability_rotate');
  await page.locator('input[name=submitter_id]').fill('fixture-submitter');
  await page.locator('textarea[name=reason]').fill('No JavaScript fallback journey');
  await expect(page.getByRole('button', { name: 'Preview change' })).toBeVisible();
  await page.getByRole('button', { name: 'Preview change' }).click();
  await expect(page.getByRole('heading', { name: 'Review preview' })).toBeVisible();
  await page.getByRole('button', { name: 'Confirm change' }).click();
  await expect(page.getByRole('heading', { name: 'New capability' })).toBeVisible();
  await page.getByRole('checkbox').check();
  await page.getByRole('button', { name: 'Continue to audit' }).click();
  await expect(page.getByRole('heading', { name: 'Audit event' })).toBeVisible();
  await page.goto('http://127.0.0.1:3010/policy');
  await page.reload();
  await expect(page.getByText('verify+one-time-fixture-secret@example.test')).toHaveCount(0);
  await page.goBack();
  await expect(page.getByText('verify+one-time-fixture-secret@example.test')).toHaveCount(0);
  await context.close();
});
