const { test, expect } = require('@playwright/test');
const AxeBuilder = require('@axe-core/playwright').default;
for (const [path, name] of [['/', 'overview'], ['/operations', 'operations'], ['/campaigns', 'campaigns'], ['/campaigns/example', 'campaign-detail'], ['/investigations', 'investigations']]) {
  test(`${name} is accessible and responsive`, async ({ page }) => {
    await page.goto(path);
    const accessibility = await new AxeBuilder({ page }).analyze();
    const serious = accessibility.violations.filter(result => ['serious', 'critical'].includes(result.impact));
    expect(serious).toEqual([]);
    for (const viewport of [{ width: 1440, height: 900 }, { width: 360, height: 800 }, { width: 768, height: 1024 }]) {
      await page.setViewportSize(viewport); if (viewport.width === 768) await page.locator('html').evaluate(el => el.style.fontSize = '200%');
      await expect(page.locator('main')).toBeVisible(); await page.screenshot({ path: `evidence/${name}-${viewport.width}x${viewport.height}.png`, fullPage: true });
    }
  });
}
