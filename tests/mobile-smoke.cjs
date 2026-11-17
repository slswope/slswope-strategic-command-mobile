const assert = require('node:assert/strict');
const { chromium, devices } = require('playwright');

async function checkDashboard() {
  const dashboardUrl = process.env.DASHBOARD_URL;
  assert.ok(dashboardUrl, 'Expected the GitHub Pages deployment URL');

  const browser = await chromium.launch({ channel: 'chrome' });
  try {
    for (const width of [320, 390, 430]) {
      const context = await browser.newContext({
        ...devices['iPhone 13'],
        viewport: { width, height: 844 },
      });
      try {
        const page = await context.newPage();
        const errors = [];
        page.on('pageerror', error => errors.push(error.message));

        const isDataset = response =>
          new URL(response.url()).pathname.endsWith('/data.json') && response.ok();
        const initialDataset = page.waitForResponse(isDataset);
        const foreignDataset = page.waitForResponse(response =>
          new URL(response.url()).pathname.endsWith('/foreign.json') && response.ok());
        const response = await page.goto(dashboardUrl);
        assert.ok(response?.ok(), 'Expected GitHub Pages to serve the dashboard');
        const dataset = await (await initialDataset).json();

        await page.locator('#updated').filter({ hasText: 'Last source check:' }).waitFor();
        assert.ok(dataset.checked_at, 'Expected data from the published workflow');
        assert.equal(await page.locator('#coverage').innerText(),
          `${dataset.coverage.feeds_ok} / ${dataset.coverage.feeds_total}`);
        assert.equal(await page.locator('#posture').innerText(), dataset.local_operations.title);
        assert.equal(await page.locator('#tracks article').count(), dataset.tracks.length);
        assert.match(await page.locator('#tracks').innerText(), /requirements covered/);
        await page.locator('#essential-services').getByRole('heading').waitFor();
        await page.locator('#service-continuity').getByRole('heading', { level: 2 }).waitFor();
        await page.locator('#cyber-advisories').getByRole('heading').waitFor();

        const briefing = await (await foreignDataset).json();
        await page.locator('#foreign-status').filter({ hasText: 'Reviewed ' }).waitFor();
        const developments = page.locator('#foreign-items article');
        assert.equal(await developments.count(), briefing.developments.length);
        assert.ok(briefing.developments.length > 0, 'Expected reviewed foreign developments');
        const source = briefing.developments[0].sources[0];
        assert.equal(await developments.first().getByRole('link', { name: source.name }).getAttribute('href'), source.url);

        const refreshed = page.waitForResponse(isDataset);
        await page.getByRole('button', { name: 'Refresh', exact: true }).click();
        await refreshed;
        const layout = await page.evaluate(() => ({
          viewport: document.documentElement.clientWidth,
          content: document.documentElement.scrollWidth,
        }));
        assert.equal(layout.viewport, width);
        assert.equal(layout.content, width, 'Dashboard overflows the mobile viewport');
        assert.deepEqual(errors, []);
        console.log(`PASS ${width}px: live dataset, refresh, and layout`);
      } finally {
        await context.close();
      }
    }
  } finally {
    await browser.close();
  }
}

checkDashboard().catch(error => {
  console.error(error);
  process.exitCode = 1;
});
