// Real API and real PPP session against the internal test fixture, not FortiGate.
const { chromium } = require('/app/node_modules/playwright');
const assert = require('node:assert/strict');
(async () => {
  const browser = await chromium.launch({headless: true, channel: 'chromium', args: ['--no-sandbox']});
  try {
    const page = await browser.newPage({viewport: {width: 1360, height: 1050}});
    await page.goto('http://127.0.0.1:8787');
    await page.locator('#status-badge[data-state="disconnected"]').waitFor();
    await page.getByLabel('Connection name', {exact: false}).fill('Local protocol test');
    await page.getByLabel('Remote gateway', {exact: true}).fill(process.env.LAB_GATEWAY);
    await page.getByLabel('Port', {exact: true}).fill('8443');
    await page.getByLabel('Username', {exact: true}).fill('test-user-otp');
    await page.getByLabel('Password', {exact: true}).fill('test-password');
    await page.getByLabel('One-time code', {exact: false}).fill('123456');
    await page.getByText('Additional settings', {exact: true}).click();
    await page.getByLabel('Ignore certificate validation', {exact: true}).check();
    await page.getByText('Additional settings', {exact: true}).click();
    await page.getByRole('button', {name: 'Test gateway', exact: true}).click();
    await page.locator('#gateway-test-message[data-result="success"]').waitFor();
    await page.getByRole('button', {name: 'Connect VPN', exact: true}).click();
    await page.locator('#status-badge[data-state="connected"]').waitFor({timeout: 25000});
    assert.equal(await page.locator('#password').inputValue(), '');
    assert.equal(await page.locator('#otp').inputValue(), '');
    await page.screenshot({path: '/artifacts/lab-connected.png', fullPage: true});
    await page.getByRole('button', {name: 'Disconnect VPN', exact: true}).click();
    await page.locator('#status-badge[data-state="disconnected"]').waitFor({timeout: 20000});
    console.log('PASS: real browser gateway check, connect, PPP readiness, cleared secrets, screenshot and disconnect (no API mocks).');
  } finally {
    await browser.close();
  }
})().catch(error => {console.error(error); process.exit(1);});
