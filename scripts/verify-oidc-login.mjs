import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const root = process.env.HETEROSECRETS_PLAYWRIGHT_ROOT;
if (!root) throw new Error('Playwright root is required');
const require = createRequire(join(root, 'package.json'));
const { chromium } = require('playwright');
const { origin, email, password } = JSON.parse(readFileSync(0, 'utf8'));

const proxyServer = process.env.HETEROSECRETS_PLAYWRIGHT_PROXY;
const browser = await chromium.launch({
  headless: true,
  ...(proxyServer ? { proxy: { server: proxyServer } } : {}),
});
try {
  const page = await browser.newPage();
  await page.goto(origin + '/ui/', { waitUntil: 'networkidle', timeout: 20000 });
  await page.locator('select').first().selectOption('oidc');
  await page.locator('input[name="role"]').fill('users');
  // The UI starts debounced role lookups after each form change. Wait for
  // their network requests and model updates before asking it to open OIDC.
  await page.waitForTimeout(550);
  await page.waitForLoadState('networkidle', { timeout: 20000 });
  await page.waitForTimeout(200);
  const popupPromise = page.waitForEvent('popup', { timeout: 10000 });
  await page.getByRole('button', { name: /Sign in with OIDC Provider/i }).click();
  let popup;
  try {
    popup = await popupPromise;
  } catch {
    throw new Error('OpenBao did not open the OIDC provider: ' +
                    (await page.locator('body').innerText()).slice(0, 260));
  }
  await popup.waitForURL(/\/id\/realms\/heterocloud\//, { timeout: 20000 });
  await popup.locator('#username').fill(email);
  await popup.locator('#password').fill(password);
  await popup.locator('#kc-login').click();
  try {
    await popup.waitForEvent('close', { timeout: 30000 });
  } catch {
    const url = new URL(popup.url());
    throw new Error('OIDC popup did not close: ' + JSON.stringify({
      origin: url.origin, path: url.pathname,
      text: (await popup.locator('body').innerText()).slice(0, 700),
    }));
  }
  await page.waitForURL(url => url.origin === origin &&
                        url.pathname.startsWith('/ui/vault/') &&
                        !url.pathname.startsWith('/ui/vault/auth'),
                        { timeout: 30000 });
  await page.waitForLoadState('networkidle', { timeout: 20000 });
  const body = await page.locator('body').innerText();
  if (/invalid|access denied|permission denied|sign in to openbao/i.test(body.slice(0, 400))) {
    throw new Error('OpenBao did not complete the user sign-in: ' +
                    JSON.stringify({ url: page.url(), text: body.slice(0, 400) }));
  }
  const access = await page.evaluate(async () => {
    // UI's authenticated token is kept in local storage. Never return it.
    const values = Object.entries(localStorage);
    const candidate = values.find(([key]) => /token/i.test(key));
    if (!candidate) return { token_found: false };
    let token = candidate[1];
    try {
      const parsed = JSON.parse(token);
      token = parsed.token || parsed.client_token || token;
    } catch {}
    const headers = { 'X-Vault-Token': token };
    const lookup = await fetch('/v1/auth/token/lookup-self', { headers });
    if (!lookup.ok) return { token_found: true, lookup_status: lookup.status };
    const self = await lookup.json();
    const entity = self?.data?.entity_id;
    if (!/^[0-9a-f-]{36}$/.test(entity || '')) {
      return { token_found: true, lookup_status: lookup.status, entity_found: false };
    }
    const path = '/v1/secret/data/users/' + entity + '/oidc-e2e';
    const write = await fetch(path, {
      method: 'POST', headers: { ...headers, 'Content-Type': 'application/json' },
      body: JSON.stringify({ data: { checked: 'yes' } }),
    });
    let read;
    let readRetries = 0;
    for (let attempt = 0; attempt < 20; attempt++) {
      read = await fetch(path, { headers });
      if (read.status !== 404) break;
      readRetries++;
      await new Promise(resolve => setTimeout(resolve, 250));
    }
    const saved = read.ok ? await read.json() : null;
    const removed = await fetch(path, { method: 'DELETE', headers });
    const owner = await fetch('/v1/secret/data/system/restore-probe', { headers });
    return { token_found: true, lookup_status: lookup.status,
             personal_write: write.status, personal_read: read.status,
             read_retries: readRetries,
             personal_value: saved?.data?.data?.checked,
             personal_delete: removed.status, owner_probe_status: owner.status };
  });
  if (access.lookup_status !== 200 || access.personal_write !== 200 ||
      access.personal_read !== 200 || access.read_retries !== 0 ||
      access.personal_value !== 'yes' ||
      access.personal_delete !== 204 || access.owner_probe_status !== 403) {
    throw new Error('OIDC user privileges differ from the expected personal KV policy: ' +
                    JSON.stringify(access));
  }
  console.log(JSON.stringify({ oidc_login: true, signed_in_url: page.url(),
                               personal_kv: true, read_retries: access.read_retries,
                               owner_probe_status: access.owner_probe_status }));
} finally {
  await browser.close();
}
