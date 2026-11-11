import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { readFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { test } from 'node:test';
import { chromium } from 'playwright';

async function serve(t, handler) {
  const server = createServer(handler);
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(() => {
    server.closeAllConnections();
    return new Promise(resolve => server.close(resolve));
  });
  return `http://127.0.0.1:${server.address().port}`;
}

function waitForReport(page) {
  return page.waitForResponse(async response =>
    response.request().method() === 'GET' &&
    /^\/api\/runs\/[\da-f-]+$/.test(new URL(response.url()).pathname) &&
    response.ok() && (await response.json()).status !== 'running');
}

test('website inspection works without a model or task and rejects unconfigured private targets', async t => {
  const securityRequests = [];
  const website = await serve(t, (request, response) => {
    if (request.url === '/beveiliging-buiten-scope') {
      response.writeHead(302, { Location: '/beveiliging-doorsturen' });
      return response.end();
    }
    if (request.url === '/beveiliging-doorsturen') {
      response.writeHead(302, { Location: privateWebsite });
      return response.end();
    }
    if (request.url === '/beveiliging-start') {
      securityRequests.push(`${request.method} ${request.url}`);
      response.writeHead(302, { Location: '/beveiliging?probe=privaat', 'X-Powered-By': 'redirect-banner' });
      return response.end();
    }
    const missing = request.url === '/ontbreekt';
    const title = missing ? 'Pagina ontbreekt' : 'Testwinkel';
    const headers = { 'Content-Type': 'text/html; charset=utf-8' };
    if (request.url.startsWith('/beveiliging?')) {
      securityRequests.push(`${request.method} ${request.url}`);
      headers['X-Content-Type-Options'] = 'nosniff';
      headers['Set-Cookie'] = ['test-secret-name=private-cookie-value; HttpOnly; SameSite=Lax'];
    }
    response.writeHead(missing ? 404 : 200, headers);
    response.end(`<!doctype html><html lang="nl"><head><meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1"><title>${title}</title></head>
      <body><main><h1>${title}</h1>${missing ? '' : '<p>Welkom in de testwinkel</p>'}</main></body></html>`);
  });
  let privateRequests = 0;
  const privateWebsite = await serve(t, (request, response) => {
    privateRequests++;
    response.end('Privépagina');
  });

  const app = spawn(process.execPath, ['server.mjs'], {
    env: {
      ...process.env,
      PORT: '0',
      TEST_ORIGINS: website,
      LLM_API_KEY: '',
      LLM_ENDPOINT: '',
      LLM_MODEL: '',
    },
    stdio: ['ignore', 'pipe', 'inherit'],
  });
  t.after(() => app.kill());
  const [startup] = await once(app.stdout, 'data', { signal: AbortSignal.timeout(5000) });
  const origin = startup.toString().match(/http:\/\/127\.0\.0\.1:\d+/)?.[0];
  assert.ok(origin);
  const browser = await chromium.launch({ channel: process.env.BROWSER_CHANNEL || 'msedge' });
  t.after(() => browser.close());
  const page = await browser.newPage();
  await page.goto(origin);

  const rejected = await page.request.post(`${origin}/api/runs`, {
    data: { url: privateWebsite, authorized: true },
  });
  assert.equal(rejected.status(), 400);
  assert.equal(privateRequests, 0);

  const targetUrl = page.getByLabel('Website-URL');
  const expectedText = page.getByLabel('Te controleren tekst');
  const startWebsite = page.getByRole('button', { name: 'Start websitetest', exact: true });
  await targetUrl.fill(website);
  await page.getByLabel('Testopdracht').waitFor({ state: 'hidden' });
  await expectedText.fill('Welkom in de testwinkel');
  await page.getByRole('checkbox', { name: 'Ik heb toestemming om deze website te testen.' }).check();
  const [request, response] = await Promise.all([
    page.waitForRequest(candidate => candidate.method() === 'POST' && candidate.url() === `${origin}/api/runs`),
    waitForReport(page),
    startWebsite.click(),
  ]);
  assert.equal(Object.hasOwn(request.postDataJSON(), 'task'), false);
  const report = await response.json();
  assert.equal(report.mode, 'inspection');
  assert.equal(report.status, 'completed');
  assert.equal(report.coverage, 'full');
  assert.equal(report.security, undefined);
  const check = report.steps.find(step => step.check?.value === 'Welkom in de testwinkel');
  assert.equal(check?.status, 'passed');
  assert.equal(check.actual, true);
  assert.ok(check.screenshot);
  const proof = await page.request.get(new URL(check.screenshot, origin).href);
  assert.equal(proof.status(), 200);
  assert.equal(proof.headers()['content-type'], 'image/png');
  await page.getByText('Website · Afgerond · Dekking volledig', { exact: true }).waitFor();
  await page.locator('#preview-image').waitFor({ state: 'visible' });

  const [download] = await Promise.all([
    page.waitForEvent('download'),
    page.getByRole('button', { name: 'Download rapport' }).click(),
  ]);
  const exported = JSON.parse(await readFile(await download.path(), 'utf8'));
  assert.equal(exported.id, report.id);
  assert.equal(exported.mode, 'inspection');
  assert.equal(exported.steps.find(step => step.id === check.id).screenshot, new URL(check.screenshot, origin).href);

  await targetUrl.fill(`${website}/beveiliging-start`);
  const securityOption = page.getByRole('checkbox', { name: 'Passieve beveiligingscontrole' });
  await securityOption.check();
  const [securityResponse] = await Promise.all([waitForReport(page), startWebsite.click()]);
  const securityRun = await securityResponse.json();
  assert.deepEqual(securityRequests, ['GET /beveiliging-start', 'GET /beveiliging?probe=privaat']);
  assert.equal(securityRun.status, 'completed');
  assert.equal(securityRun.securityRequested, true);
  const security = securityRun.security;
  assert.equal(security.mode, 'passive');
  assert.deepEqual(security.document, {
    url: `${website}/beveiliging`, httpStatus: 200, evidenceStepId: securityRun.steps[0].id,
  });
  assert.equal(security.checks.find(check => check.id === 'nosniff').status, 'observed');
  assert.equal(security.checks.find(check => check.id === 'cookie-httponly').status, 'observed');
  assert.equal(security.checks.find(check => check.id === 'banner').status, 'observed');
  assert.doesNotMatch(JSON.stringify(securityRun), /test-secret-name|private-cookie-value/);
  await page.getByRole('heading', { name: 'Beveiligingscontrole', exact: true }).waitFor();
  await page.getByText('Bekijk beveiligingscontroles', { exact: true }).click();
  await page.getByText('X-Content-Type-Options: nosniff waargenomen.', { exact: true }).waitFor();
  assert.ok(await page.getByRole('link', { name: /ASVS v5.0.0-3.4.4/ }).getAttribute('href'));
  const persisted = JSON.parse(await readFile(new URL(`../runs/${securityRun.id}/report.json`, import.meta.url), 'utf8'));
  assert.deepEqual(persisted.security, security);

  await targetUrl.fill(`${website}/beveiliging-buiten-scope`);
  const [blockedResponse] = await Promise.all([waitForReport(page), startWebsite.click()]);
  const blockedRun = await blockedResponse.json();
  assert.equal(blockedRun.status, 'error');
  assert.equal(blockedRun.security.document, null);
  assert.ok(blockedRun.security.checks.every(check => check.status === 'not_observed'));
  assert.equal(privateRequests, 0);

  await securityOption.uncheck();
  await targetUrl.fill(`${website}/ontbreekt`);
  await expectedText.clear();
  const [notFoundResponse] = await Promise.all([waitForReport(page), startWebsite.click()]);
  const notFound = await notFoundResponse.json();
  assert.equal(notFound.status, 'failed');
  assert.equal(notFound.coverage, 'partial');
  assert.ok(notFound.steps.some(step => step.status === 'failed' && /404/.test(step.detail)));
  await page.getByText('Website · Fout gevonden · Dekking gedeeltelijk', { exact: true }).waitFor();
  await page.getByRole('heading', { name: 'Beveiligingscontrole', exact: true }).waitFor({ state: 'hidden' });
});
