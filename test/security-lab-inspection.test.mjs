import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { readFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { test } from 'node:test';
import { chromium } from 'playwright';
import { startSecurityLab } from '../security-lab/server.mjs';
import { labProfile } from '../security-lab/profile.mjs';
import { runActiveSecurity } from '../security-lab/browser-probes.mjs';

function waitForRun(page) {
  return page.waitForResponse(async candidate => candidate.request().method() === 'GET' &&
    candidate.ok() && /^\/api\/runs\/[\da-f-]+$/.test(new URL(candidate.url()).pathname) &&
    (await candidate.json()).status !== 'running');
}

test('the dashboard measures passive settings and active browser behavior in both lab variants', async t => {
  const lab = await startSecurityLab({ port: 0 });
  t.after(() => lab.close());
  const modelInputs = [];
  let unmarkedServiceWrites = 0;
  const modelResponse = 'Het lab toont toegang tot een ander dossier en een sessie die na afmelden actief blijft.';
  const model = createServer(async (request, response) => {
    if (request.url !== '/model') {
      if (request.method === 'POST') unmarkedServiceWrites++;
      response.setHeader('Content-Type', 'text/html');
      response.end('<h1>Andere lokale service</h1>');
      return;
    }
    let body = '';
    for await (const chunk of request) body += chunk;
    modelInputs.push(JSON.parse(body));
    response.setHeader('Content-Type', 'application/json');
    response.end(JSON.stringify({ choices: [{ message: { content: modelResponse } }] }));
  });
  model.listen(0, '127.0.0.1');
  await once(model, 'listening');
  t.after(() => {
    model.closeAllConnections();
    return new Promise(resolve => model.close(resolve));
  });
  const server = spawn(process.execPath, ['server.mjs'], {
    cwd: new URL('../', import.meta.url),
    env: {
      ...process.env,
      PORT: '0',
      TEST_ORIGINS: lab.origin,
      SECURITY_LAB_ORIGIN: lab.origin,
      REQUIRE_DOMAIN_VERIFICATION: '0',
      LLM_API_KEY: '',
      LLM_ENDPOINT: `http://127.0.0.1:${model.address().port}/model`,
      LLM_MODEL: 'lab-model-fixture',
    },
    stdio: ['ignore', 'pipe', 'inherit'],
  });
  t.after(() => server.kill());
  const [startup] = await once(server.stdout, 'data', { signal: AbortSignal.timeout(5000) });
  const origin = startup.toString().match(/http:\/\/127\.0\.0\.1:\d+/)?.[0];
  assert.ok(origin, 'the dashboard exposes a loopback URL');

  const browser = await chromium.launch({ channel: process.env.BROWSER_CHANNEL || 'msedge' });
  t.after(() => browser.close());
  const page = await browser.newPage();
  await page.goto(origin);
  await page.getByRole('checkbox', { name: /Ik heb toestemming/ }).check();
  const capabilities = await (await page.request.get(`${origin}/api/capabilities`)).json();
  assert.equal(capabilities.securityLabOrigin, lab.origin);
  const panel = page.getByRole('region', { name: 'Beveiligingscontrole', exact: true });
  await panel.waitFor({ state: 'hidden' });

  for (const [variant, expected] of [['vulnerable', 'review'], ['fixed', 'observed']]) {
    const target = `${lab.origin}/${variant}`;
    const labResponse = await fetch(target);
    const cookies = labResponse.headers.getSetCookie();
    await labResponse.body?.cancel();
    assert.ok(cookies.length, `${variant} serves a sample cookie`);
    const cookieValues = cookies.map(cookie => {
      const assignment = cookie.split(';', 1)[0];
      return assignment.slice(assignment.indexOf('=') + 1);
    });
    assert.ok(cookieValues.every(Boolean));

    await page.getByLabel('Website-URL').fill(target);
    await page.getByRole('checkbox', { name: 'Passieve beveiligingscontrole' }).check();
    const [response] = await Promise.all([
      waitForRun(page),
      page.getByRole('button', { name: 'Start websitetest', exact: true }).click(),
    ]);
    const report = await response.json();
    assert.equal(report.mode, 'inspection');
    assert.equal(report.securityRequested, true);
    assert.equal(report.security.mode, 'passive');

    const { document: sample, checks } = report.security;
    assert.equal(sample.url, target);
    assert.equal(sample.httpStatus, 200);
    const evidence = report.steps.find(step => step.id === sample.evidenceStepId);
    assert.ok(evidence?.screenshot, 'the sampled response references a screenshot step');
    assert.equal(evidence.title, 'Website openen');
    assert.equal(evidence.url, target);
    const screenshot = await page.request.get(new URL(evidence.screenshot, origin).href);
    assert.ok(screenshot.ok());
    assert.equal(screenshot.headers()['content-type'], 'image/png');

    await panel.waitFor({ state: 'visible' });
    await panel.getByText(/Documentrespons HTTP 200/).waitFor();
    await panel.getByText('Bekijk beveiligingscontroles', { exact: true }).click();
    for (const id of ['csp', 'nosniff', 'cookie-secure']) {
      const check = checks.find(candidate => candidate.id === id);
      assert.equal(check?.status, expected, `${variant} ${id}`);
      const row = panel.getByRole('listitem').filter({
        has: page.getByRole('heading', { name: check.title, exact: true }),
      });
      await row.locator(`.badge[data-state="${expected}"]`).waitFor();
    }

    const reportFile = await readFile(new URL(`../runs/${report.id}/report.json`, import.meta.url), 'utf8');
    const panelText = await panel.textContent();
    for (const value of cookieValues) {
      assert.ok(!JSON.stringify(report).includes(value), 'cookie values stay out of the report API');
      assert.ok(!reportFile.includes(value), 'cookie values stay out of persisted reports');
      assert.ok(!panelText.includes(value), 'cookie values stay out of the dashboard');
    }
  }

  const rejected = await page.request.post(`${origin}/api/runs`, {
    data: { url: 'https://example.com/vulnerable', authorized: true, activeSecurity: true },
  });
  assert.equal(rejected.status(), 403);
  const wrongPath = await page.request.post(`${origin}/api/runs`, {
    data: { url: `${lab.origin}/vulnerable/session`, authorized: true, activeSecurity: true },
  });
  assert.equal(wrongPath.status(), 403);
  const unmarked = labProfile(`http://127.0.0.1:${model.address().port}/vulnerable`);
  await assert.rejects(runActiveSecurity(unmarked), /Security Lab-markering/);
  assert.equal(unmarkedServiceWrites, 0);
  assert.equal(modelInputs.length, 0);

  const activePanel = page.getByRole('region', { name: 'Actieve labresultaten', exact: true });
  for (const [variant, expected, runStatus] of [['vulnerable', 'confirmed', 'failed'], ['fixed', 'protected', 'completed']]) {
    await page.getByLabel('Website-URL').fill(`${lab.origin}/${variant}`);
    await page.getByRole('checkbox', { name: 'Actieve labcontrole', exact: true }).check();
    const [response] = await Promise.all([
      waitForRun(page),
      page.getByRole('button', { name: 'Start labcontrole', exact: true }).click(),
    ]);
    const report = await response.json();
    assert.equal(report.mode, 'lab');
    assert.equal(report.status, runStatus);
    assert.equal(report.coverage, 'full');
    assert.equal(report.security, undefined);
    assert.deepEqual(report.activeSecurity.checks.map(check => check.status), [expected, expected]);
    assert.equal(report.activeSecurity.checks[0].observed.cross.httpStatus, expected === 'confirmed' ? 200 : 403);
    assert.equal(report.activeSecurity.checks[1].observed.replay.httpStatus, expected === 'confirmed' ? 200 : 401);
    assert.equal(report.activeSecurity.checks[1].observed.cookieRemoved, true);
    assert.equal(report.activeSecurity.browserCookies.afterLogout.stored, false);
    assert.equal(report.activeSecurity.browserCookies.alice.stored, true);
    assert.equal(report.activeSecurity.browserCookies.alice.secure, expected === 'protected');
    assert.equal(report.activeSecurity.browserCookies.alice.httpOnly, expected === 'protected');
    assert.equal(report.activeSecurity.browserCookies.alice.scriptVisible, expected === 'confirmed');
    if (expected === 'protected') assert.equal(report.activeSecurity.browserCookies.alice.sameSiteLax, true);
    assert.equal(report.activeSecurity.explanation, expected === 'confirmed' ? modelResponse : undefined);
    assert.match(report.activeSecurity.profile.revision, /^[a-f0-9]{64}$/);
    const reportWithoutRevision = JSON.stringify(report, (key, value) => key === 'revision' ? undefined : value);
    assert.doesNotMatch(reportWithoutRevision, /security_lab_session=|Synthetisch dossier van|[a-f0-9]{48}/);
    await activePanel.waitFor({ state: 'visible' });
    await activePanel.getByRole('heading', { name: report.activeSecurity.checks[0].title, exact: true }).waitFor();
    await activePanel.getByText('Waarnemingen en reproduceerstappen', { exact: true }).first().click();
    await activePanel.getByRole('link', { name: /ASVS v5.0.0-8.2.2/ }).waitFor();
    if (expected === 'confirmed') await activePanel.getByText(modelResponse, { exact: true }).waitFor();
  }
  assert.equal(modelInputs.length, 1);
  assert.doesNotMatch(JSON.stringify(modelInputs), /security_lab_session|Synthetisch dossier|[a-f0-9]{48}/);
  const observed = JSON.parse(modelInputs[0].messages[1].content);
  assert.deepEqual(observed.map(check => check.id), ['object-authorization', 'logout-replay']);
});
