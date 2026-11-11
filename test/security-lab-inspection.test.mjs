import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { chromium } from 'playwright';
import { startSecurityLab } from '../security-lab/server.mjs';

test('the dashboard distinguishes the lab variants using passive document observations', async t => {
  const lab = await startSecurityLab({ port: 0 });
  t.after(() => lab.close());
  const server = spawn(process.execPath, ['server.mjs'], {
    cwd: new URL('../', import.meta.url),
    env: {
      ...process.env,
      PORT: '0',
      TEST_ORIGINS: lab.origin,
      REQUIRE_DOMAIN_VERIFICATION: '0',
      LLM_ENDPOINT: '',
      LLM_MODEL: '',
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
      page.waitForResponse(async candidate => candidate.request().method() === 'GET' &&
        candidate.ok() && /^\/api\/runs\/[\da-f-]+$/.test(new URL(candidate.url()).pathname) &&
        (await candidate.json()).status !== 'running'),
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
});
