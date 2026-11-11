import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { once } from 'node:events';
import { test } from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';
import { chromium } from 'playwright';

function assertStepMetadata(steps) {
  steps.forEach((step, index) => {
    const sequence = index + 1;
    assert.equal(step.sequence, sequence);
    assert.equal(step.id, `step-${String(sequence).padStart(3, '0')}`);
    assert.equal(new Date(step.startedAt).toISOString(), step.startedAt);
    assert.ok(Number.isFinite(step.durationMs) && step.durationMs >= 0);
  });
}

function waitForReport(page) {
  return page.waitForResponse(async response =>
    response.request().method() === 'GET' && /^\/api\/runs\/[\da-f-]+$/.test(new URL(response.url()).pathname) &&
    response.ok() && (await response.json()).status !== 'running');
}

test('dashboard runs the demo and distinguishes completed AI runs from findings to review', async t => {
  const navigationDelayMs = 180;
  let observedClick;
  let offeredEvidence;
  let otherRunScreenshot;
  const fixture = createServer(async (request, response) => {
    if (request.url === '/model') {
      let body = '';
      for await (const chunk of request) body += chunk;
      const input = JSON.parse(JSON.parse(body).messages[1].content);
      const targetPath = new URL(input.observation.url).pathname;
      const review = targetPath === '/review';
      if (targetPath === '/timeout' && input.history.length > 0) return;
      if (review && input.history.length === 2) {
        observedClick = input.history.at(-1);
        offeredEvidence = input.observation.evidenceSteps;
      }
      let action;
      if (input.history.length === 0) {
        action = { action: 'fill', index: 0, value: 'voorbeeld' };
      } else if (input.history.length === 1) {
        action = { action: 'click', index: 1 };
      } else if (input.history.length === 2 && input.expectations.length) {
        action = { action: 'assert', ...input.expectations[0] };
      } else {
        action = {
            action: 'finish',
            summary: input.observation.text.includes('Opgeslagen in de demo')
              ? 'De testknop werkt.' : 'De testknop geeft geen resultaat.',
            findings: review ? [{
              title: 'Geen bevestiging zichtbaar',
              detail: 'Vul het testveld in en klik op Probeer. Verwacht een bevestiging. Gezien: geen bevestiging.',
              expected: 'Een bevestiging verschijnt.',
              actual: 'Geen bevestiging zichtbaar.',
              evidenceStepIds: [observedClick.stepId, observedClick.stepId, 'step-999', otherRunScreenshot],
            }, {
              title: 'Bevinding zonder screenshot',
              detail: 'Deze bevinding verwijst naar een andere bevinding zonder eigen screenshot.',
              evidenceStepIds: ['step-004'],
            }, {
              title: 'Bevinding zonder verwijzing',
              detail: 'Deze bevinding bevat geen bewijsverwijzing.',
            }] : [],
        };
      }
      response.setHeader('Content-Type', 'application/json');
      return response.end(JSON.stringify({ choices: [{ message: { content: JSON.stringify(action) } }] }));
    }
    response.setHeader('Content-Type', 'text/html');
    if (request.url === '/review') {
      await delay(navigationDelayMs);
      return response.end('<label>Testveld <input type="text"></label><button>Probeer</button>');
    }
    response.end(`<label>Testveld <input type="text"></label><button onclick="this.insertAdjacentHTML('afterend','<p>Opgeslagen in de demo</p>')">Probeer</button>`);
  });
  fixture.listen(0, '127.0.0.1');
  await once(fixture, 'listening');
  t.after(() => fixture.close());
  const fixtureOrigin = `http://127.0.0.1:${fixture.address().port}`;

  const server = spawn(process.execPath, ['server.mjs'], {
    env: { ...process.env, PORT: '0', TEST_ORIGINS: fixtureOrigin, LLM_ENDPOINT: `${fixtureOrigin}/model`,
      LLM_MODEL: 'fixture', LLM_TIMEOUT_MS: '2000' },
    stdio: ['ignore', 'pipe', 'inherit'],
  });
  t.after(() => server.kill());
  const [startup] = await once(server.stdout, 'data', { signal: AbortSignal.timeout(5000) });
  const origin = startup.toString().match(/http:\/\/127\.0\.0\.1:\d+/)?.[0];
  assert.ok(origin);
  const browser = await chromium.launch({ channel: process.env.BROWSER_CHANNEL || 'msedge' });
  t.after(() => browser.close());
  const page = await browser.newPage({ viewport: { width: 390, height: 850 } });
  await page.goto(origin);
  await page.getByRole('checkbox').check();

  for (const [preset, result] of [['Demo met fout', 'Demo · Fout gevonden'], ['Werkende demo', 'Demo · Afgerond']]) {
    await page.getByRole('button', { name: preset }).click();
    await page.getByRole('button', { name: 'Start AI-test' }).click();
    await page.getByText(`${result} · Dekking volledig`, { exact: true }).waitFor();
    assert.equal(await page.locator('#steps li').count(), 6);
    const screenshots = page.getByRole('link', { name: /Bekijk screenshot/ });
    assert.equal(await screenshots.count(), 6);
    const screenshotUrl = await screenshots.nth(4).getAttribute('href');
    const screenshot = await page.request.get(new URL(screenshotUrl, origin).href);
    assert.equal(screenshot.headers()['content-type'], 'image/png');
    if (preset === 'Demo met fout') {
      await page.getByText(/Reproduceren: zoek/).waitFor();
      const [download] = await Promise.all([
        page.waitForEvent('download'),
        page.getByRole('button', { name: 'Download rapport' }).click(),
      ]);
      assert.match(download.suggestedFilename(), /^testrapport-.*\.json$/);
      const demo = JSON.parse(await readFile(await download.path(), 'utf8'));
      assertStepMetadata(demo.steps);
      const bug = demo.steps.find(step => step.status === 'failed');
      assert.match(bug.expected, /1 artikel/);
      assert.match(bug.actual, /0 artikelen/);
      otherRunScreenshot = new URL(bug.screenshot).pathname;
    }
  }

  await page.getByLabel('Website-URL').fill(fixtureOrigin);
  await page.getByLabel('Testopdracht').fill('Test het veld en de knop.');
  const expectedText = page.getByLabel('Te controleren tekst');
  await expectedText.fill('Opgeslagen in de demo');
  await page.getByRole('button', { name: 'Start AI-test' }).click();
  await page.getByText('AI · Afgerond · Dekking volledig', { exact: true }).waitFor();
  await page.getByText('De testknop werkt.', { exact: true }).waitFor();
  await page.getByText('Gezien · Zichtbaar', { exact: true }).waitFor();
  assert.equal(await page.locator('#steps li').count(), 4);

  await page.getByLabel('Website-URL').fill(`${fixtureOrigin}/review`);
  await expectedText.clear();
  const [reviewResponse] = await Promise.all([
    waitForReport(page),
    page.getByRole('button', { name: 'Start AI-test' }).click(),
  ]);
  const report = await reviewResponse.json();
  assert.equal(report.status, 'review');
  assert.equal(report.coverage, 'unknown');
  assert.equal(report.unverifiedFindings, 3);
  assert.equal(report.verifiedFailures, 0);
  assertStepMetadata(report.steps);
  assert.ok(report.steps[0].durationMs >= navigationDelayMs - 10);
  const evidence = report.steps[2];
  assert.equal(evidence.status, 'observed');
  assert.equal(observedClick.stepId, evidence.id);
  assert.equal(observedClick.screenshotAvailable, true);
  assert.deepEqual(offeredEvidence, report.steps.slice(0, 3).map(({ id, title, url }) => ({ id, title, url })));
  const findings = report.steps.filter(step => step.status === 'finding');
  assert.deepEqual(findings.map(step => step.evidenceStepIds), [[evidence.id], [], []]);
  assert.ok(findings.every(step => !Object.hasOwn(step, 'screenshot')));
  assert.equal(findings[0].expected, 'Een bevestiging verschijnt.');
  assert.equal(findings[0].actual, 'Geen bevestiging zichtbaar.');
  await page.getByText('AI · Te beoordelen · Dekking onbekend', { exact: true }).waitFor();
  const findingRow = page.locator('#steps li').filter({
    has: page.getByRole('heading', { name: 'Geen bevestiging zichtbaar', exact: true }),
  });
  const proofLink = findingRow.getByRole('link', { name: /Bekijk screenshot bij stap 3/ });
  assert.equal(await proofLink.getAttribute('href'), evidence.screenshot);
  await findingRow.getByText('Verwacht · Een bevestiging verschijnt.', { exact: true }).waitFor();
  await findingRow.getByText('Gezien · Geen bevestiging zichtbaar.', { exact: true }).waitFor();
  const proof = await page.request.get(new URL(evidence.screenshot, origin).href);
  assert.equal(proof.headers()['content-type'], 'image/png');
  assert.equal(await page.locator('#status').getAttribute('data-state'), 'review');

  const [download] = await Promise.all([
    page.waitForEvent('download'),
    page.getByRole('button', { name: 'Download rapport' }).click(),
  ]);
  const exported = JSON.parse(await readFile(await download.path(), 'utf8'));
  assert.equal(exported.status, 'review');
  assert.equal(exported.id, report.id);
  assert.deepEqual(exported.steps.filter(step => step.status === 'finding'), findings);
  assert.equal(exported.steps[2].screenshot, new URL(evidence.screenshot, origin).href);
  const persisted = JSON.parse(await readFile(new URL(`../runs/${report.id}/report.json`, import.meta.url), 'utf8'));
  assert.deepEqual(persisted, report);

  await page.getByLabel('Website-URL').fill(`${fixtureOrigin}/timeout`);
  const [timeoutResponse] = await Promise.all([
    waitForReport(page),
    page.getByRole('button', { name: 'Start AI-test' }).click(),
  ]);
  const interrupted = await timeoutResponse.json();
  assert.equal(interrupted.status, 'error');
  assert.equal(interrupted.errorCode, 'model_timeout');
  assert.equal(interrupted.coverage, 'partial');
  assert.deepEqual(interrupted.steps.map(step => step.status), ['passed', 'observed', 'error']);
  assert.equal(interrupted.steps[2].errorCode, 'model_timeout');
  assert.equal(interrupted.technicalErrors, 1);
  assert.ok(interrupted.steps[1].screenshot);
  const interruptedPath = new URL(`../runs/${interrupted.id}/report.json`, import.meta.url);
  assert.deepEqual(JSON.parse(await readFile(interruptedPath, 'utf8')), interrupted);
  await page.getByText('AI · Afgebroken · Dekking gedeeltelijk', { exact: true }).waitFor();
});
