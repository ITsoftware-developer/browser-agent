import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { once } from 'node:events';
import { mkdtemp, rmdir, unlink, writeFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout } from 'node:timers/promises';
import { test } from 'node:test';
import { chromium } from 'playwright';

const proof = 'browser-agent-approval-27b194ba';
const accounts = {
  a: { label: 'Team rood', login: { path: '/auth/enter', body: { handle: 'red', pin: 'qa-pin-red' }, status: 200 },
    record: { path: '/notes/primary', match: { note: { owner: 'red' } } } },
  b: { label: 'Team blauw', login: { path: '/auth/enter', body: { handle: 'blue', pin: 'qa-pin-blue' }, status: 200 },
    record: { path: '/notes/secondary', match: { note: { owner: 'blue' } } } },
};

async function startFixture(t) {
  const sessions = new Map();
  const requests = [];
  const state = { vulnerable: true, proof: true, redirect: false };
  const server = createServer(async (request, response) => {
    const { method, url } = request;
    requests.push(`${method} ${url}`);
    const reply = (status, value) => {
      response.writeHead(status, { 'Content-Type': 'application/json' });
      response.end(value ? JSON.stringify(value) : undefined);
    };
    if (method === 'GET' && url === '/proof-qa') {
      response.end(state.proof ? proof : 'wrong');
      return;
    }
    if (method === 'POST' && url === '/auth/enter') {
      let body = '';
      for await (const chunk of request) body += chunk;
      const account = Object.values(accounts).find(candidate => JSON.stringify(candidate.login.body) === body);
      if (!account) return reply(401);
      const token = randomUUID();
      sessions.set(token, account);
      response.setHeader('Set-Cookie', `stage_token=${token}; Path=/; HttpOnly; SameSite=Lax`);
      return reply(200);
    }
    const token = request.headers.cookie?.match(/(?:^|; )stage_token=([^;]+)/)?.[1];
    const account = sessions.get(token);
    if (method === 'POST' && url === '/auth/leave') {
      if (!account) return reply(401);
      if (state.redirect) {
        response.writeHead(307, { Location: '/unapproved' });
        response.end();
        return;
      }
      if (!state.vulnerable) sessions.delete(token);
      response.setHeader('Set-Cookie', 'stage_token=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0');
      return reply(204);
    }
    const record = Object.values(accounts).find(candidate => candidate.record.path === url);
    if (method === 'GET' && record) {
      if (!account) return reply(401);
      if (!state.vulnerable && record !== account) return reply(403);
      return reply(200, { ...record.record.match, other: 'synthetic content' });
    }
    reply(404);
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(() => {
    server.closeAllConnections();
    return new Promise(resolve => server.close(resolve));
  });
  return { origin: `http://127.0.0.1:${server.address().port}`, requests, state };
}

function profileFor(id, origin) {
  return {
    id, name: 'Oefenomgeving notities', origin, entryPath: '/control',
    approval: { reference: 'QA-ticket 22', expiresAt: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
      proof: { path: '/proof-qa', value: proof } },
    accounts,
    session: { cookieName: 'stage_token', logoutPath: '/auth/leave', logoutStatus: 204, anonymousStatus: 401 },
    authorization: { deniedStatus: 403 },
    allowedRequests: [
      { method: 'GET', path: '/proof-qa' }, { method: 'POST', path: '/auth/enter' },
      { method: 'GET', path: '/notes/primary' }, { method: 'GET', path: '/notes/secondary' },
      { method: 'POST', path: '/auth/leave' },
    ],
  };
}

async function completedReport(page, origin, id) {
  for (let attempt = 0; attempt < 240; attempt++) {
    const response = await page.request.get(`${origin}/api/runs/${id}`);
    assert.equal(response.status(), 200);
    const report = await response.json();
    if (report.status !== 'running') return report;
    await setTimeout(125);
  }
  assert.fail('the run did not finish within 30 seconds');
}

test('one profile detects, verifies and compares both controls on a second application', { timeout: 90000 }, async t => {
  const fixture = await startFixture(t);
  const local = profileFor('staging-notes', fixture.origin);
  const remote = profileFor('staging-https', 'https://example.com');
  const directory = await mkdtemp(join(tmpdir(), 'browser-agent-profiles-'));
  const file = join(directory, 'profiles.json');
  await writeFile(file, JSON.stringify([local, remote]));
  t.after(async () => { await unlink(file); await rmdir(directory); });
  const dashboard = spawn(process.execPath, ['server.mjs'], {
    cwd: new URL('../', import.meta.url),
    env: { ...process.env, PORT: '0', TEST_ORIGINS: '', SECURITY_LAB_ORIGIN: '', REQUIRE_DOMAIN_VERIFICATION: '0',
      LLM_ENDPOINT: '', LLM_MODEL: '', ACTIVE_SECURITY_PROFILES_FILE: file },
    stdio: ['ignore', 'pipe', 'inherit'],
  });
  t.after(() => dashboard.kill());
  const [startup] = await once(dashboard.stdout, 'data', { signal: AbortSignal.timeout(6000) });
  const origin = startup.toString().match(/http:\/\/127\.0\.0\.1:\d+/)?.[0];
  assert.ok(origin);

  const browser = await chromium.launch({ channel: process.env.BROWSER_CHANNEL || 'msedge' });
  t.after(() => browser.close());
  const page = await browser.newPage();
  const url = local.origin + local.entryPath;
  const post = data => page.request.post(`${origin}/api/runs`, { data });
  const input = { url, authorized: true, activeSecurity: true, activeProfileId: local.id };
  const historyUrl = `${origin}/api/security/history?profileId=${local.id}`;
  await page.goto(origin);
  const capabilities = await (await page.request.get(`${origin}/api/capabilities`)).json();
  assert.deepEqual(capabilities.activeSecurityProfiles[0], { id: local.id, name: local.name, url });
  assert.equal((await post({ ...input, authorized: false })).status(), 400);
  assert.equal((await post({ ...input, activeProfileId: 'missing' })).status(), 403);
  assert.equal((await post({ ...input, url: `${fixture.origin}/unapproved` })).status(), 403);
  const outside = await post({ ...input, activeProfileId: remote.id, url: remote.origin + remote.entryPath });
  assert.equal(outside.status(), 403);
  assert.equal((await outside.json()).code, 'DOMAIN_NOT_VERIFIED');
  assert.deepEqual(fixture.requests, []);

  await page.getByLabel('Website-URL').fill(url);
  await page.getByRole('checkbox', { name: 'Actieve beveiligingscontrole' }).check();
  await page.getByRole('checkbox', { name: /Ik heb toestemming/ }).check();
  const [started] = await Promise.all([
    page.waitForResponse(response => response.url() === `${origin}/api/runs` && response.status() === 202),
    page.getByRole('button', { name: 'Start beveiligingscontrole', exact: true }).click(),
  ]);
  const confirmed = await completedReport(page, origin, (await started.json()).id);
  const panel = page.getByRole('region', { name: 'Actieve beveiligingsresultaten' });
  await panel.getByText(local.name, { exact: false }).first().waitFor();
  await panel.getByText('Bevestigd', { exact: true }).first().waitFor();
  const statuses = report => report.activeSecurity.checks.map(check => check.status);
  const changes = report => report.activeSecurity.comparison.checks.map(check => check.status);
  assert.deepEqual(statuses(confirmed), ['confirmed', 'confirmed']);
  assert.deepEqual(changes(confirmed), ['new', 'new']);
  for (const check of confirmed.activeSecurity.checks) {
    assert.match(check.route, /^GET |^POST /);
    assert.ok(check.expected && check.observed && check.repair && check.reproduction.length);
  }
  const serialized = JSON.stringify({ capabilities, confirmed });
  for (const secret of [proof, 'qa-pin-red', 'qa-pin-blue', 'synthetic content']) assert.ok(!serialized.includes(secret));

  async function runAgain() {
    const response = await post(input);
    assert.equal(response.status(), 202);
    return completedReport(page, origin, (await response.json()).id);
  }
  fixture.state.vulnerable = false;
  const fixed = await runAgain();
  assert.deepEqual(statuses(fixed), ['protected', 'protected']);
  assert.deepEqual(changes(fixed), ['resolved', 'resolved']);
  assert.equal(fixed.activeSecurity.comparison.previousRunId, confirmed.id);

  fixture.state.redirect = true;
  const redirected = await runAgain();
  assert.deepEqual(statuses(redirected), ['protected', 'inconclusive']);
  assert.deepEqual(changes(redirected), ['unchanged', 'not_tested']);
  assert.ok(!fixture.requests.some(request => request.includes('/unapproved')));

  fixture.state.proof = false;
  const beforeProof = fixture.requests.length;
  const refused = await runAgain();
  assert.deepEqual(fixture.requests.slice(beforeProof), ['GET /proof-qa']);
  assert.deepEqual(statuses(refused), ['not_tested', 'not_tested']);

  Object.assign(fixture.state, { vulnerable: true, proof: true, redirect: false });
  const reappeared = await runAgain();
  assert.deepEqual(statuses(reappeared), ['confirmed', 'confirmed']);
  assert.deepEqual(changes(reappeared), ['reappeared', 'reappeared']);
  assert.equal(reappeared.activeSecurity.comparison.previousRunId, refused.id);
  const allowed = new Set(local.allowedRequests.map(({ method, path }) => `${method} ${path}`));
  assert.ok(fixture.requests.every(request => allowed.has(request)));

  const { runs } = await (await page.request.get(historyUrl)).json();
  assert.deepEqual(runs.map(run => run.id), [reappeared.id, refused.id, redirected.id, fixed.id, confirmed.id]);
  await page.reload();
  await page.getByLabel('Website-URL').fill(url);
  await page.getByText('Beveiligingsgeschiedenis openen', { exact: true }).click();
  const [opened] = await Promise.all([
    page.waitForResponse(response => response.url() === `${origin}/api/runs/${fixed.id}` && response.ok()),
    page.locator('#target-security-history-runs').getByRole('button', { name: /Bekijk rapport/ }).nth(3).click(),
  ]);
  assert.equal((await opened.json()).id, fixed.id);
  await panel.getByText('Opgelost', { exact: true }).first().waitFor();
  const outsider = await browser.newPage();
  await outsider.goto(origin);
  assert.deepEqual(await (await outsider.request.get(historyUrl)).json(), { runs: [] });
  assert.equal((await outsider.request.get(`${origin}/api/runs/${confirmed.id}`)).status(), 404);
});
