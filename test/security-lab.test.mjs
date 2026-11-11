import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { get } from 'node:http';
import { test } from 'node:test';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import { startSecurityLab } from '../security-lab/server.mjs';

const execute = promisify(execFile);
const verifier = fileURLToPath(new URL('../security-lab/verify.mjs', import.meta.url));

test('the lab accepts its loopback host and blocks cross-origin session creation', async t => {
  const lab = await startSecurityLab();
  t.after(() => lab.close());
  assert.match(lab.origin, /^http:\/\/127\.0\.0\.1:\d+$/);
  const hostStatus = await new Promise((resolve, reject) => {
    const request = get(`${lab.origin}/vulnerable`, { headers: { Host: 'ander-domein.example' } }, response => {
      response.resume();
      resolve(response.statusCode);
    });
    request.on('error', reject);
  });
  assert.equal(hostStatus, 403);
  const mismatchedOrigin = await fetch(`${lab.origin}/vulnerable/session`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Origin: 'https://ander-domein.example' },
    body: JSON.stringify({ user: 'bob' }),
  });
  assert.equal(mismatchedOrigin.status, 403);
  assert.equal(mismatchedOrigin.headers.get('set-cookie'), null);
  await mismatchedOrigin.body.cancel();
});

test('the Security Lab command reproduces seeded findings and verifies the reference controls', async () => {
  const { stdout } = await execute(process.execPath, [verifier], { timeout: 15000 });
  const report = JSON.parse(stdout);
  assert.equal(report.mode, 'security-lab');
  assert.equal(report.status, 'passed');
  assert.equal(report.standard, 'OWASP ASVS 5.0.0');
  const expected = {
    vulnerable: { configuration: 'review', active: 'confirmed', cross: 200, replay: 200 },
    fixed: { configuration: 'observed', active: 'protected', cross: 403, replay: 401 },
  };
  for (const [variant, outcome] of Object.entries(expected)) {
    const result = report.variants[variant];
    assert.equal(result.configuration.kind, 'configuration-observation');
    assert.equal(result.configuration.document.path, `/${variant}`);
    const configuration = new Map(result.configuration.checks.map(check => [check.id, check]));
    for (const id of ['csp', 'nosniff', 'cookie-secure', 'cookie-httponly', 'cookie-samesite']) {
      assert.equal(configuration.get(id).status, outcome.configuration, `${variant}/${id}`);
      assert.equal(configuration.get(id).matchesExpected, true);
      assert.ok(configuration.get(id).evidence);
    }
    assert.deepEqual(result.active.map(check => check.id).sort(), ['logout-replay', 'object-authorization']);
    for (const check of result.active) {
      assert.equal(check.kind, 'active-fixture');
      assert.equal(check.status, outcome.active);
      assert.equal(check.matchesExpected, true);
      assert.ok(Object.keys(check.observed).length);
      assert.ok(check.reproduction.length > 1);
      assert.match(check.asvs[0].id, /^v5\.0\.0-/);
    }
    const authorization = result.active.find(check => check.id === 'object-authorization').observed;
    assert.equal(authorization.anonymousHttpStatus, 401);
    assert.equal(authorization.distinctSessions, true);
    assert.deepEqual(authorization.aliceOwn, { httpStatus: 200, recordMatched: true });
    assert.deepEqual(authorization.bobOwn, { httpStatus: 200, recordMatched: true });
    assert.deepEqual(authorization.cross, { httpStatus: outcome.cross, recordMatched: outcome.cross === 200 });
    const logout = result.active.find(check => check.id === 'logout-replay').observed;
    assert.equal(logout.logoutHttpStatus, 204);
    assert.deepEqual(logout.replay, { httpStatus: outcome.replay, recordMatched: outcome.replay === 200 });
  }
  assert.doesNotMatch(stdout, /demo-sample|security_lab_session=|Synthetisch dossier van/);
});
