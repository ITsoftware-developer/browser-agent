import assert from 'node:assert/strict';
import { test } from 'node:test';
import { buildSecurityReport, observeSecurityResponse } from '../security-checks.mjs';

function resultsFor(options) {
  const observation = observeSecurityResponse({
    url: 'https://site.example/pagina?token=private-query#private-fragment',
    status: 200,
    ...options,
  });
  const report = buildSecurityReport(observation, 'step-001');
  return { report, observation, checks: new Map(report.checks.map(check => [check.id, check])) };
}

test('observes settings on the sampled document and links the exact ASVS version', () => {
  const { report, checks } = resultsFor({
    headers: {
      'content-type': 'text/html; charset=utf-8',
      'strict-transport-security': 'max-age=31536000; includeSubDomains',
      'content-security-policy': "default-src 'self'",
      'x-content-type-options': 'nosniff',
    },
    setCookies: ['__Host-session=private-session; Secure; HttpOnly; SameSite=Lax; Path=/'],
  });
  assert.deepEqual(report.document, { url: 'https://site.example/pagina', httpStatus: 200, evidenceStepId: 'step-001' });
  assert.equal(report.standard, 'OWASP ASVS 5.0.0');
  for (const id of ['https', 'hsts', 'csp', 'nosniff', 'cookie-secure', 'cookie-samesite', 'cookie-httponly']) {
    assert.equal(checks.get(id).status, 'observed', id);
    assert.match(checks.get(id).asvs[0].id, /^v5\.0\.0-/);
  }
});

test('treats configuration gaps as review and keeps cookie and header secrets out of evidence', () => {
  const { report, observation, checks } = resultsFor({
    headers: {
      'content-type': 'text/html',
      'strict-transport-security': 'max-age=0',
      'content-security-policy-report-only': "script-src 'nonce-private-csp'",
      'x-content-type-options': 'invalid-private-header',
      'x-powered-by': 'private-implementation',
    },
    setCookies: ['private-cookie-name=private-cookie-value; SameSite=None'],
  });
  for (const id of ['hsts', 'csp', 'nosniff', 'cookie-secure', 'cookie-samesite', 'cookie-httponly', 'banner']) {
    assert.equal(checks.get(id).status, 'review', id);
  }
  assert.match(checks.get('csp').evidence, /Report-Only/);
  assert.match(checks.get('hsts').evidence, /max-age=0/);
  assert.doesNotMatch(JSON.stringify({ report, observation }), /private-/);
});

test('records the limits of HTTP, non-HTML responses and unavailable evidence', () => {
  const { checks } = resultsFor({ url: 'http://site.example/gegevens', headers: { 'content-type': 'application/json' } });
  assert.equal(checks.get('https').status, 'review');
  assert.equal(checks.get('hsts').status, 'not_observed');
  assert.equal(checks.get('csp').status, 'not_observed');
  assert.equal(checks.get('cookie-secure').status, 'not_observed');
  const unavailable = buildSecurityReport(null);
  assert.equal(unavailable.document, null);
  assert.ok(unavailable.checks.length > 0);
  assert.ok(unavailable.checks.every(check => check.status === 'not_observed'));
});
