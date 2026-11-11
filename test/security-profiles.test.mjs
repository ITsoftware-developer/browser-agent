import assert from 'node:assert/strict';
import { mkdtemp, rmdir, unlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { loadSecurityProfiles, profileRevision, profileSummary, validateSecurityProfiles } from '../security-profiles.mjs';

const secret = 'vertrouwelijke-testwaarde-123456';

function fixture() {
  return {
    id: 'staging-security',
    name: 'Staging beveiligingscontrole',
    origin: 'https://staging.example.com',
    entryPath: '/security-test',
    approval: {
      reference: 'SEC-123',
      expiresAt: '2035-02-28T14:00:00+01:00',
      proof: { path: '/.well-known/browser-agent', value: secret },
    },
    accounts: {
      a: {
        label: 'Testaccount A',
        login: { path: '/api/session', body: { username: 'fixture-a', password: secret }, status: 201 },
        record: { path: '/api/records/a', match: { record: { id: 'a', flags: ['synthetic'] } } },
      },
      b: {
        label: 'Testaccount B',
        login: { path: '/api/session', body: { username: 'fixture-b', password: secret }, status: 201 },
        record: { path: '/api/records/b', match: { record: { id: 'b', flags: ['synthetic'] } } },
      },
    },
    session: { cookieName: '__Host-session', logoutPath: '/api/logout', logoutStatus: 204, anonymousStatus: 401 },
    authorization: { deniedStatus: 403 },
    allowedRequests: [
      { method: 'GET', path: '/.well-known/browser-agent' },
      { method: 'GET', path: '/api/records/a' },
      { method: 'GET', path: '/api/records/b' },
      { method: 'POST', path: '/api/session' },
      { method: 'POST', path: '/api/logout' },
    ],
  };
}

function normalize(profile) {
  return validateSecurityProfiles([profile])[0];
}

test('profiles normalize approval proof and expose only metadata for selection', () => {
  const input = fixture();
  input.origin = 'https://STAGING.example.com/';
  const profile = normalize(input);
  assert.equal(profile.origin, 'https://staging.example.com');
  assert.equal(profile.approval.expiresAt, '2035-02-28T13:00:00.000Z');
  assert.equal(profile.approval.proof.kind, 'body');
  assert.deepEqual(profileSummary(profile), {
    id: 'staging-security', name: 'Staging beveiligingscontrole', url: 'https://staging.example.com/security-test',
  });
  assert.equal(normalize({ ...input, origin: 'http://127.0.0.1:4327' }).origin, 'http://127.0.0.1:4327');
});

test('origins and paths cannot redirect the configured scope or use ambiguous URL syntax', () => {
  for (const origin of [
    'http://staging.example.com', 'https://localhost', 'https://service.internal', 'https://8.8.8.8',
    'http://127.1:4327', 'http://127.0.0.1', 'https://[::1]:4327', 'https://service',
    'https://user:secret@staging.example.com', 'https://staging.example.com/start', 'https://staging.example.com/?token=secret',
  ]) {
    assert.throws(() => normalize({ ...fixture(), origin }), /Controleer origin/);
  }
  for (const entryPath of [
    '//ander.example.com', '/api//record', '/api/../record', '/api/./record', '/api/%2e%2e/record', '/api%2Frecord',
    '/api/record?token=secret', '/api/record#secret', '/api\\record', '/api/*',
  ]) {
    assert.throws(() => normalize({ ...fixture(), entryPath }), /Controleer entryPath/);
  }
});

test('only the exact proof, record, login and logout requests can be allowlisted', () => {
  const profile = fixture();
  assert.equal(normalize(profile).allowedRequests.length, 5);
  const { allowedRequests } = profile;
  const badRequests = [
    allowedRequests.slice(1),
    [...allowedRequests, { method: 'POST', path: '/api/elsewhere' }],
    [...allowedRequests.slice(0, -1), allowedRequests[3]],
    [...allowedRequests.slice(0, -1), { method: ['POST'], path: '/api/logout' }],
    [...allowedRequests.slice(0, -1), { method: 'GET', path: '/api/logout' }],
  ];
  for (const list of badRequests) {
    assert.throws(() => normalize({ ...profile, allowedRequests: list }), /allowedRequests/);
  }
  profile.accounts.b.login.path = '/api/b/session';
  profile.allowedRequests.push({ method: 'POST', path: '/api/b/session' });
  assert.equal(normalize(profile).allowedRequests.length, 6);
});

test('profile IDs and normalized targets are unique', () => {
  assert.throws(() => normalize({ ...fixture(), id: 'lab-vulnerable' }), /profiel-ID’s/);
  assert.throws(() => validateSecurityProfiles([fixture(), { ...fixture(), entryPath: '/another-target' }]), /profiel-ID’s/);
  assert.throws(() => validateSecurityProfiles([
    fixture(), { ...fixture(), id: 'another-profile', origin: 'https://STAGING.EXAMPLE.COM/' },
  ]), /profiel-URL’s/);
});

test('approval, credentials and record assertions are validated without echoing supplied values', () => {
  const rejected = [
    input => { input.approval.proof.value = secret + ' ongeldig'; },
    input => { input.approval.proof.kind = secret; },
    input => { input.approval.expiresAt = '2035-02-30T00:00:00Z'; },
    input => { input.accounts.b.login.body = { password: secret, username: 'fixture-a' }; },
    input => { input.accounts.b.login.body = { password: secret.repeat(400) }; },
    input => { input.accounts.b.record.path = input.accounts.a.record.path; },
    input => { input.accounts.b.record.match = { unrelated: secret }; },
    input => { input.accounts.b.record.match = {}; },
    input => { input.session.cookieName = secret + ' ongeldig'; },
    input => { input.authorization.deniedStatus = 500; },
  ];
  for (const change of rejected) {
    const input = fixture();
    change(input);
    assert.throws(() => normalize(input), error =>
      /Ongeldig beveiligingsprofiel/.test(error.message) && !error.message.includes(secret));
  }
});

test('the revision reflects tested behavior and scope but survives secret rotation', () => {
  const first = normalize(fixture());
  const second = fixture();
  second.name = 'Nieuwe naam';
  second.approval.reference = 'SEC-124';
  second.approval.expiresAt = '2036-03-01T12:00:00Z';
  second.approval.proof.value = 'nieuwe-vertrouwelijke-testwaarde';
  second.accounts.a.login.body.password = 'vervangen-a';
  second.accounts.b.login.body.password = 'vervangen-b';
  second.accounts.a.record.match.record = { flags: ['synthetic'], id: 'a' };
  second.allowedRequests.reverse();
  const revision = profileRevision(first);
  assert.match(revision, /^[0-9a-f]{64}$/);
  assert.equal(profileRevision(normalize(second)), revision);
  second.authorization.deniedStatus = 404;
  assert.notEqual(profileRevision(normalize(second)), revision);
  second.authorization.deniedStatus = 403;
  second.accounts.a.record.match.record.flags = ['changed'];
  assert.notEqual(profileRevision(normalize(second)), revision);
});

test('the optional profile file loads safely and malformed JSON errors remain redacted', async t => {
  assert.deepEqual(await loadSecurityProfiles(), []);
  assert.deepEqual(await loadSecurityProfiles(''), []);
  const directory = await mkdtemp(join(tmpdir(), 'browser-agent-profiles-'));
  const file = join(directory, 'profiles.json');
  await writeFile(file, JSON.stringify([fixture()]));
  t.after(async () => {
    await unlink(file);
    await rmdir(directory);
  });
  assert.deepEqual(await loadSecurityProfiles(file), [normalize(fixture())]);
  await writeFile(file, '{"password": "' + secret + '"');
  await assert.rejects(loadSecurityProfiles(file), error =>
    /geldige.*JSON/.test(error.message) && !error.message.includes(secret) && !error.message.includes(file));
});
