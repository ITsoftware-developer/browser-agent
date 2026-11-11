import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createDomainVerification } from '../domain-verification.mjs';

const origin = 'https://www.example.com';
const owner = 'owner-1';

test('publishing the exact TXT value verifies only the challenge owner and exact origin', async () => {
  let records = [];
  const requestedNames = [];
  const verification = createDomainVerification({
    resolveTxt: async name => {
      requestedNames.push(name);
      return records;
    },
  });
  const first = verification.challenge(owner, 'https://WWW.example.com:443/a?query=one');
  assert.equal(first.origin, origin);
  assert.equal(first.name, '_browser-agent.www.example.com');
  assert.match(first.value, /^browser-agent=[a-f0-9]{48}$/);
  assert.deepEqual(verification.challenge(owner, `${origin}/other`), first);
  assert.deepEqual(verification.verifiedOrigins(owner), []);

  const otherOwner = verification.challenge('owner-2', origin);
  const variants = ['http://www.example.com', 'https://www.example.com:444', 'https://api.example.com', 'https://example.com'];
  const otherOrigins = variants.map(url => verification.challenge(owner, url));
  assert.equal(new Set([first, otherOwner, ...otherOrigins].map(item => item.value)).size, 6);
  records = [[first.value.slice(0, 20), first.value.slice(20)]];
  await assert.rejects(verification.verify('owner-2', origin), { status: 409 });
  for (const variant of variants) await assert.rejects(verification.verify(owner, variant), { status: 409 });

  const result = await verification.verify(owner, origin);
  assert.equal(result.origin, origin);
  assert.ok(Date.parse(result.verifiedUntil) > Date.now());
  assert.deepEqual(verification.verifiedOrigins(owner), [origin]);
  assert.deepEqual(verification.verifiedOrigins('owner-2'), []);
  assert.equal(requestedNames.at(-1), first.name);
  await assert.rejects(verification.verify(owner, origin), { status: 409 });
});

test('TXT records must match exactly and DNS misses leave the challenge available for retry', async () => {
  let records;
  const verification = createDomainVerification({
    resolveTxt: async () => {
      if (!records) throw Object.assign(new Error('dns failure'), { code: 'ENOTFOUND' });
      return records;
    },
  });
  const challenge = verification.challenge(owner, origin);
  await assert.rejects(verification.verify(owner, origin), { status: 409 });
  records = [[challenge.value.slice(0, 20)], [challenge.value.slice(20)], [` ${challenge.value}`], [challenge.value.toUpperCase()]];
  await assert.rejects(verification.verify(owner, origin), { status: 409 });
  assert.deepEqual(verification.challenge(owner, origin), challenge);
  records = [['other TXT'], [challenge.value]];
  await verification.verify(owner, origin);
  assert.deepEqual(verification.verifiedOrigins(owner), [origin]);
});

test('expired challenges rotate and verified origins expire', async () => {
  let time = Date.UTC(2026, 0, 1);
  let records;
  const verification = createDomainVerification({ now: () => time, resolveTxt: async () => records });
  const old = verification.challenge(owner, origin);
  records = [[old.value]];
  time = Date.parse(old.expiresAt);
  await assert.rejects(verification.verify(owner, origin), { status: 409 });
  const next = verification.challenge(owner, origin);
  assert.notEqual(next.value, old.value);
  await assert.rejects(verification.verify(owner, origin), { status: 409 });
  records = [[next.value]];
  const proof = await verification.verify(owner, origin);
  assert.deepEqual(verification.verifiedOrigins(owner), [origin]);
  time = Date.parse(proof.verifiedUntil);
  assert.deepEqual(verification.verifiedOrigins(owner), []);
});

test('a concurrent verification cannot replay or overwrite a rotated challenge', async () => {
  let time = Date.UTC(2026, 0, 1);
  let resolveTxt = Promise.withResolvers();
  const verification = createDomainVerification({
    now: () => time,
    resolveTxt: () => resolveTxt.promise,
  });
  const old = verification.challenge(owner, origin);
  const pending = verification.verify(owner, origin);
  await assert.rejects(verification.verify(owner, origin), { status: 409 });
  time = Date.parse(old.expiresAt);
  const next = verification.challenge(owner, origin);
  assert.notEqual(next.value, old.value);
  resolveTxt.resolve([[old.value]]);
  await assert.rejects(pending, { status: 409 });
  assert.deepEqual(verification.challenge(owner, origin), next);
  resolveTxt = Promise.withResolvers();
  resolveTxt.resolve([[next.value]]);
  await verification.verify(owner, origin);
  assert.deepEqual(verification.verifiedOrigins(owner), [origin]);
});

test('DNS verification accepts only named public HTTP origins and bounds claims per owner', () => {
  let time = Date.UTC(2026, 0, 1);
  const verification = createDomainVerification({ now: () => time });
  const invalid = [
    'example.com', 'ftp://example.com', 'https://name:pass@example.com', 'http://localhost',
    'http://demo.local', 'https://intranet', 'http://8.8.8.8', 'http://[2606:4700::1111]',
    'https://dev.example.test', 'https://bad_label.example.com',
  ];
  for (const url of invalid) assert.throws(() => verification.challenge(owner, url), { status: 400 }, url);
  assert.throws(() => verification.challenge('', origin), { status: 400 });
  const first = verification.challenge(owner, origin);
  for (let index = 1; index < 16; index++) verification.challenge(owner, `https://site-${index}.example.com`);
  assert.throws(() => verification.challenge(owner, 'https://extra.example.com'), { status: 429 });
  assert.deepEqual(verification.challenge(owner, origin), first);
  assert.ok(verification.challenge('owner-2', 'https://extra.example.com').value);
  time = Date.parse(first.expiresAt);
  assert.ok(verification.challenge(owner, 'https://extra.example.com').value);
});
