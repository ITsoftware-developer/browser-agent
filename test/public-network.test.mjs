import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { Readable } from 'node:stream';
import { test } from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';
import { gzipSync } from 'node:zlib';
import { createPublicFetcher, isPublicUrl } from '../public-network.mjs';

function responseRequest({ status = 200, headers = {}, chunks = [] }, inspect = () => {}) {
  return (url, options, callback) => {
    inspect(url, options);
    const request = new EventEmitter();
    request.end = () => {
      const response = Object.assign(Readable.from(chunks), { statusCode: status, headers });
      callback(response);
    };
    return request;
  };
}

test('public URL validation rejects credentials, local hosts and non-public IP forms', () => {
  const rejected = [
    'ftp://example.com', 'https://user:password@example.com', 'http://localhost',
    'http://sub.localhost.', 'http://server.local.', 'http://0.0.0.0',
    'http://127.1', 'http://2130706433', 'http://0x7f000001', 'http://10.0.0.1',
    'http://100.64.0.1', 'http://169.254.169.254', 'http://172.31.0.1',
    'http://192.168.1.1', 'http://198.18.0.1', 'http://203.0.113.1',
    'http://224.0.0.1', 'http://255.255.255.255', 'http://[::]', 'http://[::1]',
    'http://[::ffff:127.0.0.1]', 'http://[::ffff:a00:1]', 'http://[64:ff9b::a00:1]',
    'http://[fc00::1]', 'http://[fe80::1]', 'http://[2001:db8::1]',
    'http://[2002:7f00:1::]', 'http://[3fff::1]', 'http://[ff02::1]',
  ];
  for (const url of rejected) assert.equal(isPublicUrl(url), false, url);
  for (const url of ['https://example.com', 'http://93.184.216.34', 'https://[2606:4700::1111]']) {
    assert.equal(isPublicUrl(new URL(url)), true, url);
  }
});

test('private and mixed DNS answers fail before any socket request', async () => {
  for (const addresses of [
    [{ address: '127.0.0.1', family: 4 }],
    [{ address: '93.184.216.34', family: 4 }, { address: '::ffff:10.0.0.1', family: 6 }],
    [{ address: 'fe80::1%eth0', family: 6 }],
  ]) {
    const fetchPublic = createPublicFetcher({
      lookup: async () => addresses,
      request: () => assert.fail('No request may be opened for an unsafe DNS result'),
    });
    await assert.rejects(fetchPublic('https://site.example'), { code: 'PUBLIC_ADDRESS_REQUIRED' });
  }
});

test('transport pins checked addresses while retaining hostname and applies the HTTP boundary', async () => {
  const addresses = [{ address: '93.184.216.34', family: 4 }, { address: '2606:4700::1111', family: 6 }];
  let lookups = 0;
  let requests = 0;
  const fetchPublic = createPublicFetcher({
    lookup: async (host, options) => {
      lookups++;
      assert.equal(host, 'site.example');
      assert.deepEqual(options, { all: true });
      return addresses;
    },
    request: responseRequest({
      status: 302,
      headers: {
        location: 'http://127.0.0.1/private', connection: 'x-hop',
        'x-hop': 'discard me', 'content-encoding': 'gzip',
        'transfer-encoding': 'chunked', 'set-cookie': ['test=1'],
      },
      chunks: [gzipSync('redirect response')],
    }, (url, options) => {
      requests++;
      assert.equal(url.hostname, 'site.example');
      assert.equal(url.protocol, 'https:');
      assert.equal(options.agent, false);
      assert.equal(options.rejectUnauthorized, true);
      assert.deepEqual({ ...options.headers }, { accept: 'text/html', 'accept-encoding': 'identity' });
      options.lookup('site.example', { all: true }, (error, actual) => {
        assert.equal(error, null);
        assert.deepEqual(actual, addresses);
      });
      options.lookup('site.example', {}, (error, ip, family) => {
        assert.equal(error, null);
        assert.equal(ip, addresses[0].address);
        assert.equal(family, addresses[0].family);
      });
    }),
  });
  const response = await fetchPublic('https://site.example/page', {
    headers: { Accept: 'text/html', Cookie: 'secret', Authorization: 'secret', Host: '127.0.0.1' },
  });
  assert.equal(lookups, 1);
  assert.equal(requests, 1);
  assert.equal(response.status, 302);
  assert.deepEqual(response.headers, { location: 'http://127.0.0.1/private' });
  assert.equal(response.body.toString(), 'redirect response');
  await assert.rejects(fetchPublic('https://site.example/page', { method: 'POST' }), { code: 'PUBLIC_METHOD_NOT_ALLOWED' });
  assert.equal(requests, 1);
});

test('transport bounds wire and decoded response sizes', async () => {
  for (const [encoding, body] of [
    ['identity', Buffer.alloc(1024)],
    ['gzip', gzipSync(Buffer.alloc(1024))],
  ]) {
    const fetchPublic = createPublicFetcher({
      maxBytes: 128,
      request: responseRequest({ headers: { 'content-encoding': encoding }, chunks: [body] }),
    });
    await assert.rejects(fetchPublic('http://93.184.216.34'), { code: 'PUBLIC_RESPONSE_TOO_LARGE' });
  }
});

test('DNS resolution is included in the request deadline', async () => {
  const fetchPublic = createPublicFetcher({
    timeoutMs: 20,
    lookup: () => delay(100, [{ address: '93.184.216.34', family: 4 }]),
    request: () => assert.fail('A timed-out lookup must not open a request'),
  });
  await assert.rejects(fetchPublic('https://site.example'), { code: 'PUBLIC_REQUEST_TIMEOUT' });
});
