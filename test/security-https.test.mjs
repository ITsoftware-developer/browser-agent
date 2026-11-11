import assert from 'node:assert/strict';
import { createHash, randomUUID, X509Certificate } from 'node:crypto';
import { once } from 'node:events';
import { readFile } from 'node:fs/promises';
import { createServer } from 'node:https';
import { test } from 'node:test';
import { createSecureContext } from 'node:tls';
import { chromium } from 'playwright';
import { runActiveSecurity } from '../security-lab/browser-probes.mjs';

const hostname = 'browser-agent-staging.example.com';
const proof = 'browser-agent-tls-fixture-approval';
const cookieName = '__Host-stage_session';
const cookieFlags = 'Path=/; Secure; HttpOnly; SameSite=Strict';

async function startTls(t, options, handle) {
  const server = createServer(options, handle);
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(() => new Promise(resolve => {
    server.close(resolve);
    server.closeAllConnections();
  }));
  return `https://${hostname}:${server.address().port}`;
}

function profileFor(origin) {
  const account = name => ({
    label: name,
    login: { path: '/signin', body: { name }, status: 204 },
    record: { path: `/records/${name}`, match: { owner: name } },
  });
  return {
    id: 'https-fixture', name: 'TLS fixture', origin, entryPath: '/tests',
    approval: { reference: 'Local TLS regression fixture', expiresAt: new Date(Date.now() + 120000).toISOString(),
      proof: { path: '/proof', kind: 'body', value: proof } },
    accounts: { a: account('red'), b: account('blue') },
    authorization: { deniedStatus: 403 },
    session: { cookieName, logoutPath: '/signout', logoutStatus: 204, anonymousStatus: 401 },
    allowedRequests: [
      { method: 'GET', path: '/proof' }, { method: 'GET', path: '/records/red' },
      { method: 'GET', path: '/records/blue' }, { method: 'POST', path: '/signin' },
      { method: 'POST', path: '/signout' },
    ],
  };
}

test('the active browser probe enforces TLS and keeps HTTPS sessions and redirects within scope', { timeout: 75000 }, async t => {
  // This intentionally public, self-signed identity is for loopback tests only.
  const [cert, key] = await Promise.all([
    readFile(new URL('fixtures/staging-test-cert.pem', import.meta.url)),
    readFile(new URL('fixtures/staging-test-key.pem', import.meta.url)),
  ]);
  const tls = { cert, key };
  const identity = new X509Certificate(cert);
  assert.equal(identity.checkHost(hostname), hostname);
  const spki = createHash('sha256').update(identity.publicKey.export({ type: 'spki', format: 'der' })).digest('base64');
  const handshakeHosts = [];
  const secureContext = createSecureContext(tls);
  const requests = [];
  const offScope = [];
  const outsideOrigin = await startTls(t, tls, (request, response) => {
    offScope.push(request.url);
    response.end();
  });
  let redirect = false;
  const sessions = new Map();
  const origin = await startTls(t, {
    ...tls,
    SNICallback(servername, callback) {
      handshakeHosts.push(servername);
      callback(null, secureContext);
    },
  }, async (request, response) => {
    const { method, url } = request;
    requests.push({ route: `${method} ${url}`, host: request.headers.host });
    const reply = (status, record) => {
      response.writeHead(status, { 'Content-Type': 'application/json' });
      response.end(record ? JSON.stringify(record) : undefined);
    };
    if (method === 'GET' && url === '/proof') return response.end(proof);
    if (method === 'POST' && url === '/signin') {
      let body = '';
      for await (const chunk of request) body += chunk;
      const name = JSON.parse(body).name;
      if (name !== 'red' && name !== 'blue') return reply(401);
      const token = randomUUID();
      sessions.set(token, name);
      response.setHeader('Set-Cookie', `${cookieName}=${token}; ${cookieFlags}`);
      return reply(204);
    }
    const cookie = request.headers.cookie?.split('; ').find(item => item.startsWith(`${cookieName}=`));
    const token = cookie?.slice(cookieName.length + 1);
    const name = sessions.get(token);
    if (!name) return reply(401);
    if (method === 'POST' && url === '/signout') {
      if (redirect) {
        response.writeHead(307, { Location: `${outsideOrigin}/outside` });
        return response.end();
      }
      sessions.delete(token);
      response.setHeader('Set-Cookie', `${cookieName}=; ${cookieFlags}; Max-Age=0`);
      return reply(204);
    }
    if (method === 'GET' && url === `/records/${name}`) return reply(200, { owner: name });
    if (method === 'GET' && ['/records/red', '/records/blue'].includes(url)) return reply(403);
    return reply(404);
  });

  const profile = profileFor(origin);
  const publicPin = '93.184.216.34';
  const publicRule = `--host-resolver-rules=MAP ${hostname} ${publicPin}, MAP * ~NOTFOUND`;
  const launch = chromium.launch.bind(chromium);
  let launches = 0;
  let trustFixture = false;
  t.mock.method(chromium, 'launch', options => {
    launches++;
    assert.ok(options.args.includes(publicRule));
    assert.ok(options.args.includes('--disable-quic'));
    assert.deepEqual(options.proxy, { server: 'http://127.0.0.1:1', bypass: hostname });
    // Preserve the host name and TLS. Only substitute the checked address at
    // this test boundary so Edge never connects to a third-party system.
    const args = options.args.map(arg => arg === publicRule ? arg.replace(publicPin, '127.0.0.1') : arg);
    if (trustFixture) args.push(`--ignore-certificate-errors-spki-list=${spki}`);
    return launch({ ...options, args });
  });

  for (const pinnedAddress of [undefined, '127.0.0.1', '::1', '192.168.1.4']) {
    await assert.rejects(runActiveSecurity(profile, { pinnedAddress }), /Ongeldig profiel/);
  }
  assert.equal(launches, 0);

  await assert.rejects(runActiveSecurity(profile, { pinnedAddress: publicPin }), /goedkeuringsbewijs/);
  assert.ok(handshakeHosts.includes(hostname), 'Edge reached the fixture and sent the original TLS host name');
  assert.deepEqual(requests, [], 'an untrusted certificate blocks proof and login requests');

  trustFixture = true;
  const report = await runActiveSecurity(profile, { pinnedAddress: publicPin });
  assert.deepEqual(report.checks.map(check => check.status), ['protected', 'protected']);
  assert.deepEqual(report.browserCookies.alice, {
    stored: true, secure: true, httpOnly: true, sameSiteLax: false,
    sameSiteStrict: true, sameSiteNone: false, scriptVisible: false,
  });
  assert.equal(report.browserCookies.afterLogout.stored, false);
  assert.equal(report.checks[1].observed.replay.httpStatus, 401);
  assert.equal(requests[0].route, 'GET /proof');

  redirect = true;
  const redirected = await runActiveSecurity(profile, { pinnedAddress: publicPin });
  assert.deepEqual(redirected.checks.map(check => check.status), ['protected', 'inconclusive']);
  assert.equal(redirected.checks[1].observed.logoutHttpStatus, null);
  assert.deepEqual(offScope, [], 'the browser did not follow a 307 to another origin');
  const scope = new Set(profile.allowedRequests.map(({ method, path }) => `${method} ${path}`));
  assert.ok(requests.every(request => request.host === new URL(origin).host && scope.has(request.route)));
});
