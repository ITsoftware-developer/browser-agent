import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { once } from 'node:events';
import { createServer } from 'node:http';
import { test } from 'node:test';
import { runActiveSecurity } from '../security-lab/browser-probes.mjs';
import { validateSecurityProfiles } from '../security-profiles.mjs';

const proof = 'browser-agent-cookie-evidence-fixture';
const cookieName = 'staging_session';

async function startFixture(t, { narrowSecondCookie = false, companionCookie = false }) {
  const accounts = Object.fromEntries([['a', 'alice'], ['b', 'bob']].map(([key, user]) => [key, {
    label: user,
    login: { path: '/login', body: { user }, status: 201 },
    record: { path: `/records/${user}`, match: { user } },
  }]));
  const sessions = new Map();
  const server = createServer(async (request, response) => {
    const { method, url } = request;
    if (method === 'GET' && url === '/approval') {
      response.end(proof);
      return;
    }
    if (method === 'POST' && url === '/login') {
      let raw = '';
      for await (const chunk of request) raw += chunk;
      const { user } = JSON.parse(raw);
      const session = randomUUID();
      sessions.set(session, user);
      const path = narrowSecondCookie && user === 'bob' ? '/records/bob' : '/';
      const cookies = [`${cookieName}=${session}; Path=${path}; HttpOnly`];
      if (companionCookie) cookies.push(`companion=${session}; Path=/; HttpOnly`);
      response.writeHead(201, { 'Set-Cookie': cookies }).end();
      return;
    }
    const cookies = new Map((request.headers.cookie ?? '').split('; ').map(cookie => cookie.split('=')));
    const session = cookies.get(cookieName);
    const user = !companionCookie || cookies.get('companion') === session ? sessions.get(session) : undefined;
    if (method === 'POST' && url === '/logout' && user) {
      response.writeHead(204, { 'Set-Cookie': `${cookieName}=; Path=/; Max-Age=0; HttpOnly` }).end();
      return;
    }
    if (method === 'GET' && user && url === `/records/${user}`) {
      response.writeHead(200, { 'Content-Type': 'application/json' }).end(JSON.stringify({ user }));
      return;
    }
    response.writeHead(401).end();
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(() => {
    server.closeAllConnections();
    return new Promise(resolve => server.close(resolve));
  });

  const [profile] = validateSecurityProfiles([{
    id: 'cookie-evidence',
    name: 'Cookie evidence fixture',
    origin: `http://127.0.0.1:${server.address().port}`,
    entryPath: '/stage',
    approval: {
      reference: 'Synthetic regression fixture',
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
      proof: { path: '/approval', value: proof },
    },
    accounts,
    session: { cookieName, logoutPath: '/logout', logoutStatus: 204, anonymousStatus: 401 },
    authorization: { deniedStatus: 401 },
    allowedRequests: [
      { method: 'GET', path: '/approval' },
      { method: 'POST', path: '/login' },
      { method: 'POST', path: '/logout' },
      { method: 'GET', path: '/records/alice' },
      { method: 'GET', path: '/records/bob' },
    ],
  }]);
  return profile;
}

test('cross-account denial requires a session cookie applicable to the target record', async t => {
  const profile = await startFixture(t, { narrowSecondCookie: true });
  const { checks } = await runActiveSecurity(profile);
  const [authorization, logout] = checks;
  assert.equal(authorization.status, 'inconclusive');
  assert.deepEqual(authorization.observed.bobOwn, { httpStatus: 200, recordMatched: true });
  assert.equal(authorization.observed.crossSessionApplicable, false);
  assert.deepEqual(authorization.observed.cross, { httpStatus: null, recordMatched: false });
  assert.equal(logout.status, 'confirmed');
});

test('replay denial after logout requires successful replay before logout with the same cookie', async t => {
  const profile = await startFixture(t, { companionCookie: true });
  const { checks } = await runActiveSecurity(profile);
  const [authorization, logout] = checks;
  assert.equal(authorization.status, 'protected');
  assert.equal(authorization.observed.crossSessionApplicable, true);
  assert.equal(logout.status, 'inconclusive');
  assert.equal(logout.observed.logoutHttpStatus, 204);
  assert.equal(logout.observed.cookieRemoved, true);
  assert.deepEqual(logout.observed.replayBeforeLogout, { httpStatus: 401, recordMatched: false });
  assert.deepEqual(logout.observed.replay, { httpStatus: 401, recordMatched: false });
});
