import { isIP } from 'node:net';
import { chromium } from 'playwright';
import { isPublicUrl } from '../public-network.mjs';

const cookieNames = new Map([
  ['/vulnerable', 'security_lab_session'],
  ['/fixed', '__Secure-security_lab_session'],
]);
const asvs = 'https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/';
const authorization = {
  id: 'v5.0.0-8.2.2',
  url: `${asvs}0x17-V8-Authorization.md#v82-general-authorization-design`,
};
const termination = {
  id: 'v5.0.0-7.4.1',
  url: `${asvs}0x16-V7-Session-Management.md#v74-session-termination`,
};
const missingRecord = { httpStatus: null, recordMatched: false };
const maxNativeRequests = 12;
const maxResponseBytes = 64 * 1024;
const probeDeadlineMs = 30000;

function prepareScope(profile, pinnedAddress) {
  const origin = URL.canParse(profile?.origin ?? '') ? new URL(profile.origin) : null;
  const invalid = () => new Error('Ongeldig profiel voor de actieve browserproef.');
  if (!origin || origin.origin !== profile.origin || !Array.isArray(profile.allowedRequests)) throw invalid();
  const { entryPath, accounts, session, authorization } = profile;
  const proof = profile.approval?.proof;
  const local = origin.protocol === 'http:' && origin.hostname === '127.0.0.1' && Boolean(origin.port);
  let deadline = Date.now() + probeDeadlineMs;
  let resolverRule;
  if (local && proof?.kind === 'header') {
    if (session?.cookieName !== cookieNames.get(entryPath) || !cookieNames.has(entryPath) ||
      profile.id !== `lab-${entryPath.slice(1)}` || proof?.path !== entryPath ||
      proof.kind !== 'header' || proof.header !== 'x-browser-agent-security-lab' || proof.value !== '1' ||
      accounts?.a?.login?.path !== `${entryPath}/session` || accounts?.b?.login?.path !== `${entryPath}/session` ||
      accounts?.a?.login?.body?.user !== 'alice' || accounts?.b?.login?.body?.user !== 'bob' ||
      accounts?.a?.record?.path !== `${entryPath}/records/alice-record` ||
      accounts?.b?.record?.path !== `${entryPath}/records/bob-record` ||
      session.logoutPath !== `${entryPath}/logout`) throw invalid();
  } else {
    const expiresAt = Date.parse(profile.approval?.expiresAt);
    if (!Number.isFinite(expiresAt) || expiresAt <= Date.now() || proof?.kind !== 'body') throw invalid();
    deadline = Math.min(deadline, expiresAt);
    if (!local) {
      const family = typeof pinnedAddress === 'string' ? isIP(pinnedAddress) : 0;
      const address = family === 6 ? `[${pinnedAddress}]` : pinnedAddress;
      if (origin.protocol !== 'https:' || !/^[a-z0-9.-]+$/.test(origin.hostname) ||
        isIP(origin.hostname) || !isPublicUrl(origin) || !family || !isPublicUrl(`https://${address}`)) throw invalid();
      resolverRule = `MAP ${origin.hostname} ${address}, MAP * ~NOTFOUND`;
    }
  }
  const pathValid = path => typeof path === 'string' && path.startsWith('/') && !path.startsWith('//') &&
    !/[?#\\]/.test(path) && new URL(path, origin).pathname === path;
  if (!pathValid(entryPath) || !pathValid(proof?.path) || typeof proof.value !== 'string' || !proof.value ||
    !pathValid(session?.logoutPath) || typeof session.cookieName !== 'string' ||
    !Number.isInteger(session.logoutStatus) || !Number.isInteger(session.anonymousStatus) ||
    !Number.isInteger(authorization?.deniedStatus) ||
    ![accounts?.a, accounts?.b].every(account =>
      pathValid(account?.login?.path) && pathValid(account?.record?.path) &&
      Number.isInteger(account.login.status) && account.login.body && typeof account.login.body === 'object' &&
      account.record.match && typeof account.record.match === 'object')) throw invalid();

  const allowlist = new Set(profile.allowedRequests.map(({ method, path }) => `${method} ${path}`));
  const allowed = new Map();
  function allow(method, path, body = null) {
    const key = `${method} ${path}`;
    if (!allowlist.has(key)) throw invalid();
    if (!allowed.has(key)) allowed.set(key, new Set());
    allowed.get(key).add(body);
  }
  allow('GET', proof.path);
  allow('GET', accounts.a.record.path);
  allow('GET', accounts.b.record.path);
  allow('POST', accounts.a.login.path, JSON.stringify(accounts.a.login.body));
  allow('POST', accounts.b.login.path, JSON.stringify(accounts.b.login.body));
  allow('POST', session.logoutPath);
  return {
    origin: origin.origin, hostname: origin.hostname, proof, deadline, resolverRule,
    proofVerified: false, requestCount: 0, allowed,
  };
}

async function browserProbe(browser, scope, documentPath) {
  const context = await browser.newContext({ serviceWorkers: 'block', acceptDownloads: false });
  await context.routeWebSocket('**/*', socket => socket.close());
  await context.route('**/*', route => {
    const request = route.request();
    const url = new URL(request.url());
    if (url.origin !== scope.origin || url.search || url.hash) return route.abort();
    if (url.pathname === documentPath && request.method() === 'GET' && request.resourceType() === 'document') {
      return route.fulfill({
        status: 200,
        contentType: 'text/html; charset=utf-8',
        headers: {
          'Content-Security-Policy': "default-src 'none'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'",
          'Cache-Control': 'no-store',
        },
        body: '<!doctype html><html lang="nl"><title>Browserproef</title></html>',
      });
    }
    const method = request.method();
    const body = request.postData() || null;
    if (request.resourceType() === 'fetch' && scope.allowed.get(`${method} ${url.pathname}`)?.has(body) &&
      (scope.proofVerified || (url.pathname === scope.proof.path && method === 'GET')) &&
      scope.requestCount < maxNativeRequests && Date.now() < scope.deadline) {
      scope.requestCount++;
      return route.continue();
    }
    return route.abort();
  });
  const page = await context.newPage();
  await page.goto(new URL(documentPath, scope.origin).href, {
    waitUntil: 'domcontentloaded', timeout: Math.max(1, Math.min(4000, scope.deadline - Date.now())),
  });
  return { context, page, deadline: scope.deadline };
}

async function probeFetch(probe, path, { method = 'GET', jsonBody, expected, proof } = {}) {
  const timeout = Math.min(3000, probe.deadline - Date.now());
  if (timeout <= 0) return { ...missingRecord, marker: false };
  try {
    return await probe.page.evaluate(async ({ path, method, jsonBody, expected, proof, timeout, maxResponseBytes }) => {
      const response = await fetch(path, {
        method,
        headers: jsonBody === undefined ? undefined : { 'Content-Type': 'application/json' },
        body: jsonBody,
        redirect: 'error',
        credentials: 'same-origin',
        cache: 'no-store',
        signal: AbortSignal.timeout(timeout),
      });
      async function boundedText() {
        if (!response.body) return '';
        const reader = response.body.getReader();
        const decoder = new TextDecoder('utf-8', { ignoreBOM: true });
        let length = 0;
        let text = '';
        for (;;) {
          const { done, value } = await reader.read();
          if (done) return text + decoder.decode();
          length += value.length;
          if (length > maxResponseBytes) {
            await reader.cancel();
            throw new Error('Reactie te groot voor de browserproef.');
          }
          text += decoder.decode(value, { stream: true });
        }
      }
      function matches(actual, pattern) {
        if (Array.isArray(pattern)) {
          return Array.isArray(actual) && actual.length === pattern.length &&
            pattern.every((value, index) => matches(actual[index], value));
        }
        if (pattern === null || typeof pattern !== 'object') return actual === pattern;
        return actual !== null && typeof actual === 'object' && !Array.isArray(actual) &&
          Object.entries(pattern).every(([key, value]) => Object.hasOwn(actual, key) && matches(actual[key], value));
      }
      const text = expected || proof?.kind === 'body' ? await boundedText() : undefined;
      if (text === undefined) await response.body?.cancel();
      let actual;
      if (expected && text) {
        try { actual = JSON.parse(text); } catch { /* A non-JSON response cannot match the record. */ }
      }
      return {
        httpStatus: response.status,
        recordMatched: Boolean(expected && matches(actual, expected)),
        marker: proof?.kind === 'body' ? text === proof.value :
          Boolean(proof && response.headers.get(proof.header) === proof.value),
      };
    }, { path, method, jsonBody, expected, proof, timeout, maxResponseBytes });
  } catch {
    return { ...missingRecord, marker: false };
  }
}

async function cookieObservation(probe, recordUrl, cookieName) {
  const cookies = await probe.context.cookies(recordUrl);
  const cookie = cookies.find(entry => entry.name === cookieName);
  const scriptVisible = await probe.page.evaluate(name =>
    document.cookie.split(';').some(item => item.trim().startsWith(`${name}=`)), cookieName);
  return {
    cookie,
    flags: {
      stored: Boolean(cookie),
      secure: cookie?.secure === true,
      httpOnly: cookie?.httpOnly === true,
      sameSiteLax: cookie?.sameSite === 'Lax',
      sameSiteStrict: cookie?.sameSite === 'Strict',
      sameSiteNone: cookie?.sameSite === 'None',
      scriptVisible,
    },
  };
}

async function login(probe, login, recordUrl, cookieName) {
  const { httpStatus } = await probeFetch(probe, login.path, { method: 'POST', jsonBody: JSON.stringify(login.body) });
  return { httpStatus, ...await cookieObservation(probe, recordUrl, cookieName) };
}

async function readRecord(probe, path, expected) {
  const { httpStatus, recordMatched } = await probeFetch(probe, path, { expected });
  return { httpStatus, recordMatched };
}

function validRecord(result) {
  return result.httpStatus === 200 && result.recordMatched;
}

function deniedRecord(result, status) {
  return result.httpStatus === status && !result.recordMatched;
}

function result({ id, title, reference, route, reproduction, status, expected, observed, repair }) {
  return { id, title, kind: 'active-fixture', route, status, expected, observed, repair, reproduction, asvs: [reference] };
}

export async function runActiveSecurity(profile, { pinnedAddress } = {}) {
  const scope = prepareScope(profile, pinnedAddress);
  const { accounts: { a, b }, session, authorization: { deniedStatus } } = profile;
  const { cookieName, logoutPath, logoutStatus, anonymousStatus } = session;
  const alicePath = a.record.path;
  const bobPath = b.record.path;
  const aliceUrl = new URL(alicePath, scope.origin).href;
  const bobUrl = new URL(bobPath, scope.origin).href;
  const browser = await chromium.launch({
    channel: process.env.BROWSER_CHANNEL || 'msedge',
    headless: true,
    timeout: Math.max(1, Math.min(10000, scope.deadline - Date.now())),
    proxy: { server: 'http://127.0.0.1:1', bypass: scope.hostname },
    args: scope.resolverRule ? ['--disable-quic', `--host-resolver-rules=${scope.resolverRule}`] : [],
  });
  try {
    const anonymousProbe = await browserProbe(browser, scope, alicePath);
    const marker = await probeFetch(anonymousProbe, scope.proof.path, { proof: scope.proof });
    if (marker.httpStatus !== 200 || !marker.marker) {
      throw new Error(scope.proof.kind === 'header'
        ? 'De browser heeft de lokale Security Lab-markering niet ontvangen.'
        : 'De browser heeft het goedkeuringsbewijs niet ontvangen.');
    }
    scope.proofVerified = true;

    const aliceProbe = await browserProbe(browser, scope, alicePath);
    const bobProbe = await browserProbe(browser, scope, bobPath);
    const anonymous = await readRecord(anonymousProbe, alicePath, a.record.match);
    const alice = await login(aliceProbe, a.login, aliceUrl, cookieName);
    const bob = await login(bobProbe, b.login, bobUrl, cookieName);
    const aliceOwn = alice.cookie ? await readRecord(aliceProbe, alicePath, a.record.match) : missingRecord;
    const bobOwn = bob.cookie ? await readRecord(bobProbe, bobPath, b.record.match) : missingRecord;
    const cross = bob.cookie ? await readRecord(bobProbe, alicePath, a.record.match) : missingRecord;
    const distinctSessions = Boolean(alice.cookie && bob.cookie && alice.cookie.value !== bob.cookie.value);
    let accessStatus = 'inconclusive';
    if (alice.httpStatus === a.login.status && bob.httpStatus === b.login.status && distinctSessions &&
      deniedRecord(anonymous, anonymousStatus) &&
      validRecord(aliceOwn) && validRecord(bobOwn)) {
      if (validRecord(cross)) accessStatus = 'confirmed';
      else if (deniedRecord(cross, deniedStatus)) accessStatus = 'protected';
    }
    const access = result({
      id: 'object-authorization',
      title: 'Toegang tot het record van een andere gebruiker',
      reference: authorization,
      route: `GET ${alicePath}`,
      reproduction: [
        `Open GET ${alicePath} vanuit een schone browsercontext en controleer HTTP ${anonymousStatus}.`,
        `Maak aparte sessies voor de twee accounts via POST ${a.login.path} en POST ${b.login.path}.`,
        `Vraag met elk account het eigen oefenrecord op via GET ${alicePath} of GET ${bobPath}.`,
        `Vraag met het tweede account GET ${alicePath} op en controleer de status en het ontvangen record.`,
      ],
      status: accessStatus,
      expected: {
        aliceSessionHttpStatus: a.login.status, bobSessionHttpStatus: b.login.status, distinctSessions: true,
        anonymousHttpStatus: anonymousStatus, aliceOwn: { httpStatus: 200, recordMatched: true },
        bobOwn: { httpStatus: 200, recordMatched: true }, cross: { httpStatus: deniedStatus, recordMatched: false },
      },
      observed: {
        aliceSessionHttpStatus: alice.httpStatus, bobSessionHttpStatus: bob.httpStatus, distinctSessions,
        anonymousHttpStatus: anonymous.httpStatus, aliceOwn, bobOwn, cross,
      },
      repair: 'Controleer op de server bij iedere opvraag of het aangemelde account toegang heeft tot het gevraagde record.',
    });

    const logout = alice.cookie && alice.httpStatus === a.login.status && validRecord(aliceOwn)
      ? await probeFetch(aliceProbe, logoutPath, { method: 'POST' }) : missingRecord;
    const afterLogout = await cookieObservation(aliceProbe, aliceUrl, cookieName);
    const cookieRemoved = Boolean(alice.cookie && !afterLogout.cookie);
    const afterLogoutRead = logout.httpStatus === logoutStatus
      ? await readRecord(aliceProbe, alicePath, a.record.match) : missingRecord;
    const replayProbe = await browserProbe(browser, scope, alicePath);
    if (alice.cookie && logout.httpStatus === logoutStatus) {
      // Keep the original fictitious cookie only in memory. Chromium decides whether to send it.
      await replayProbe.context.addCookies([alice.cookie]).catch(() => {});
    }
    const replayState = await cookieObservation(replayProbe, aliceUrl, cookieName);
    const replayCookieStored = Boolean(alice.cookie && replayState.cookie?.value === alice.cookie.value);
    const replay = replayCookieStored ? await readRecord(replayProbe, alicePath, a.record.match) : missingRecord;
    let replayStatus = 'inconclusive';
    if (alice.httpStatus === a.login.status && validRecord(aliceOwn) && logout.httpStatus === logoutStatus && cookieRemoved &&
      deniedRecord(afterLogoutRead, anonymousStatus) && replayCookieStored) {
      if (validRecord(replay)) replayStatus = 'confirmed';
      else if (deniedRecord(replay, anonymousStatus)) replayStatus = 'protected';
    }
    const logoutReplay = result({
      id: 'logout-replay',
      title: 'Hergebruik van de sessie na uitloggen',
      reference: termination,
      route: `POST ${logoutPath}`,
      reproduction: [
        `Maak een sessie voor het eerste account via POST ${a.login.path} en bevestig toegang via GET ${alicePath}.`,
        `Voer POST ${logoutPath} uit en controleer of Chromium de sessiecookie verwijdert.`,
        `Plaats de oorspronkelijke fictieve cookie in een aparte browsercontext en voer GET ${alicePath} uit.`,
      ],
      status: replayStatus,
      expected: {
        aliceSessionHttpStatus: a.login.status, before: { httpStatus: 200, recordMatched: true }, logoutHttpStatus: logoutStatus,
        cookieRemoved: true, afterLogout: { httpStatus: anonymousStatus, recordMatched: false }, replayCookieStored: true,
        replay: { httpStatus: anonymousStatus, recordMatched: false },
      },
      observed: {
        aliceSessionHttpStatus: alice.httpStatus, before: aliceOwn, logoutHttpStatus: logout.httpStatus,
        cookieRemoved, afterLogout: afterLogoutRead, replayCookieStored, replay,
      },
      repair: 'Trek de sessie op de server in bij uitloggen en controleer bij volgende verzoeken of de sessie nog geldig is.',
    });

    return {
      checks: [access, logoutReplay],
      browserCookies: { alice: alice.flags, bob: bob.flags, afterLogout: afterLogout.flags, replay: replayState.flags },
    };
  } finally {
    await browser.close();
  }
}
