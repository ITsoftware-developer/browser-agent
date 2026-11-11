import { chromium } from 'playwright';

const cookieNames = new Map([
  ['/vulnerable', 'security_lab_session'],
  ['/fixed', '__Secure-security_lab_session'],
]);
const asvs = 'https://github.com/OWASP/ASVS/blob/v5.0.0_release/5.0/en/';
const authorization = {
  id: 'v5.0.0-8.2.2',
  url: `${asvs}0x17-V8-Authorization.md#v82-general-authorization-design`,
};
const termination = {
  id: 'v5.0.0-7.4.1',
  url: `${asvs}0x16-V7-Session-Management.md#v74-session-termination`,
};
const missingRecord = { httpStatus: null, recordMatched: false };

function validateProfile(profile) {
  const origin = URL.canParse(profile?.origin ?? '') ? new URL(profile.origin) : null;
  const expectedName = cookieNames.get(profile?.basePath);
  if (!origin || origin.protocol !== 'http:' || origin.hostname !== '127.0.0.1' ||
    !origin.port || origin.origin !== profile.origin || !expectedName || profile.cookieName !== expectedName ||
    !['alice', 'bob'].every(user => {
      const record = profile.records?.[user];
      return record?.id === `${user}-record` && record.owner === user && typeof record.content === 'string';
    })) {
    throw new Error('Ongeldig profiel voor de lokale browserproef.');
  }
}

async function browserProbe(browser, scope) {
  const context = await browser.newContext({ serviceWorkers: 'block', acceptDownloads: false });
  await context.routeWebSocket('**/*', socket => socket.close());
  await context.route('**/*', route => {
    const request = route.request();
    const url = new URL(request.url());
    if (url.origin !== scope.origin || url.search || url.hash) return route.abort();
    if (url.pathname === scope.probePath && request.method() === 'GET' && request.resourceType() === 'document') {
      return route.fulfill({
        status: 200,
        contentType: 'text/html; charset=utf-8',
        headers: {
          'Content-Security-Policy': "default-src 'none'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'",
          'Cache-Control': 'no-store',
        },
        body: '<!doctype html><html lang="nl"><title>Lokale browserproef</title></html>',
      });
    }
    if (request.resourceType() === 'fetch' && scope.allowed.get(url.pathname) === request.method() &&
      (url.pathname === scope.basePath || scope.markerVerified)) {
      return route.continue();
    }
    return route.abort();
  });
  const page = await context.newPage();
  await page.goto(new URL(scope.probePath, scope.origin).href, { waitUntil: 'domcontentloaded', timeout: 4000 });
  return { context, page };
}

async function probeFetch(page, path, { method = 'GET', user, expected } = {}) {
  try {
    return await page.evaluate(async ({ path, method, user, expected }) => {
      const response = await fetch(path, {
        method,
        headers: user ? { 'Content-Type': 'application/json' } : undefined,
        body: user ? JSON.stringify({ user }) : undefined,
        redirect: 'error',
        credentials: 'same-origin',
        cache: 'no-store',
        signal: AbortSignal.timeout(3000),
      });
      let recordMatched = false;
      if (expected) {
        const actual = await response.json().catch(() => null);
        recordMatched = actual?.id === expected.id && actual.owner === expected.owner && actual.content === expected.content;
      } else {
        await response.body?.cancel();
      }
      return {
        httpStatus: response.status,
        recordMatched,
        marker: response.headers.get('x-browser-agent-security-lab') === '1',
      };
    }, { path, method, user, expected });
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

async function login(probe, path, user, recordUrl, cookieName) {
  const { httpStatus } = await probeFetch(probe.page, path, { method: 'POST', user });
  return { httpStatus, ...await cookieObservation(probe, recordUrl, cookieName) };
}

async function readRecord(probe, path, expected) {
  const { httpStatus, recordMatched } = await probeFetch(probe.page, path, { expected });
  return { httpStatus, recordMatched };
}

function validRecord(result) {
  return result.httpStatus === 200 && result.recordMatched;
}

function deniedRecord(result, status) {
  return result.httpStatus === status && !result.recordMatched;
}

function result(id, title, reference, reproduction, status, observed) {
  return { id, title, kind: 'active-fixture', status, observed, reproduction, asvs: [reference] };
}

export async function runActiveSecurity(profile) {
  validateProfile(profile);
  const { origin, basePath, records, cookieName } = profile;
  const sessionPath = `${basePath}/session`;
  const logoutPath = `${basePath}/logout`;
  const alicePath = `${basePath}/records/${records.alice.id}`;
  const bobPath = `${basePath}/records/${records.bob.id}`;
  const aliceUrl = new URL(alicePath, origin).href;
  const bobUrl = new URL(bobPath, origin).href;
  const scope = {
    origin,
    basePath,
    probePath: `${basePath}/__browser-agent-probe`,
    markerVerified: false,
    allowed: new Map([
      [basePath, 'GET'], [alicePath, 'GET'], [bobPath, 'GET'], [sessionPath, 'POST'], [logoutPath, 'POST'],
    ]),
  };
  const browser = await chromium.launch({
    channel: process.env.BROWSER_CHANNEL || 'msedge',
    headless: true,
    proxy: { server: 'http://127.0.0.1:1', bypass: '127.0.0.1' },
  });
  try {
    const anonymousProbe = await browserProbe(browser, scope);
    const marker = await probeFetch(anonymousProbe.page, basePath);
    if (marker.httpStatus !== 200 || !marker.marker) {
      throw new Error('De browser heeft de lokale Security Lab-markering niet ontvangen.');
    }
    scope.markerVerified = true;

    const aliceProbe = await browserProbe(browser, scope);
    const bobProbe = await browserProbe(browser, scope);
    const anonymous = await readRecord(anonymousProbe, alicePath, records.alice);
    const alice = await login(aliceProbe, sessionPath, 'alice', aliceUrl, cookieName);
    const bob = await login(bobProbe, sessionPath, 'bob', bobUrl, cookieName);
    const aliceOwn = alice.cookie ? await readRecord(aliceProbe, alicePath, records.alice) : missingRecord;
    const bobOwn = bob.cookie ? await readRecord(bobProbe, bobPath, records.bob) : missingRecord;
    const cross = bob.cookie ? await readRecord(bobProbe, alicePath, records.alice) : missingRecord;
    const distinctSessions = Boolean(alice.cookie && bob.cookie && alice.cookie.value !== bob.cookie.value);
    let accessStatus = 'inconclusive';
    if (alice.httpStatus === 201 && bob.httpStatus === 201 && distinctSessions && deniedRecord(anonymous, 401) &&
      validRecord(aliceOwn) && validRecord(bobOwn)) {
      if (validRecord(cross)) accessStatus = 'confirmed';
      else if (deniedRecord(cross, 403)) accessStatus = 'protected';
    }
    const access = result(
      'object-authorization',
      'Toegang tot het record van een andere gebruiker',
      authorization,
      [
        `Open GET ${alicePath} vanuit een schone browsercontext en controleer HTTP 401.`,
        `Maak Alice- en Bob-sessies via POST ${sessionPath} in aparte browsercontexten.`,
        `Vraag met Alice GET ${alicePath} op en met Bob GET ${bobPath}. Vergelijk beide ontvangen oefenrecords.`,
        `Vraag met Bob GET ${alicePath} op en controleer de status en het ontvangen record.`,
      ],
      accessStatus,
      {
        aliceSessionHttpStatus: alice.httpStatus, bobSessionHttpStatus: bob.httpStatus, distinctSessions,
        anonymousHttpStatus: anonymous.httpStatus, aliceOwn, bobOwn, cross,
      },
    );

    const logout = alice.cookie ? await probeFetch(aliceProbe.page, logoutPath, { method: 'POST' }) : missingRecord;
    const afterLogout = await cookieObservation(aliceProbe, aliceUrl, cookieName);
    const cookieRemoved = Boolean(alice.cookie && !afterLogout.cookie);
    const afterLogoutRead = await readRecord(aliceProbe, alicePath, records.alice);
    const replayProbe = await browserProbe(browser, scope);
    if (alice.cookie && logout.httpStatus === 204) {
      // Keep the original fictitious cookie only in memory. Chromium decides whether to send it.
      await replayProbe.context.addCookies([alice.cookie]).catch(() => {});
    }
    const replayState = await cookieObservation(replayProbe, aliceUrl, cookieName);
    const replayCookieStored = Boolean(alice.cookie && replayState.cookie?.value === alice.cookie.value);
    const replay = replayCookieStored ? await readRecord(replayProbe, alicePath, records.alice) : missingRecord;
    let replayStatus = 'inconclusive';
    if (alice.httpStatus === 201 && validRecord(aliceOwn) && logout.httpStatus === 204 && cookieRemoved &&
      deniedRecord(afterLogoutRead, 401) && replayCookieStored) {
      if (validRecord(replay)) replayStatus = 'confirmed';
      else if (deniedRecord(replay, 401)) replayStatus = 'protected';
    }
    const session = result(
      'logout-replay',
      'Hergebruik van de sessie na uitloggen',
      termination,
      [
        `Maak een Alice-sessie via POST ${sessionPath} en bevestig toegang via GET ${alicePath}.`,
        `Voer POST ${logoutPath} uit en controleer of Chromium de sessiecookie verwijdert.`,
        `Plaats de oorspronkelijke fictieve cookie in een aparte browsercontext en voer GET ${alicePath} uit.`,
      ],
      replayStatus,
      {
        aliceSessionHttpStatus: alice.httpStatus, before: aliceOwn, logoutHttpStatus: logout.httpStatus,
        cookieRemoved, afterLogout: afterLogoutRead, replayCookieStored, replay,
      },
    );

    return {
      checks: [access, session],
      browserCookies: { alice: alice.flags, bob: bob.flags, afterLogout: afterLogout.flags, replay: replayState.flags },
    };
  } finally {
    await browser.close();
  }
}
