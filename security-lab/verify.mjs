import { pathToFileURL } from 'node:url';
import { isDeepStrictEqual } from 'node:util';
import { observeSecurityResponse, buildSecurityReport } from '../security-checks.mjs';
import { startSecurityLab } from './server.mjs';
import { labProfile } from './profile.mjs';
import { runActiveSecurity } from './browser-probes.mjs';
const cookieChecks = ['cookie-secure', 'cookie-httponly', 'cookie-samesite', 'cookie-prefix'];
const documentChecks = ['csp', 'nosniff', ...cookieChecks];

async function request(origin, path, options = {}) {
  const url = new URL(path, origin);
  if (url.origin !== origin) throw new Error('Ongeldig doel voor het lokale beveiligingslab.');
  try {
    return await fetch(url, { ...options, redirect: 'error', signal: AbortSignal.timeout(3000) });
  } catch {
    return null;
  }
}

function observe(response) {
  if (!response) return null;
  return observeSecurityResponse({
    url: response.url,
    status: response.status,
    headers: Object.fromEntries(response.headers),
    setCookies: response.headers.getSetCookie(),
  });
}

function checkConfiguration(observation, ids, vulnerable) {
  const { checks } = buildSecurityReport(observation);
  return checks.filter(check => ids.includes(check.id)).map(check => {
    const expectedStatus = vulnerable ? (check.id === 'cookie-prefix' ? 'recommendation' : 'review') : 'observed';
    return { ...check, expectedStatus, matchesExpected: check.status === expectedStatus };
  });
}

function expectedActive(id, vulnerable) {
  const status = vulnerable ? 'confirmed' : 'protected';
  if (id === 'object-authorization') {
    return {
      status,
      aliceSessionHttpStatus: 201,
      bobSessionHttpStatus: 201,
      distinctSessions: true,
      crossSessionApplicable: true,
      anonymousHttpStatus: 401,
      aliceOwn: { httpStatus: 200, recordMatched: true },
      bobOwn: { httpStatus: 200, recordMatched: true },
      cross: { httpStatus: vulnerable ? 200 : 403, recordMatched: vulnerable },
    };
  }
  return {
    status,
    logoutHttpStatus: 204,
    replayBeforeLogout: { httpStatus: 200, recordMatched: true },
    cookieRemoved: true,
    afterLogout: { httpStatus: 401, recordMatched: false },
    replayCookieStored: true,
    replay: { httpStatus: vulnerable ? 200 : 401, recordMatched: vulnerable },
  };
}

async function verifyVariant(origin, variant) {
  const vulnerable = variant === 'vulnerable';
  const basePath = `/${variant}`;
  const sessionPath = `${basePath}/session`;
  const document = await request(origin, basePath);
  const documentHttpStatus = document?.status ?? null;
  const sampledChecks = checkConfiguration(observe(document), documentChecks, vulnerable);
  await document?.body?.cancel();
  const session = await request(origin, sessionPath, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ user: 'alice' }),
  });
  const sessionHttpStatus = session?.status ?? null;
  const sessionChecks = checkConfiguration(observe(session), cookieChecks, vulnerable);
  await session?.body?.cancel();
  const configuration = {
    kind: 'configuration-observation',
    document: { method: 'GET', path: basePath, httpStatus: documentHttpStatus },
    checks: sampledChecks,
    session: { method: 'POST', path: sessionPath, httpStatus: sessionHttpStatus, checks: sessionChecks },
    matchesExpected: documentHttpStatus === 200 && sessionHttpStatus === 201 &&
      sampledChecks.length === documentChecks.length && sessionChecks.length === cookieChecks.length &&
      [...sampledChecks, ...sessionChecks].every(check => check.matchesExpected),
  };

  const { checks, browserCookies } = await runActiveSecurity(labProfile(new URL(basePath, origin)));
  const active = checks.map(check => {
    const expected = expectedActive(check.id, vulnerable);
    const { status, ...observations } = expected;
    const matchesExpected = check.status === status && Object.entries(observations)
      .every(([key, value]) => isDeepStrictEqual(check.observed[key], value));
    return { ...check, expected, matchesExpected };
  });
  const accountCookiesMatch = [browserCookies.alice, browserCookies.bob].every(cookie => cookie.stored &&
    cookie.secure === !vulnerable && cookie.httpOnly === !vulnerable && cookie.scriptVisible === vulnerable &&
    (vulnerable || cookie.sameSiteLax));
  const browserCookiesMatch = accountCookiesMatch && !browserCookies.afterLogout.stored && browserCookies.replay.stored;
  return { configuration, active, browserCookies, browserCookiesMatch };
}

export async function verifySecurityLab() {
  const report = {
    mode: 'security-lab',
    standard: 'OWASP ASVS 5.0.0',
    status: 'failed',
    scope: 'Twee varianten van het lokale oefenlab met synthetische records. Configuratieobservaties en actieve controles beschrijven de geteste responses, routes en sessies.',
    variants: {},
  };
  let lab;
  try {
    lab = await startSecurityLab({ port: 0 });
    if (!/^http:\/\/127\.0\.0\.1:\d+$/.test(lab.origin)) throw new Error('Verwacht een lokaal loopbackadres.');
    for (const variant of ['vulnerable', 'fixed']) {
      report.variants[variant] = await verifyVariant(lab.origin, variant);
    }
    if (Object.values(report.variants).every(variant =>
      variant.configuration.matchesExpected && variant.browserCookiesMatch &&
      variant.active.length === 2 && variant.active.every(check => check.matchesExpected))) {
      report.status = 'passed';
    }
  } catch {
    report.error = 'Het lokale beveiligingslab kon niet volledig worden geverifieerd.';
  } finally {
    try {
      await lab?.close();
    } catch {
      report.status = 'failed';
      report.error = 'Het lokale beveiligingslab kon niet worden afgesloten.';
    }
  }
  return report;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const report = process.argv.length === 2
    ? await verifySecurityLab()
    : { mode: 'security-lab', status: 'failed', error: 'Voer deze opdracht uit zonder argumenten.' };
  console.log(JSON.stringify(report, null, 2));
  if (report.status !== 'passed') process.exitCode = 1;
}
