import { pathToFileURL } from 'node:url';
import { observeSecurityResponse, buildSecurityReport } from '../security-checks.mjs';
import { startSecurityLab } from './server.mjs';

const asvs = 'https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/';
const authorization = {
  id: 'v5.0.0-8.2.2',
  url: `${asvs}0x17-V8-Authorization.md#v82-general-authorization-design`,
};
const termination = {
  id: 'v5.0.0-7.4.1',
  url: `${asvs}0x16-V7-Session-Management.md#v74-session-termination`,
};
const records = {
  alice: { id: 'alice-record', owner: 'alice', content: 'Synthetisch dossier van Alice.' },
  bob: { id: 'bob-record', owner: 'bob', content: 'Synthetisch dossier van Bob.' },
};
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

async function login(origin, path, user) {
  const response = await request(origin, path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ user }),
  });
  const headers = response?.headers.getSetCookie() ?? [];
  const cookie = response?.status === 201 && headers.length === 1
    ? /^[^=;\s]+=[^;\s]+(?=;|$)/.exec(headers[0])?.[0]
    : undefined;
  const result = { cookie, httpStatus: response?.status ?? null, observation: observe(response) };
  await response?.body?.cancel();
  return result;
}

async function readRecord(origin, basePath, owner, cookie) {
  const expected = records[owner];
  const response = await request(origin, `${basePath}/records/${expected.id}`, {
    headers: cookie ? { Cookie: cookie } : undefined,
  });
  const actual = await response?.json().catch(() => null);
  return {
    httpStatus: response?.status ?? null,
    recordMatched: actual?.id === expected.id && actual.owner === expected.owner && actual.content === expected.content,
  };
}

function validRecord(result) {
  return result.httpStatus === 200 && result.recordMatched;
}

function activeResult(id, title, reference, reproduction, status, expected, observed) {
  return {
    id,
    title,
    kind: 'active-fixture',
    status,
    expected,
    observed,
    matchesExpected: status === expected.status,
    reproduction,
    asvs: [reference],
  };
}

async function verifyVariant(origin, variant) {
  const vulnerable = variant === 'vulnerable';
  const basePath = `/${variant}`;
  const sessionPath = `${basePath}/session`;
  const logoutPath = `${basePath}/logout`;
  const document = await request(origin, basePath);
  const documentHttpStatus = document?.status ?? null;
  const sampledChecks = checkConfiguration(observe(document), documentChecks, vulnerable);
  await document?.body?.cancel();
  const alice = await login(origin, sessionPath, 'alice');
  const bob = await login(origin, sessionPath, 'bob');
  const sessionChecks = checkConfiguration(alice.observation, cookieChecks, vulnerable);
  const configuration = {
    kind: 'configuration-observation',
    document: { method: 'GET', path: basePath, httpStatus: documentHttpStatus },
    checks: sampledChecks,
    session: { method: 'POST', path: sessionPath, httpStatus: alice.httpStatus, checks: sessionChecks },
    matchesExpected: documentHttpStatus === 200 && alice.httpStatus === 201 &&
      sampledChecks.length === documentChecks.length && sessionChecks.length === cookieChecks.length &&
      [...sampledChecks, ...sessionChecks].every(check => check.matchesExpected),
  };

  const anonymous = await readRecord(origin, basePath, 'alice');
  const missingSession = { httpStatus: null, recordMatched: false };
  const aliceOwn = alice.cookie ? await readRecord(origin, basePath, 'alice', alice.cookie) : missingSession;
  const bobOwn = bob.cookie ? await readRecord(origin, basePath, 'bob', bob.cookie) : missingSession;
  const cross = bob.cookie ? await readRecord(origin, basePath, 'alice', bob.cookie) : missingSession;
  const distinctSessions = Boolean(alice.cookie && bob.cookie && alice.cookie !== bob.cookie);
  let authorizationStatus = 'inconclusive';
  if (distinctSessions && anonymous.httpStatus === 401 && !anonymous.recordMatched &&
      validRecord(aliceOwn) && validRecord(bobOwn)) {
    if (validRecord(cross)) authorizationStatus = 'confirmed';
    else if (cross.httpStatus === 403 && !cross.recordMatched) authorizationStatus = 'protected';
  }
  const access = activeResult(
    'object-authorization',
    'Toegang tot het record van een andere gebruiker',
    authorization,
    [
      `Maak aparte sessies voor Alice en Bob met POST ${sessionPath}.`,
      `Vraag GET ${basePath}/records/alice-record zonder sessie op en controleer dat de server toegang weigert.`,
      `Vraag met iedere sessie het eigen record op via GET ${basePath}/records/alice-record of GET ${basePath}/records/bob-record.`,
      `Vraag GET ${basePath}/records/alice-record op met Bobs sessie en controleer de status en het ontvangen record.`,
    ],
    authorizationStatus,
    {
      status: vulnerable ? 'confirmed' : 'protected',
      aliceSessionHttpStatus: 201,
      bobSessionHttpStatus: 201,
      distinctSessions: true,
      anonymousHttpStatus: 401,
      aliceOwn: { httpStatus: 200, recordMatched: true },
      bobOwn: { httpStatus: 200, recordMatched: true },
      cross: { httpStatus: vulnerable ? 200 : 403, recordMatched: vulnerable },
    },
    {
      aliceSessionHttpStatus: alice.httpStatus,
      bobSessionHttpStatus: bob.httpStatus,
      distinctSessions,
      anonymousHttpStatus: anonymous.httpStatus,
      aliceOwn,
      bobOwn,
      cross,
    },
  );

  const logout = alice.cookie ? await request(origin, logoutPath, { method: 'POST', headers: { Cookie: alice.cookie } }) : null;
  const logoutHttpStatus = logout?.status ?? null;
  await logout?.body?.cancel();
  const replay = alice.cookie ? await readRecord(origin, basePath, 'alice', alice.cookie) : missingSession;
  let replayStatus = 'inconclusive';
  if (validRecord(aliceOwn) && logoutHttpStatus === 204) {
    if (validRecord(replay)) replayStatus = 'confirmed';
    else if (replay.httpStatus === 401 && !replay.recordMatched) replayStatus = 'protected';
  }
  const session = activeResult(
    'logout-replay',
    'Hergebruik van de sessie na uitloggen',
    termination,
    [
      `Maak een Alice-sessie met POST ${sessionPath}.`,
      `Vraag met die sessie GET ${basePath}/records/alice-record op en bevestig dat het eigen record toegankelijk is.`,
      `Voer POST ${logoutPath} uit met dezelfde sessie en controleer HTTP 204.`,
      `Gebruik de oorspronkelijke sessiecookie opnieuw voor GET ${basePath}/records/alice-record en controleer het resultaat.`,
    ],
    replayStatus,
    {
      status: vulnerable ? 'confirmed' : 'protected',
      aliceSessionHttpStatus: 201,
      before: { httpStatus: 200, recordMatched: true },
      logoutHttpStatus: 204,
      replay: { httpStatus: vulnerable ? 200 : 401, recordMatched: vulnerable },
    },
    { aliceSessionHttpStatus: alice.httpStatus, before: aliceOwn, logoutHttpStatus, replay },
  );
  return { configuration, active: [access, session] };
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
      variant.configuration.matchesExpected && variant.active.every(check => check.matchesExpected))) {
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
