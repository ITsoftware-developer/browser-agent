import { createServer } from 'node:http';
import { randomUUID } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { AgentError, runDemo, runAgent, runInspection } from './runner.mjs';
import { parseExpectations } from './agent-actions.mjs';
import { getRunOutcome } from './run-status.mjs';
import { isPublicUrl } from './public-network.mjs';
import { buildSecurityReport } from './security-checks.mjs';
import { createDomainVerification } from './domain-verification.mjs';
import { redactReportValue, reportOwner } from './report-privacy.mjs';
import { configuredLabOrigin, labProfile } from './security-lab/profile.mjs';
import { runLabChecks } from './security-lab/run.mjs';

const port = Number(process.env.PORT || 4317);
let base = `http://127.0.0.1:${port}`;
const allowedOrigins = new Set((process.env.TEST_ORIGINS || '').split(',').map(value => value.trim()).filter(Boolean));
const model = process.env.LLM_MODEL;
const endpoint = process.env.LLM_ENDPOINT;
const aiOrigins = model && endpoint ? [...allowedOrigins] : [];
const requireDomainVerification = process.env.REQUIRE_DOMAIN_VERIFICATION === '1';
const securityLabOrigin = requireDomainVerification ? null : configuredLabOrigin(process.env.SECURITY_LAB_ORIGIN);
const domains = createDomainVerification();
const configuredModelTimeout = Number(process.env.LLM_TIMEOUT_MS);
const modelTimeoutMs = Number.isInteger(configuredModelTimeout) && configuredModelTimeout >= 1 &&
  configuredModelTimeout <= 120000 ? configuredModelTimeout : undefined;
let activeRun;
const files = {
  '/': ['index.html', 'text/html'],
  '/app.js': ['app.js', 'text/javascript'],
  '/style.css': ['style.css', 'text/css'],
  '/demo': ['demo.html', 'text/html'],
  '/demo.js': ['demo.js', 'text/javascript'],
};

function json(response, status, data, replacer) {
  response.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
  response.end(JSON.stringify(data, replacer));
}

function appendRunError(run, errorCode, detail) {
  const sequence = run.steps.length + 1;
  run.steps.push({
    id: `step-${String(sequence).padStart(3, '0')}`,
    sequence,
    title: 'Technische fout',
    startedAt: new Date().toISOString(),
    durationMs: 0,
    status: 'error',
    errorCode,
    detail,
  });
}

async function readJson(request) {
  let body = '';
  for await (const chunk of request) {
    body += chunk;
    if (body.length > 8192) throw Object.assign(new Error('De aanvraag is te lang.'), { status: 413 });
  }
  try {
    return JSON.parse(body);
  } catch {
    throw Object.assign(new Error('Ongeldige aanvraag.'), { status: 400 });
  }
}

async function start(input, response, owner) {
  if (activeRun) return json(response, 409, { error: 'Er loopt al een test.' });
  if (input?.authorized !== true) {
    return json(response, 400, { error: 'Bevestig dat je toestemming hebt om de website te testen.' });
  }
  let target;
  try {
    if (typeof input.url === 'string') target = new URL(input.url);
  } catch {
    // Report malformed and missing URLs through the same validation below.
  }
  if (!target || !['http:', 'https:'].includes(target.protocol) || target.username || target.password) {
    return json(response, 400, { error: 'Voer een geldige website-URL in met http:// of https://.' });
  }
  const demo = target.origin === base && target.pathname === '/demo';
  const activeRequested = input.activeSecurity === true;
  const profile = activeRequested && target.origin === securityLabOrigin ? labProfile(target) : null;
  if (activeRequested && !profile) {
    return json(response, 403, { error: 'Actieve controles zijn beschikbaar voor de ingestelde lokale labvarianten.' });
  }
  const securityRequested = !profile && !demo && input.security === true;
  const mode = profile ? 'lab' : demo ? 'demo' : !securityRequested && aiOrigins.includes(target.origin) ? 'ai' : 'inspection';
  const verifiedOrigins = !demo && requireDomainVerification ? new Set(domains.verifiedOrigins(owner)) : undefined;
  const publicNetwork = Boolean(verifiedOrigins) || (mode === 'inspection' && !allowedOrigins.has(target.origin));
  if (publicNetwork && !isPublicUrl(target)) {
    return json(response, 400, { error: 'Gebruik een publieke website-URL. Een lokale testsite kun je instellen via TEST_ORIGINS.' });
  }
  if (verifiedOrigins && !verifiedOrigins.has(target.origin)) {
    return json(response, 403, { code: 'DOMAIN_NOT_VERIFIED', error: 'Verifieer dit domein via het DNS TXT-record voordat je een test start.' });
  }
  const task = typeof input.task === 'string' ? input.task.trim() : '';
  if (mode === 'ai' && (!task || task.length > 2000)) {
    return json(response, 400, { error: 'Geef een AI-testopdracht op van maximaal 2.000 tekens.' });
  }
  let expectations;
  try {
    expectations = parseExpectations(input.expectations);
  } catch (error) {
    return json(response, 400, { error: error.message });
  }

  const id = randomUUID();
  const directory = new URL(`runs/${id}/`, import.meta.url);
  const runTask = profile ? 'Actieve autorisatie- en sessiecontrole in Security Lab'
    : mode === 'inspection' ? 'Automatische websitecontrole' : task;
  const run = { id, url: target.href, task: runTask, mode, status: 'running', steps: [] };
  if (securityRequested) run.securityRequested = true;
  if (!profile && !demo && expectations.length) run.expectations = expectations;
  activeRun = { owner, run };
  json(response, 202, run, redactReportValue);

  let outcome;
  try {
    await mkdir(directory, { recursive: true });
    await writeFile(new URL('owner', directory), owner, { flag: 'wx', mode: 0o600 });
    const options = { target, run, directory: fileURLToPath(directory), model, endpoint, modelTimeoutMs, publicNetwork, verifiedOrigins, profile };
    const runTest = { demo: runDemo, ai: runAgent, inspection: runInspection, lab: runLabChecks }[mode];
    await runTest(options);
    outcome = getRunOutcome(run);
  } catch (error) {
    console.error(redactReportValue('', error.message));
    if (run.coverage !== 'full') {
      run.coverage = 'partial';
      run.incompleteReason ??= 'De test is voortijdig afgebroken.';
    }
    if (error instanceof AgentError) {
      run.errorCode = error.code;
      run.summary = error.message;
    } else {
      run.errorCode = 'run_execution_failed';
      run.summary = 'De test is afgebroken door een technische fout. Bekijk de serverlog.';
    }
    if (!error.stepId) appendRunError(run, run.errorCode, run.summary);
    outcome = getRunOutcome({ ...run, status: 'error' });
  }
  if (run.securityRequested) run.security ??= buildSecurityReport(null);
  try {
    await writeFile(new URL('report.json', directory), JSON.stringify({ ...run, ...outcome }, redactReportValue, 2));
  } catch (error) {
    console.error(redactReportValue('', error.message));
    run.summary = 'Het testrapport kon niet op schijf worden opgeslagen.';
    run.errorCode = 'report_write_failed';
    appendRunError(run, run.errorCode, run.summary);
    outcome = getRunOutcome({ ...run, status: 'error' });
  }
  lastRun = { owner, run: { ...run, ...outcome } };
  activeRun = undefined;
}

let lastRun;
const server = createServer(async (request, response) => {
  response.setHeader('X-Content-Type-Options', 'nosniff');
  response.setHeader('Cache-Control', 'no-store');
  if (request.headers.host !== new URL(base).host) return json(response, 403, { error: 'Gebruik het lokale adres.' });
  const path = new URL(request.url, base).pathname;
  try {
    if (request.method === 'POST' && ['/api/runs', '/api/domain/challenge', '/api/domain/verify'].includes(path)) {
      if (request.headers.origin && request.headers.origin !== base) return json(response, 403, { error: 'Ongeldige herkomst.' });
      if (!request.headers['content-type']?.startsWith('application/json')) return json(response, 415, { error: 'JSON vereist.' });
      const input = await readJson(request);
      const owner = reportOwner(request, response);
      if (path === '/api/domain/challenge') return json(response, 200, domains.challenge(owner, input?.url));
      if (path === '/api/domain/verify') return json(response, 200, await domains.verify(owner, input?.url));
      return await start(input, response, owner);
    }
    if (request.method === 'GET') {
      if (path === '/api/capabilities') {
        const owner = reportOwner(request, response);
        const capabilities = { aiOrigins, requireDomainVerification, verifiedOrigins: domains.verifiedOrigins(owner) };
        if (securityLabOrigin) capabilities.securityLabOrigin = securityLabOrigin;
        return json(response, 200, capabilities);
      }
      const match = /^\/api\/runs\/([a-f0-9-]{36})(?:\/(\d+\.png))?$/.exec(path);
      if (match) {
        const owner = reportOwner(request);
        const current = [activeRun, lastRun].find(entry => entry?.run.id === match[1]);
        const directory = new URL(`runs/${match[1]}/`, import.meta.url);
        if (!owner || owner !== (current?.owner ?? await readFile(new URL('owner', directory), 'utf8'))) {
          return json(response, 404, { error: 'Rapport niet gevonden.' });
        }
        if (!match[2]) {
          const report = current?.run ?? JSON.parse(await readFile(new URL('report.json', directory), 'utf8'));
          if (report.status === 'running') {
            return json(response, 200, { ...report, ...getRunOutcome(report), status: 'running' }, redactReportValue);
          }
          return json(response, 200, { ...report, ...getRunOutcome(report) }, redactReportValue);
        }
        const screenshot = await readFile(new URL(match[2], directory));
        response.writeHead(200, { 'Content-Type': 'image/png' });
        return response.end(screenshot);
      }
      if (Object.hasOwn(files, path)) {
        const [file, type] = files[path];
        const content = await readFile(new URL(`public/${file}`, import.meta.url));
        if (path === '/') reportOwner(request, response);
        response.writeHead(200, { 'Content-Type': `${type}; charset=utf-8` });
        return response.end(content);
      }
    }
    json(response, 404, { error: 'Pagina niet gevonden.' });
  } catch (error) {
    if (Number.isInteger(error.status) && error.status >= 400 && error.status < 500) {
      return json(response, error.status, { error: error.message });
    }
    if (error.code === 'ENOENT') return json(response, 404, { error: 'Bestand niet gevonden.' });
    console.error(redactReportValue('', error.message));
    json(response, 500, { error: 'De server kon de aanvraag niet verwerken.' });
  }
});
server.listen(port, '127.0.0.1', () => {
  base = `http://127.0.0.1:${server.address().port}`;
  console.log(`Browser Agent draait op ${base}`);
});
