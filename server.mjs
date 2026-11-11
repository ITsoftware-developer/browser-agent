import { createServer } from 'node:http';
import { randomUUID } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { AgentError, runDemo, runAgent, runInspection } from './runner.mjs';
import { parseExpectations } from './agent-actions.mjs';
import { getRunOutcome } from './run-status.mjs';
import { isPublicUrl } from './public-network.mjs';
import { buildSecurityReport } from './security-checks.mjs';

const port = Number(process.env.PORT || 4317);
let base = `http://127.0.0.1:${port}`;
const allowedOrigins = new Set((process.env.TEST_ORIGINS || '').split(',').map(value => value.trim()).filter(Boolean));
const model = process.env.LLM_MODEL;
const endpoint = process.env.LLM_ENDPOINT;
const aiOrigins = model && endpoint ? [...allowedOrigins] : [];
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

function json(response, status, data) {
  response.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
  response.end(JSON.stringify(data));
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

async function start(request, response) {
  if (activeRun) return json(response, 409, { error: 'Er loopt al een test.' });
  let body = '';
  for await (const chunk of request) {
    body += chunk;
    if (body.length > 8192) return json(response, 413, { error: 'De opdracht is te lang.' });
  }
  let input;
  try {
    input = JSON.parse(body);
  } catch {
    return json(response, 400, { error: 'Ongeldige aanvraag.' });
  }
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
  const securityRequested = !demo && input.security === true;
  const mode = demo ? 'demo' : !securityRequested && aiOrigins.includes(target.origin) ? 'ai' : 'inspection';
  const publicInspection = mode === 'inspection' && !allowedOrigins.has(target.origin);
  if (publicInspection && !isPublicUrl(target)) {
    return json(response, 400, { error: 'Gebruik een publieke website-URL. Een lokale testsite kun je instellen via TEST_ORIGINS.' });
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
  const run = { id, url: target.href, task: mode === 'inspection' ? 'Automatische websitecontrole' : task, mode, status: 'running', steps: [] };
  if (securityRequested) run.securityRequested = true;
  if (!demo && expectations.length) run.expectations = expectations;
  activeRun = run;
  json(response, 202, run);

  let outcome;
  try {
    await mkdir(directory, { recursive: true });
    const options = { target, run, directory: fileURLToPath(directory), model, endpoint, modelTimeoutMs, publicInspection };
    const runTest = { demo: runDemo, ai: runAgent, inspection: runInspection }[mode];
    await runTest(options);
    outcome = getRunOutcome(run);
  } catch (error) {
    console.error(error.message);
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
    await writeFile(new URL('report.json', directory), JSON.stringify({ ...run, ...outcome }, null, 2));
  } catch (error) {
    console.error(error.message);
    run.summary = 'Het testrapport kon niet op schijf worden opgeslagen.';
    run.errorCode = 'report_write_failed';
    appendRunError(run, run.errorCode, run.summary);
    outcome = getRunOutcome({ ...run, status: 'error' });
  }
  lastRun = { ...run, ...outcome };
  activeRun = undefined;
}

let lastRun;
const server = createServer(async (request, response) => {
  response.setHeader('X-Content-Type-Options', 'nosniff');
  response.setHeader('Cache-Control', 'no-store');
  if (request.headers.host !== new URL(base).host) return json(response, 403, { error: 'Gebruik het lokale adres.' });
  const path = new URL(request.url, base).pathname;
  try {
    if (request.method === 'POST' && path === '/api/runs') {
      if (request.headers.origin && request.headers.origin !== base) return json(response, 403, { error: 'Ongeldige herkomst.' });
      if (!request.headers['content-type']?.startsWith('application/json')) return json(response, 415, { error: 'JSON vereist.' });
      return await start(request, response);
    }
    if (request.method === 'GET') {
      if (path === '/api/capabilities') return json(response, 200, { aiOrigins });
      const match = /^\/api\/runs\/([a-f0-9-]{36})(?:\/(\d+\.png))?$/.exec(path);
      if (match) {
        if (!match[2]) {
          const current = [activeRun, lastRun].find(run => run?.id === match[1]);
          const report = current || JSON.parse(await readFile(new URL(`runs/${match[1]}/report.json`, import.meta.url), 'utf8'));
          if (report.status === 'running') {
            return json(response, 200, { ...report, ...getRunOutcome(report), status: 'running' });
          }
          return json(response, 200, { ...report, ...getRunOutcome(report) });
        }
        const screenshot = await readFile(new URL(`runs/${match[1]}/${match[2]}`, import.meta.url));
        response.writeHead(200, { 'Content-Type': 'image/png' });
        return response.end(screenshot);
      }
      if (Object.hasOwn(files, path)) {
        const [file, type] = files[path];
        const content = await readFile(new URL(`public/${file}`, import.meta.url));
        response.writeHead(200, { 'Content-Type': `${type}; charset=utf-8` });
        return response.end(content);
      }
    }
    json(response, 404, { error: 'Pagina niet gevonden.' });
  } catch (error) {
    if (error.code === 'ENOENT') return json(response, 404, { error: 'Bestand niet gevonden.' });
    console.error(error.message);
    json(response, 500, { error: 'De server kon de aanvraag niet verwerken.' });
  }
});
server.listen(port, '127.0.0.1', () => {
  base = `http://127.0.0.1:${server.address().port}`;
  console.log(`Browser Agent draait op ${base}`);
});
