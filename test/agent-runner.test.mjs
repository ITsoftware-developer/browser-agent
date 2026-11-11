import assert from 'node:assert/strict';
import { once } from 'node:events';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { runAgent, runDemo } from '../runner.mjs';
import { getRunOutcome } from '../run-status.mjs';

const absentText = { condition: 'text_visible', value: 'Bevestiging', expected: true };
const checkAbsent = { action: 'assert', ...absentText };
const finish = { action: 'finish', summary: 'Controle afgerond.' };

async function fixture(t, chooseAction, options = {}) {
  const requests = [];
  const server = createServer(async (request, response) => {
    if (request.url !== '/model') {
      if (options.handleSiteRequest?.(request, response)) return;
      response.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      return response.end(options.html ?? '<button>Probeer</button>');
    }
    let body = '';
    for await (const chunk of request) body += chunk;
    const { messages } = JSON.parse(body);
    const input = JSON.parse(messages[1].content);
    requests.push({ input, correction: messages[2]?.content });
    const action = await chooseAction(input, requests.length);
    if (action === undefined) return;
    const content = typeof action === 'string' ? action : JSON.stringify(action);
    response.writeHead(200, { 'Content-Type': 'application/json' });
    response.end(JSON.stringify({ choices: [{ message: { content } }] }));
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(() => {
    server.closeAllConnections();
    return new Promise(resolve => server.close(resolve));
  });
  const origin = `http://127.0.0.1:${server.address().port}`;
  const directory = await mkdtemp(join(tmpdir(), 'browser-agent-test-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const mode = options.mode ?? 'ai';
  const run = { id: 'fixture', mode, task: 'Controleer deze testpagina.', steps: [], expectations: options.expectations ?? [] };
  const runner = mode === 'demo' ? runDemo : runAgent;
  const target = new URL(mode === 'demo' ? '/demo' : '/', origin);
  return {
    run,
    requests,
    directory,
    execute: () => runner({
      run, directory, target, endpoint: `${origin}/model`,
      model: 'fixture', modelTimeoutMs: options.modelTimeoutMs,
    }),
  };
}

test('an explicit failed assertion supplies observed evidence and a failed run', async t => {
  const { execute, run, directory } = await fixture(t, ({ history }) => history.length ? finish : checkAbsent, {
    expectations: [absentText],
  });
  await execute();
  const check = run.steps.find(step => step.check);
  assert.deepEqual(check.check, absentText);
  assert.equal(check.status, 'failed');
  assert.equal(check.expected, true);
  assert.equal(check.actual, false);
  const screenshot = await readFile(join(directory, check.screenshot.split('/').at(-1)));
  assert.equal(screenshot.toString('ascii', 1, 4), 'PNG');
  assert.deepEqual(getRunOutcome(run), {
    status: 'failed', coverage: 'full', incompleteReason: null, verifiedFailures: 1, unverifiedFindings: 0,
    technicalErrors: 0, warnings: 0, verifiedChecks: 1, totalChecks: 1,
  });
});

test('a mismatch based solely on a model expectation yields a finding for review', async t => {
  const { execute, run } = await fixture(t, ({ history }) => history.length ? finish : checkAbsent);
  await execute();
  const check = run.steps.find(step => step.check);
  assert.equal(check.status, 'observed');
  assert.equal(check.actual, false);
  assert.ok(check.screenshot);
  const finding = run.steps.find(step => step.status === 'finding');
  assert.deepEqual(finding.evidenceStepIds, [check.id]);
  assert.equal(getRunOutcome(run).status, 'review');
  assert.equal(getRunOutcome(run).verifiedFailures, 0);
});

test('model output gets one corrective retry on the same browser observation', async t => {
  const { execute, run, requests } = await fixture(t, ({ history }, attempt) => {
    if (attempt === 1) return 'not json';
    return history.length ? finish : { action: 'click', index: 0 };
  });
  await execute();
  assert.equal(requests.length, 3);
  assert.match(requests[1].correction, /Ongeldige actie/);
  assert.deepEqual(requests[1].input, requests[0].input);
  assert.equal(requests[2].correction, undefined);
  assert.equal(run.steps.filter(step => step.status === 'observed').length, 1);
  const outcome = getRunOutcome(run);
  assert.equal(outcome.status, 'completed');
  assert.equal(outcome.coverage, 'unknown');
  assert.equal(outcome.verifiedChecks, 0);
});

test('an invalid element index exhausts the corrective retry without executing a browser action', async t => {
  const { execute, run, requests } = await fixture(t, () => ({ action: 'click', index: 99 }));
  await assert.rejects(execute(), { code: 'invalid_model_action' });
  assert.equal(requests.length, 2);
  assert.deepEqual(requests[1].input, requests[0].input);
  assert.deepEqual(run.steps.map(step => step.status), ['passed', 'error']);
  assert.equal(run.steps[1].errorCode, 'invalid_model_action');
});

test('a model timeout preserves browser actions already recorded in the report', async t => {
  const { execute, run, requests } = await fixture(t, ({ history }) =>
    history.length ? undefined : { action: 'click', index: 0 }, { modelTimeoutMs: 1500 });
  await assert.rejects(execute(), { code: 'model_timeout' });
  assert.equal(requests.length, 2);
  assert.deepEqual(run.steps.map(step => step.status), ['passed', 'observed', 'error']);
  assert.equal(run.steps[2].errorCode, 'model_timeout');
  assert.ok(run.steps[1].screenshot);
});

test('the model can wait for dynamic text and capture a targeted screenshot', async t => {
  const expectation = { condition: 'text_visible', value: 'Klaar', expected: true };
  const actions = [
    { action: 'click', index: 0 },
    { action: 'wait', ...expectation, timeoutMs: 3000 },
    { action: 'screenshot', index: 0, label: 'Testknop vastleggen' },
    { action: 'assert', ...expectation },
    finish,
  ];
  const { execute, run } = await fixture(t, ({ history }) => actions[history.length], {
    html: `<button onclick="setTimeout(() => document.querySelector('p').hidden = false, 450)">Probeer</button><p hidden>Klaar</p>`,
    expectations: [expectation],
  });
  await execute();
  assert.deepEqual(run.steps.map(step => step.status), ['passed', 'observed', 'observed', 'observed', 'passed']);
  assert.match(run.steps[2].title, /Wacht op/);
  assert.equal(run.steps[3].title, 'Testknop vastleggen');
  assert.match(run.steps[3].detail, /Probeer/);
  assert.ok(run.steps[3].screenshot);
  assert.equal(run.steps[4].actual, true);
  assert.equal(getRunOutcome(run).coverage, 'full');
});

test('a detached control is skipped and the model sees the replacement before clicking', async t => {
  let shouldRefresh = false;
  const refreshed = Promise.withResolvers();
  const { execute, run, requests } = await fixture(t, async ({ history }) => {
    if (history.length === 0) {
      shouldRefresh = true;
      await refreshed.promise;
    }
    return history.length < 2 ? { action: 'click', index: 0 } : finish;
  }, {
    modelTimeoutMs: 6000,
    html: `<button>Oude knop</button><script>
      async function refresh() {
        const response = await fetch('/refresh');
        if (!(await response.json()).replace) {
          setTimeout(refresh, 40);
          return;
        }
        const replacement = document.createElement('button');
        replacement.textContent = 'Nieuwe knop';
        replacement.onclick = () => replacement.after('Nieuwe knop aangeklikt');
        document.querySelector('button').replaceWith(replacement);
        await fetch('/refreshed');
      }
      refresh();
    </script>`,
    handleSiteRequest(request, response) {
      if (request.url === '/refresh') {
        response.writeHead(200, { 'Content-Type': 'application/json' });
        response.end(JSON.stringify({ replace: shouldRefresh }));
        return true;
      }
      if (request.url === '/refreshed') {
        response.writeHead(204).end();
        refreshed.resolve();
        return true;
      }
      return false;
    },
  });
  await execute();
  assert.equal(requests[0].input.observation.controls[0].name, 'Oude knop');
  assert.equal(requests[1].input.history[0].errorCode, 'stale_element');
  assert.equal(requests[1].input.observation.controls[0].name, 'Nieuwe knop');
  assert.match(requests[2].input.observation.text, /Nieuwe knop aangeklikt/);
  assert.equal(run.steps.filter(step => step.status === 'observed').length, 1);
});

test('a blocked POST produces a network diagnostic without a verified website failure', async t => {
  let submitRequests = 0;
  const actions = [
    { action: 'click', index: 0 },
    { action: 'wait', condition: 'text_visible', value: 'Verzoek afgehandeld' },
    checkAbsent,
    finish,
  ];
  const { execute, run } = await fixture(t, ({ history }) => actions[history.length], {
    expectations: [absentText],
    html: `<button onclick="fetch('/submit', { method: 'POST' }).catch(() => {}).finally(() => this.insertAdjacentHTML('afterend', '<p>Verzoek afgehandeld</p>'))">Probeer</button>`,
    handleSiteRequest(request, response) {
      if (request.url !== '/submit') return false;
      submitRequests++;
      response.writeHead(204).end();
      return true;
    },
  });
  await execute();
  assert.equal(submitRequests, 0);
  assert.equal(run.steps[2].status, 'observed');
  const check = run.steps.find(step => step.check);
  assert.equal(check.status, 'error');
  assert.equal(check.errorCode, 'network_interference');
  assert.ok(run.steps.some(step => step.status === 'warning' && step.errorCode === 'network_request_limited' && /POST \/submit/.test(step.detail)));
  const outcome = getRunOutcome(run);
  assert.equal(outcome.status, 'incomplete');
  assert.equal(outcome.verifiedFailures, 0);
});

test('a POST that starts after the click is recorded remains a standalone network warning', async t => {
  const releasePost = Promise.withResolvers();
  const postSettled = Promise.withResolvers();
  const expectation = { ...absentText, expected: false };
  let submitRequests = 0;
  const { execute, run } = await fixture(t, async ({ history }) => {
    if (history.length === 0) return { action: 'click', index: 0 };
    if (history.length === 1) {
      releasePost.resolve();
      await postSettled.promise;
      return { action: 'assert', ...expectation };
    }
    return finish;
  }, {
    expectations: [expectation],
    modelTimeoutMs: 6000,
    html: `<button onclick="submitLater()">Probeer</button><script>
      async function submitLater() {
        await fetch('/release-post');
        await fetch('/delayed-submit', { method: 'POST' }).catch(() => {});
        await fetch('/post-settled');
      }
    </script>`,
    handleSiteRequest(request, response) {
      if (request.url === '/release-post') {
        void releasePost.promise.then(() => response.writeHead(204).end());
        return true;
      }
      if (request.url === '/delayed-submit') {
        submitRequests++;
        response.writeHead(204).end();
        return true;
      }
      if (request.url === '/post-settled') {
        response.writeHead(204).end();
        postSettled.resolve();
        return true;
      }
      return false;
    },
  });
  await execute();
  assert.equal(submitRequests, 0);
  assert.equal(run.steps[1].status, 'observed');
  const check = run.steps.find(step => step.check);
  assert.equal(check.status, 'passed');
  assert.equal(check.actual, false);
  const warning = run.steps.find(step => step.errorCode === 'network_request_limited');
  assert.equal(warning.status, 'warning');
  const request = warning.requests.find(request => request.path === '/delayed-submit');
  assert.equal(request.method, 'POST');
  assert.equal(request.relatedStepId, undefined);
  const outcome = getRunOutcome(run);
  assert.equal(outcome.status, 'completed_with_issues');
  assert.equal(outcome.coverage, 'full');
  assert.equal(outcome.verifiedChecks, 1);
  assert.equal(outcome.verifiedFailures, 0);
  assert.equal(outcome.technicalErrors, 0);
});

test('an unrelated blocked GET does not invalidate a matching absence assertion', async t => {
  const expectation = { ...absentText, expected: false };
  const { execute, run } = await fixture(t, ({ history }) => history.length ? finish : { action: 'assert', ...expectation }, {
    html: '<button>Probeer</button><img src="http://127.0.0.1:1/tracker.png" alt="">',
    expectations: [expectation],
  });
  await execute();
  const check = run.steps.find(step => step.check);
  assert.equal(check.status, 'passed');
  assert.equal(check.expected, false);
  assert.equal(check.actual, false);
  assert.ok(run.steps.some(step => step.status === 'warning' && step.errorCode === 'network_request_limited' && /GET \/tracker\.png/.test(step.detail)));
  const outcome = getRunOutcome(run);
  assert.equal(outcome.status, 'completed_with_issues');
  assert.equal(outcome.coverage, 'full');
  assert.equal(outcome.verifiedChecks, 1);
  assert.equal(outcome.totalChecks, 1);
  assert.equal(outcome.warnings, 1);
  assert.equal(outcome.technicalErrors, 0);
});

test('a wait timeout does not hide an earlier verified pass or yield a plain completion', async t => {
  const expectation = { ...absentText, expected: false };
  const actions = [
    { action: 'assert', ...expectation },
    { action: 'wait', ...absentText, timeoutMs: 100 },
    finish,
  ];
  const { execute, run } = await fixture(t, ({ history }) => actions[history.length], {
    expectations: [expectation],
  });
  await execute();
  assert.equal(run.steps.find(step => step.check).status, 'passed');
  assert.ok(run.steps.some(step => step.status === 'error' && step.errorCode === 'wait_timeout'));
  const outcome = getRunOutcome(run);
  assert.equal(outcome.status, 'incomplete');
  assert.equal(outcome.verifiedChecks, 1);
  assert.equal(outcome.totalChecks, 1);
  assert.equal(outcome.verifiedFailures, 0);
  assert.equal(outcome.unverifiedFindings, 0);
  assert.equal(outcome.technicalErrors, 1);
  assert.equal(outcome.warnings, 0);
});

test('a timed-out demo operation preserves the original step and evidence before rejecting', async t => {
  const { execute, run, directory } = await fixture(t, () => undefined, {
    mode: 'demo',
    html: '<h1>Winkel zonder zoekveld</h1>',
  });
  await assert.rejects(execute(), { code: 'step_timeout' });
  assert.deepEqual(run.steps.map(step => step.status), ['passed', 'error']);
  const interrupted = run.steps[1];
  assert.equal(interrupted.title, 'Product zoeken');
  assert.equal(interrupted.errorCode, 'step_timeout');
  assert.equal(interrupted.id, 'step-002');
  assert.equal(interrupted.sequence, 2);
  assert.equal(new Date(interrupted.startedAt).toISOString(), interrupted.startedAt);
  assert.ok(interrupted.durationMs >= 3500);
  const screenshot = await readFile(join(directory, interrupted.screenshot.split('/').at(-1)));
  assert.equal(screenshot.toString('ascii', 1, 4), 'PNG');
});
