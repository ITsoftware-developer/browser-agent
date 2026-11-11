const form = document.querySelector('#run-form');
const url = document.querySelector('#url');
const task = document.querySelector('#task');
const expectation = document.querySelector('#expectation');
const expectationText = document.querySelector('#expectation-text');
const expectationVisibility = document.querySelector('#expectation-visibility');
const authorized = document.querySelector('#authorized');
const start = document.querySelector('#start');
const status = document.querySelector('#status');
const summary = document.querySelector('#summary');
const steps = document.querySelector('#steps');
const error = document.querySelector('#error');
const download = document.querySelector('#export');
const presets = [...document.querySelectorAll('[data-demo]')];
const counts = document.createElement('p');
counts.hidden = true;
summary.after(counts);
let latestRun;

function selectDemo(scenario) {
  url.value = `${location.origin}/demo?scenario=${scenario}`;
  task.value = 'Test zoeken, categoriefilters, productdetails, toevoegen aan de winkelwagen en navigeren naar de betaalstap.';
  markPreset(scenario);
}

function isAiTarget() {
  try {
    const target = new URL(url.value);
    return ['http:', 'https:'].includes(target.protocol) &&
      !(target.origin === location.origin && target.pathname === '/demo');
  } catch {
    return false;
  }
}

function markPreset(scenario) {
  task.readOnly = Boolean(scenario);
  const showExpectation = isAiTarget();
  expectation.hidden = !showExpectation;
  expectation.disabled = !showExpectation;
  for (const preset of presets) {
    const selected = preset.dataset.demo === scenario;
    preset.classList.toggle('selected', selected);
    preset.setAttribute('aria-pressed', selected);
  }
}

for (const preset of presets) preset.addEventListener('click', () => selectDemo(preset.dataset.demo));
url.addEventListener('input', () => {
  const preset = presets.find(button => url.value === `${location.origin}/demo?scenario=${button.dataset.demo}`);
  markPreset(preset?.dataset.demo);
});
selectDemo('bug');

const labels = {
  running: 'Bezig', completed: 'Afgerond', completed_with_issues: 'Afgerond met aandachtspunten',
  failed: 'Fout gevonden', error: 'Afgebroken', warning: 'Waarschuwing',
  review: 'Te beoordelen', incomplete: 'Onvolledig', passed: 'Geslaagd', skipped: 'Overgeslagen', observed: 'Uitgevoerd',
  finding: 'AI-bevinding',
};

const coverageLabels = {
  full: 'Dekking volledig',
  partial: 'Dekking gedeeltelijk',
  unknown: 'Dekking onbekend',
};

function screenshotLink(href, label) {
  const link = document.createElement('a');
  link.href = href;
  link.target = '_blank';
  link.rel = 'noopener';
  link.textContent = label;
  return link;
}

function appendEvidence(row, step, runSteps) {
  const hasReferences = Array.isArray(step.evidenceStepIds);
  const modelSelected = step.evidenceSource === 'model' ||
    (!step.evidenceSource && step.status === 'finding' && hasReferences);
  const suffix = modelSelected ? ' (AI-selectie, te beoordelen) ↗' : ' ↗';
  if (!hasReferences) {
    if (step.screenshot) row.append(screenshotLink(step.screenshot, `Bekijk screenshot${suffix}`));
    return;
  }
  if (!step.evidenceStepIds.length) {
    const paragraph = document.createElement('p');
    paragraph.textContent = 'Geen screenshot als bewijs beschikbaar.';
    row.append(paragraph);
    return;
  }

  for (const id of step.evidenceStepIds) {
    const evidence = runSteps.find(candidate => candidate.id === id);
    const paragraph = document.createElement('p');
    if (!evidence) {
      paragraph.textContent = `Bewijsstap ${id} ontbreekt.`;
    } else {
      const label = `stap ${evidence.sequence} · ${evidence.title}`;
      if (evidence.screenshot) {
        paragraph.append(screenshotLink(evidence.screenshot, `Bekijk screenshot bij ${label}${suffix}`));
      } else {
        paragraph.textContent = `Screenshot ontbreekt bij ${label}.`;
      }
    }
    row.append(paragraph);
  }
}

function describeVisibility(value) {
  if (value === true) return 'Zichtbaar';
  if (value === false) return 'Niet zichtbaar';
  return 'Niet vastgesteld';
}

function appendObservation(row, label, value) {
  if (!value) return;
  const observation = document.createElement('p');
  observation.textContent = `${label} · ${value}`;
  row.append(observation);
}

function renderCounts(run) {
  const items = [];
  if (run.totalChecks > 0) items.push(`${run.verifiedChecks ?? 0} van ${run.totalChecks} controles uitgevoerd`);
  if (run.technicalErrors > 0) {
    items.push(run.technicalErrors === 1 ? '1 technische fout' : `${run.technicalErrors} technische fouten`);
  }
  if (run.warnings > 0) items.push(run.warnings === 1 ? '1 waarschuwing' : `${run.warnings} waarschuwingen`);
  counts.hidden = !items.length;
  counts.textContent = items.join(' · ');
}

function render(run) {
  latestRun = run;
  document.querySelector('#empty').hidden = true;
  const coverage = run.coverage ?? 'unknown';
  status.textContent = `${run.mode === 'demo' ? 'Demo' : 'AI'} · ${labels[run.status]} · ${coverageLabels[coverage] ?? coverageLabels.unknown}`;
  status.dataset.state = run.status;
  status.dataset.coverage = coverage;
  const description = [run.summary, run.status !== 'error' && run.incompleteReason].filter(Boolean).join(' ');
  summary.hidden = !description;
  summary.textContent = description;
  renderCounts(run);
  download.hidden = run.status === 'running';
  for (const step of run.steps.slice(steps.children.length)) {
    const row = document.createElement('li');
    const title = document.createElement('h3');
    title.textContent = step.title;
    const badge = document.createElement('span');
    badge.className = 'badge';
    badge.dataset.state = step.status;
    badge.textContent = step.status === 'error' ? 'Technische fout' : labels[step.status];
    const detail = document.createElement('p');
    detail.textContent = step.detail;
    row.append(title, badge, detail);
    if (step.check?.condition === 'text_visible') {
      appendObservation(row, 'Verwacht', `‘${step.check.value}’ is ${describeVisibility(step.check.expected).toLowerCase()}`);
      appendObservation(row, 'Gezien', describeVisibility(step.actual));
    } else if (step.status === 'finding') {
      appendObservation(row, 'Verwacht', step.expected);
      appendObservation(row, 'Gezien', step.actual);
    }
    if (step.fix) {
      const fix = document.createElement('p');
      fix.className = 'fix';
      fix.textContent = `Voorgestelde oplossing · ${step.fix}`;
      row.append(fix);
    }
    appendEvidence(row, step, run.steps);
    steps.append(row);
  }
}

async function request(path, options) {
  const response = await fetch(path, options);
  const data = await response.json();
  if (!response.ok) throw new Error(data.error);
  return data;
}

form.addEventListener('submit', async event => {
  event.preventDefault();
  start.disabled = true;
  error.hidden = true;
  try {
    const input = { url: url.value, task: task.value, authorized: authorized.checked };
    const value = expectationText.value.trim();
    if (value && isAiTarget()) {
      input.expectations = [{ condition: 'text_visible', value, expected: expectationVisibility.value === 'visible' }];
    }
    let run = await request('/api/runs', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(input),
    });
    steps.replaceChildren();
    render(run);
    while (run.status === 'running') {
      await new Promise(resolve => setTimeout(resolve, 650));
      run = await request(`/api/runs/${run.id}`);
      render(run);
    }
  } catch (failure) {
    error.textContent = failure.message;
    error.hidden = false;
  } finally {
    start.disabled = false;
  }
});

download.addEventListener('click', () => {
  const report = { ...latestRun, steps: latestRun.steps.map(step => ({
    ...step, screenshot: step.screenshot ? new URL(step.screenshot, location.origin).href : undefined,
  })) };
  const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
  const href = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = href;
  link.download = `testrapport-${report.id}.json`;
  link.click();
  setTimeout(() => URL.revokeObjectURL(href), 1000);
});
