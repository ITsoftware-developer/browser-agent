const form = document.querySelector('#run-form');
const url = document.querySelector('#url');
const task = document.querySelector('#task');
const expectation = document.querySelector('#expectation');
const expectationText = document.querySelector('#expectation-text');
const expectationVisibility = document.querySelector('#expectation-visibility');
const authorized = document.querySelector('#authorized');
const start = document.querySelector('#start');
const startLabel = document.querySelector('#start-label');
const status = document.querySelector('#status');
const summary = document.querySelector('#summary');
const steps = document.querySelector('#steps');
const error = document.querySelector('#error');
const download = document.querySelector('#export');
const presets = [...document.querySelectorAll('[data-demo]')];
const counts = document.querySelector('#run-counts');
const coverageNote = document.querySelector('#coverage-note');
const passedCount = document.querySelector('#passed-count');
const failedCount = document.querySelector('#failed-count');
const findingCount = document.querySelector('#finding-count');
const previewScreen = document.querySelector('#preview-screen');
const previewImage = document.querySelector('#preview-image');
const previewEmpty = document.querySelector('#preview-empty');
const previewUrl = document.querySelector('#preview-url');
const previewCaption = document.querySelector('#preview-caption');
const followLatest = document.querySelector('#follow-latest');
let latestRun;
let pinnedStepIndex = null;

function selectDemo(scenario) {
  url.value = `${location.origin}/demo?scenario=${scenario}`;
  task.value = 'Test zoeken, categoriefilters, productdetails, toevoegen aan de winkelwagen en navigeren naar de betaalstap.';
  markPreset(scenario);
}

function targetUrl() {
  try {
    return new URL(url.value);
  } catch {
    return null;
  }
}

function isDemoTarget(target) {
  return target?.origin === location.origin && target.pathname === '/demo';
}

function isAiTarget(target = targetUrl()) {
  return target && ['http:', 'https:'].includes(target.protocol) && !isDemoTarget(target);
}

function markPreset(scenario) {
  const target = targetUrl();
  const showExpectation = Boolean(isAiTarget(target));
  const demo = isDemoTarget(target);
  task.readOnly = demo;
  startLabel.textContent = demo ? 'Start demotest' : 'Start AI-test';
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
  const checks = run.mode === 'demo' ? run.steps.slice(1) : run.steps.filter(step => step.check);
  passedCount.textContent = checks.filter(step => step.status === 'passed').length;
  failedCount.textContent = checks.filter(step => step.status === 'failed').length;
  findingCount.textContent = run.unverifiedFindings ?? run.steps.filter(step => step.status === 'finding').length;
  coverageNote.hidden = run.mode !== 'ai' || run.status === 'running' || run.totalChecks > 0;
  const items = [];
  if (run.totalChecks > 0) items.push(`${run.verifiedChecks ?? 0} van ${run.totalChecks} controles uitgevoerd`);
  if (run.technicalErrors > 0) {
    items.push(run.technicalErrors === 1 ? '1 technische fout' : `${run.technicalErrors} technische fouten`);
  }
  if (run.warnings > 0) items.push(run.warnings === 1 ? '1 waarschuwing' : `${run.warnings} waarschuwingen`);
  counts.hidden = !items.length;
  counts.textContent = items.join(' · ');
}

function showPreviewMessage(message) {
  previewImage.hidden = true;
  previewEmpty.textContent = message;
  previewEmpty.hidden = false;
}

previewImage.addEventListener('load', () => {
  if (!previewImage.getAttribute('src')) return;
  previewImage.hidden = false;
  previewEmpty.hidden = true;
});
previewImage.addEventListener('error', () => showPreviewMessage('Screenshot kon niet worden geladen.'));

function renderPreview() {
  const runSteps = latestRun.steps;
  const latestImageIndex = runSteps.findLastIndex(step => step.screenshot);
  const selectedIndex = pinnedStepIndex ?? (latestImageIndex >= 0 ? latestImageIndex : runSteps.length - 1);
  const step = runSteps[selectedIndex];
  const evidence = step?.screenshot ? step : step?.evidenceStepIds
    ?.map(id => runSteps.find(candidate => candidate.id === id))
    .find(candidate => candidate?.screenshot);
  const pageUrl = evidence?.url ?? step?.url ?? latestRun.url;
  previewUrl.textContent = pageUrl;
  previewUrl.title = pageUrl;
  followLatest.disabled = pinnedStepIndex === null;
  followLatest.setAttribute('aria-pressed', String(pinnedStepIndex === null));
  for (const [index, row] of [...steps.children].entries()) {
    const selected = index === selectedIndex;
    row.dataset.selected = String(selected);
    row.querySelector('.step-select').setAttribute('aria-pressed', String(selected));
  }

  const label = step ? `Stap ${step.sequence ?? selectedIndex + 1} · ${step.title}` : '';
  const caption = [label];
  if (evidence && evidence !== step) {
    caption.push(`Screenshot uit stap ${evidence.sequence ?? runSteps.indexOf(evidence) + 1}`);
    if (step.evidenceSource !== 'assertion') caption.push('AI-selectie, te beoordelen');
  }
  previewCaption.textContent = caption.filter(Boolean).join(' · ');
  previewCaption.hidden = !step;

  if (!evidence) {
    previewImage.removeAttribute('src');
    showPreviewMessage(step ? 'Voor deze stap is geen screenshot beschikbaar.' : 'Wachten op de eerste screenshot…');
    return;
  }
  previewImage.alt = `Screenshot bij ${evidence.title}`;
  if (previewImage.getAttribute('src') !== evidence.screenshot) {
    showPreviewMessage('Screenshot laden…');
    previewImage.src = evidence.screenshot;
  }
}

followLatest.addEventListener('click', () => {
  pinnedStepIndex = null;
  renderPreview();
});

function render(run) {
  if (latestRun?.id !== run.id) {
    steps.replaceChildren();
    pinnedStepIndex = null;
  }
  latestRun = run;
  document.querySelector('#empty').hidden = run.steps.length > 0;
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
    const index = steps.children.length;
    const row = document.createElement('li');
    const header = document.createElement('div');
    header.className = 'timeline-step-header';
    const title = document.createElement('h3');
    const select = document.createElement('button');
    select.type = 'button';
    select.className = 'step-select';
    select.textContent = step.title;
    select.setAttribute('aria-controls', 'preview-screen');
    select.addEventListener('click', () => {
      pinnedStepIndex = index;
      renderPreview();
      const { top, bottom } = previewScreen.getBoundingClientRect();
      if (bottom <= 0 || top >= window.innerHeight) previewScreen.scrollIntoView({ block: 'nearest' });
    });
    title.append(select);
    const badge = document.createElement('span');
    badge.className = 'badge';
    badge.dataset.state = step.status;
    badge.textContent = step.status === 'error' ? 'Technische fout' : labels[step.status];
    header.append(title, badge);
    if (Number.isFinite(step.durationMs)) {
      const duration = document.createElement('span');
      duration.className = 'step-duration';
      duration.textContent = `${step.durationMs} ms`;
      header.append(duration);
    }
    const detail = document.createElement('p');
    detail.textContent = step.detail;
    row.append(header, detail);
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
  renderPreview();
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
