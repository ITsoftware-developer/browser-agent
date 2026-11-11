const form = document.querySelector('#run-form');
const url = document.querySelector('#url');
const task = document.querySelector('#task');
const taskField = document.querySelector('#task-field');
const inspectionNote = document.querySelector('#inspection-note');
const expectation = document.querySelector('#expectation');
const expectationText = document.querySelector('#expectation-text');
const expectationVisibility = document.querySelector('#expectation-visibility');
const securityOption = document.querySelector('#security-option');
const securityEnabled = document.querySelector('#security-enabled');
const activeSecurityOption = document.querySelector('#active-security-option');
const activeSecurityEnabled = document.querySelector('#active-security-enabled');
const activeSecurityLabel = document.querySelector('#active-security-label');
const activeSecurityNote = document.querySelector('#active-security-note');
const activeSecurityPanel = document.querySelector('#active-security-report');
const activeSecurityHeading = document.querySelector('#active-security-heading');
const activeSecurityProfile = document.querySelector('#active-security-profile');
const activeSecurityStatus = document.querySelector('#active-security-status');
const activeSecurityChecks = document.querySelector('#active-security-checks');
const activeSecurityCookies = document.querySelector('#active-security-cookies');
const activeSecurityCookieObservations = document.querySelector('#active-security-cookie-observations');
const activeSecurityExplanation = document.querySelector('#active-security-explanation');
const activeSecurityExplanationText = document.querySelector('#active-security-explanation-text');
const securityComparison = document.querySelector('#security-comparison');
const securityComparisonBaseline = document.querySelector('#security-comparison-baseline');
const securityComparisonChecks = document.querySelector('#security-comparison-checks');
const securityHistory = document.querySelector('#security-history');
const targetSecurityHistory = document.querySelector('#target-security-history');
const reportHistoryView = {
  status: document.querySelector('#security-history-status'),
  rows: document.querySelector('#security-history-runs'),
};
const targetHistoryView = {
  status: document.querySelector('#target-security-history-status'),
  rows: document.querySelector('#target-security-history-runs'),
};
const securityPanel = document.querySelector('#security-report');
const securityStatus = document.querySelector('#security-status');
const securityCount = document.querySelector('#security-count');
const securityScope = document.querySelector('#security-scope');
const securitySample = document.querySelector('#security-sample');
const securityUntested = document.querySelector('#security-untested');
const securityDetails = document.querySelector('#security-details');
const securityChecks = document.querySelector('#security-checks');
const domainVerification = document.querySelector('#domain-verification');
const domainStatus = document.querySelector('#domain-status');
const domainRecord = document.querySelector('#domain-record');
const domainName = document.querySelector('#domain-name');
const domainValue = document.querySelector('#domain-value');
const domainExpiry = document.querySelector('#domain-expiry');
const domainChallenge = document.querySelector('#domain-challenge');
const domainVerify = document.querySelector('#domain-verify');
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
let aiOrigins = new Set();
let securityLabOrigin;
let activeSecurityProfiles = [];
let lastActiveSecurityResults;
let targetHistoryProfile;
let historySelection = 0;
let verifiedOrigins = new Set();
let requireDomainVerification = false;
const domainStates = new Map();
let domainRequest;
let currentMode;
let aiTask = '';

const demoTask = 'Test zoeken, categoriefilters, productdetails, toevoegen aan de winkelwagen en navigeren naar de betaalstap.';
const startLabels = {
  demo: 'Start demotest',
  inspection: 'Start websitetest',
  ai: 'Start AI-test',
  lab: 'Start labcontrole',
};
const localDate = new Intl.DateTimeFormat('nl-NL', { dateStyle: 'short', timeStyle: 'medium' });

function selectDemo(scenario) {
  url.value = `${location.origin}/demo?scenario=${scenario}`;
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

function isLabTarget(target) {
  return Boolean(target && securityLabOrigin && !requireDomainVerification &&
    ['/vulnerable', '/fixed'].some(path => target.href === `${securityLabOrigin}${path}`));
}

function matchingActiveProfile(target) {
  if (!target || (requireDomainVerification && target.protocol !== 'https:')) return undefined;
  return activeSecurityProfiles.find(profile => profile.url === target.href);
}

function targetMode(target) {
  if (isDemoTarget(target)) return 'demo';
  if (activeSecurityEnabled.checked && (isLabTarget(target) || matchingActiveProfile(target))) return 'lab';
  if (securityEnabled.checked) return 'inspection';
  return aiOrigins.has(target?.origin) ? 'ai' : 'inspection';
}

function isExternalTarget(target) {
  return ['http:', 'https:'].includes(target?.protocol) && !isDemoTarget(target);
}

function isDomainVerified(origin) {
  const verifiedUntil = domainStates.get(origin)?.verifiedUntil;
  return verifiedUntil ? new Date(verifiedUntil).getTime() > Date.now() : verifiedOrigins.has(origin);
}

function needsDomainVerification(target) {
  return isExternalTarget(target) &&
    (requireDomainVerification ||
      (target.protocol === 'https:' && targetMode(target) === 'lab' && Boolean(matchingActiveProfile(target))));
}

function renderDomainVerification(target = targetUrl()) {
  const active = targetMode(target) === 'lab';
  const verificationRequired = needsDomainVerification(target);
  domainVerification.hidden = !isExternalTarget(target) || (active && !verificationRequired);
  if (domainVerification.hidden) {
    domainVerification.open = false;
    delete domainVerification.dataset.origin;
    return;
  }
  const { origin } = target;
  const state = domainStates.get(origin);
  const verified = isDomainVerified(origin);
  const required = Boolean(verificationRequired) && !verified;
  if (domainVerification.dataset.origin !== origin) domainVerification.open = required;
  else if (required && domainVerification.dataset.required !== 'true') domainVerification.open = true;
  domainVerification.dataset.origin = origin;
  domainVerification.dataset.required = String(required);

  const challenge = state?.challenge;
  const expired = challenge && new Date(challenge.expiresAt).getTime() <= Date.now();
  domainChallenge.disabled = Boolean(domainRequest) || verified;
  domainVerify.disabled = Boolean(domainRequest) || verified || !challenge || expired;
  domainRecord.hidden = !challenge || verified;
  if (!domainRecord.hidden) {
    domainName.textContent = challenge.name;
    domainValue.textContent = challenge.value;
    domainExpiry.dateTime = challenge.expiresAt;
    domainExpiry.textContent = localDate.format(new Date(challenge.expiresAt));
  }

  if (domainRequest?.origin === origin) {
    domainStatus.textContent = domainRequest.action === 'challenge' ? 'TXT-record voorbereiden…' : 'TXT-record opzoeken…';
  } else if (verified) {
    domainStatus.textContent = state?.verifiedUntil
      ? `Domein geverifieerd tot ${localDate.format(new Date(state.verifiedUntil))}.`
      : 'Domein geverifieerd.';
  } else if (state?.error) {
    domainStatus.textContent = state.error;
  } else if (expired) {
    domainStatus.textContent = 'Het TXT-record is verlopen. Genereer een nieuw record.';
  } else {
    domainStatus.textContent = required
      ? 'Verifieer dit domein voordat je de test start.'
      : 'Je kunt het eigendom van dit domein aantonen met een DNS TXT-record.';
  }
}

async function runDomainAction(action) {
  const target = targetUrl();
  if (!isExternalTarget(target) || domainRequest) return;
  const { origin } = target;
  const state = domainStates.get(origin) ?? {};
  domainStates.set(origin, state);
  domainRequest = { origin, action };
  state.error = '';
  renderDomainVerification(target);
  try {
    await capabilities;
    const activeTarget = targetUrl();
    if (!isExternalTarget(activeTarget) || activeTarget.origin !== origin) return;
    const result = await request(`/api/domain/${action}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: target.href }),
    });
    if (action === 'challenge') {
      state.challenge = result;
    } else {
      state.verifiedUntil = result.verifiedUntil;
      state.challenge = undefined;
    }
  } catch (failure) {
    state.error = failure.message;
  } finally {
    domainRequest = undefined;
    renderDomainVerification();
  }
}

function updateTargetFields() {
  const target = targetUrl();
  const mode = targetMode(target);
  const external = isExternalTarget(target);
  const lab = mode === 'lab';
  const profile = matchingActiveProfile(target);
  const showExpectation = external && !lab;
  const showTask = mode === 'demo' || mode === 'ai';
  const builtInLab = isLabTarget(target);
  const activeAvailable = Boolean(profile || builtInLab);
  if (mode !== currentMode) {
    if (currentMode === 'ai') aiTask = task.value;
    task.value = mode === 'demo' ? demoTask : aiTask;
    currentMode = mode;
  }
  taskField.hidden = !showTask;
  task.disabled = !showTask;
  task.readOnly = mode === 'demo';
  task.required = mode === 'ai';
  inspectionNote.hidden = mode !== 'inspection' || !external;
  activeSecurityNote.hidden = !lab;
  activeSecurityNote.textContent = profile
    ? `Voert de ingestelde controles van ${profile.name} uit.`
    : 'Controleert toegang tot oefenrecords en sessiehergebruik na uitloggen.';
  startLabel.textContent = lab && profile ? 'Start beveiligingscontrole' : startLabels[mode];
  expectation.hidden = !showExpectation;
  expectation.disabled = !showExpectation;
  securityOption.hidden = !external;
  securityEnabled.disabled = !external || lab;
  activeSecurityLabel.textContent = profile ? 'Actieve beveiligingscontrole' : 'Actieve labcontrole';
  activeSecurityOption.hidden = !activeAvailable;
  activeSecurityEnabled.disabled = !activeAvailable;
  if (!activeAvailable) activeSecurityEnabled.checked = false;
  updateTargetSecurityHistory(profile?.id ?? (builtInLab ? `lab-${target.pathname.slice(1)}` : undefined), Boolean(profile));
  renderDomainVerification(target);
}

function markPreset(scenario) {
  updateTargetFields();
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
securityEnabled.addEventListener('change', updateTargetFields);
activeSecurityEnabled.addEventListener('change', updateTargetFields);
domainChallenge.addEventListener('click', () => runDomainAction('challenge'));
domainVerify.addEventListener('click', () => runDomainAction('verify'));
selectDemo('bug');
const capabilities = request('/api/capabilities').then(data => {
  aiOrigins = new Set(data.aiOrigins);
  securityLabOrigin = data.securityLabOrigin;
  activeSecurityProfiles = data.activeSecurityProfiles ?? [];
  verifiedOrigins = new Set(data.verifiedOrigins);
  requireDomainVerification = data.requireDomainVerification === true;
  updateTargetFields();
}).catch(() => {
  // The server still validates the target and its selected test mode when a run starts.
});

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
const modeLabels = { demo: 'Demo', inspection: 'Website', ai: 'AI', lab: 'Lab' };

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
  let checks = run.steps;
  if (run.mode === 'demo') checks = run.steps.slice(1);
  if (run.mode === 'ai') checks = run.steps.filter(step => step.check);
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

const securityLabels = {
  observed: 'Waargenomen',
  review: 'Te beoordelen',
  not_observed: 'Niet waargenomen',
  recommendation: 'Aanbeveling',
};
const securitySeverity = { info: 'Informatief', low: 'Laag', medium: 'Middel' };

function appendSecurityReferences(item, references) {
  for (const reference of references ?? []) {
    if (!reference.url.startsWith('https://github.com/OWASP/ASVS/blob/v5.0.0/')) continue;
    const citation = document.createElement('p');
    citation.append(screenshotLink(reference.url, `ASVS ${reference.id} ↗`));
    if (reference.applicability) citation.append(` · ${reference.applicability}`);
    item.append(citation);
  }
}

function renderSecurity(run) {
  securityPanel.hidden = !run.securityRequested;
  if (securityPanel.hidden) return;
  if (securityPanel.dataset.run !== run.id) {
    securityPanel.dataset.run = run.id;
    securityPanel.dataset.state = '';
    securityDetails.open = false;
  }
  const state = run.security ? 'ready' : run.status === 'running' ? 'loading' : 'unavailable';
  if (securityPanel.dataset.state === state) return;
  securityPanel.dataset.state = state;
  securityChecks.replaceChildren();
  securityUntested.replaceChildren();
  securityScope.hidden = true;
  securityDetails.hidden = state !== 'ready';
  securityCount.hidden = state !== 'ready';
  if (state !== 'ready') {
    securityStatus.textContent = state === 'loading' ? 'Wachten op de documentrespons…' : 'Documentrespons niet beschikbaar.';
    return;
  }
  const { document: source, standard, checks, scope } = run.security;
  securityStatus.textContent = source
    ? `${standard} · Documentrespons HTTP ${source.httpStatus} · ${source.url}. De resultaten gelden voor deze respons.`
    : `${standard} · Documentrespons niet beschikbaar.`;
  if (scope) {
    securitySample.textContent = scope.sample;
    for (const category of scope.untested) {
      const item = document.createElement('li');
      item.textContent = category;
      securityUntested.append(item);
    }
    securityScope.hidden = false;
  }
  const pending = checks.filter(check => check.status === 'review').length;
  securityCount.dataset.state = pending ? 'review' : 'observed';
  securityCount.textContent = `${pending} te beoordelen`;
  for (const check of checks) {
    const item = document.createElement('li');
    const title = document.createElement('h3');
    title.textContent = check.title;
    const badge = document.createElement('span');
    badge.className = 'badge';
    badge.dataset.state = check.status;
    badge.textContent = check.status === 'review'
      ? `${securityLabels.review} · ${securitySeverity[check.severity]}`
      : securityLabels[check.status];
    const evidence = document.createElement('p');
    evidence.textContent = check.evidence;
    item.append(title, badge, evidence);
    if (check.advice) {
      const advice = document.createElement('p');
      advice.textContent = check.advice;
      item.append(advice);
    }
    appendSecurityReferences(item, check.asvs);
    securityChecks.append(item);
  }
}

const labOutcomeLabels = {
  confirmed: 'Kwetsbaarheid bevestigd',
  protected: 'Afgeweerd',
  inconclusive: 'Onbeslist',
  not_tested: 'Niet getest',
};
const profileOutcomeLabels = {
  confirmed: 'Bevestigd',
  protected: 'Beschermd',
  inconclusive: 'Niet vastgesteld',
  not_tested: 'Niet getest',
};
const labObservationLabels = {
  aliceSessionHttpStatus: 'Aanmelden Alice',
  bobSessionHttpStatus: 'Aanmelden Bob',
  distinctSessions: 'Afzonderlijke sessies',
  anonymousHttpStatus: 'Toegang zonder sessie',
  aliceOwn: 'Eigen record van Alice',
  bobOwn: 'Eigen record van Bob',
  crossSessionApplicable: 'Sessiecookie van Bob is geldig voor het pad van Alice',
  cross: 'Bob vraagt het record van Alice op',
  before: 'Eigen record vóór uitloggen',
  replayBeforeLogout: 'Hergebruik van de oorspronkelijke sessie vóór uitloggen',
  logoutHttpStatus: 'Uitloggen',
  cookieRemoved: 'Cookie na uitloggen uit de browser verwijderd',
  afterLogout: 'Verzoek uit dezelfde browsercontext na uitloggen',
  replayCookieStored: 'Oorspronkelijke cookie in aparte browsercontext geplaatst',
  replay: 'Hergebruik van de oorspronkelijke sessie',
};
const profileObservationLabels = {
  ...labObservationLabels,
  aliceSessionHttpStatus: 'Aanmelden eerste testaccount',
  bobSessionHttpStatus: 'Aanmelden tweede testaccount',
  aliceOwn: 'Eigen record van het eerste testaccount',
  bobOwn: 'Eigen record van het tweede testaccount',
  crossSessionApplicable: 'Sessiecookie van het tweede testaccount geldt voor het geteste pad',
  cross: 'Tweede testaccount vraagt het record van het eerste testaccount op',
};

function labBoolean(value) {
  if (value === true) return 'Ja';
  if (value === false) return 'Nee';
  return 'Onbekend';
}

function labEvidenceValue(value) {
  if (value && typeof value === 'object') {
    return `${labEvidenceValue(value.httpStatus)} · Verwacht record ontvangen · ${labBoolean(value.recordMatched)}`;
  }
  if (Number.isInteger(value)) return `HTTP ${value}`;
  if (typeof value === 'boolean') return labBoolean(value);
  if (Object.hasOwn(labOutcomeLabels, value)) return labOutcomeLabels[value];
  return 'HTTP-status onbekend';
}

function appendLabDefinition(list, label, value) {
  const term = document.createElement('dt');
  term.textContent = label;
  const definition = document.createElement('dd');
  definition.textContent = value;
  list.append(term, definition);
}

function appendLabEvidence(details, heading, evidence, observationLabels, exclude) {
  if (!evidence) return;
  const list = document.createElement('dl');
  list.className = 'lab-observations';
  for (const [field, label] of Object.entries({ status: 'Uitkomst', ...observationLabels })) {
    if (field !== exclude && Object.hasOwn(evidence, field)) {
      appendLabDefinition(list, label, labEvidenceValue(evidence[field]));
    }
  }
  if (!list.children.length) return;
  const title = document.createElement('h4');
  title.textContent = heading;
  details.append(title, list);
}

function renderLabCheck(check, configured) {
  const item = document.createElement('li');
  const title = document.createElement('h3');
  title.textContent = check.title;
  const badge = document.createElement('span');
  badge.className = 'badge';
  badge.dataset.state = check.status;
  badge.textContent = (configured ? profileOutcomeLabels : labOutcomeLabels)[check.status];
  item.append(title, badge);
  appendObservation(item, 'Route', check.route);

  const observed = check.observed ?? {};
  const observationLabels = configured ? profileObservationLabels : labObservationLabels;
  const key = Object.hasOwn(observed, 'cross') ? 'cross' : 'replay';
  if (Object.hasOwn(observed, key)) {
    const mainEvidence = document.createElement('p');
    mainEvidence.textContent = `${observationLabels[key]} · ${labEvidenceValue(observed[key])}`;
    item.append(mainEvidence);
  }
  appendObservation(item, 'Herstel', check.repair);

  const details = document.createElement('details');
  const disclosure = document.createElement('summary');
  disclosure.textContent = 'Waarnemingen en reproduceerstappen';
  details.append(disclosure);
  appendLabEvidence(details, 'Verwacht', check.expected, observationLabels);
  appendLabEvidence(details, 'Waargenomen', observed, observationLabels, key);
  const reproduction = document.createElement('ol');
  reproduction.className = 'lab-reproduction';
  for (const instruction of check.reproduction ?? []) {
    const step = document.createElement('li');
    step.textContent = instruction;
    reproduction.append(step);
  }
  if (reproduction.children.length) details.append(reproduction);
  appendSecurityReferences(details, check.asvs);
  if (details.children.length > 1) item.append(details);
  return item;
}

function renderLabCookies(browserCookies, configured) {
  activeSecurityCookieObservations.replaceChildren();
  for (const [key, name] of [
    ['alice', configured ? 'Eerste testaccount vóór uitloggen' : 'Alice vóór uitloggen'],
    ['bob', configured ? 'Tweede testaccount' : 'Bob'],
    ['afterLogout', configured ? 'Eerste testaccount na uitloggen' : 'Alice na uitloggen'],
    ['replay', 'Aparte context met oorspronkelijke cookie'],
  ]) {
    const cookie = browserCookies?.[key];
    if (!cookie) continue;
    const title = document.createElement('h3');
    title.textContent = name;
    const attributes = document.createElement('dl');
    attributes.className = 'lab-observations';
    const sameSite = Object.entries({ sameSiteLax: 'Lax', sameSiteStrict: 'Strict', sameSiteNone: 'None' })
      .find(([flag]) => cookie[flag] === true)?.[1];
    appendLabDefinition(attributes, 'Opgeslagen in de browser', labBoolean(cookie.stored));
    appendLabDefinition(attributes, 'Secure', cookie.stored ? labBoolean(cookie.secure) : 'Niet waargenomen');
    appendLabDefinition(attributes, 'HttpOnly', cookie.stored ? labBoolean(cookie.httpOnly) : 'Niet waargenomen');
    appendLabDefinition(attributes, 'SameSite', sameSite ?? 'Niet waargenomen');
    appendLabDefinition(attributes, 'Zichtbaar voor JavaScript', labBoolean(cookie.scriptVisible));
    const account = document.createElement('section');
    account.append(title, attributes);
    activeSecurityCookieObservations.append(account);
  }
  activeSecurityCookies.hidden = !activeSecurityCookieObservations.children.length;
}

const comparisonLabels = {
  baseline: 'Eerste meting',
  new: 'Nieuw',
  resolved: 'Opgelost',
  reappeared: 'Teruggekeerd',
  unchanged: 'Ongewijzigd',
  not_tested: 'Niet getest',
};

function renderSecurityComparison(comparison, checks, profile) {
  securityComparisonChecks.replaceChildren();
  securityComparison.hidden = !comparison?.checks?.length;
  if (securityComparison.hidden) return;
  const previousId = comparison.previousRunId;
  securityComparisonBaseline.hidden = !previousId || !profile?.id;
  securityComparisonBaseline.onclick = previousId && profile?.id
    ? () => openSecurityReport(previousId, profile.id, securityComparisonBaseline, reportHistoryView)
    : null;
  for (const result of comparison.checks) {
    const item = document.createElement('li');
    const title = document.createElement('span');
    title.textContent = checks.find(check => check.id === result.id)?.title ?? result.id;
    const badge = document.createElement('span');
    badge.className = 'badge';
    badge.dataset.state = result.status;
    badge.textContent = comparisonLabels[result.status];
    item.append(title, badge);
    if (result.comparedWithRunId && result.comparedWithRunId !== previousId && profile?.id) {
      const button = document.createElement('button');
      button.type = 'button';
      button.className = 'preset';
      button.textContent = 'Bekijk vergelijkingsbewijs';
      button.setAttribute('aria-label', `Bekijk vergelijkingsbewijs · ${title.textContent}`);
      button.addEventListener('click', () => openSecurityReport(result.comparedWithRunId, profile.id, button, reportHistoryView));
      item.append(button);
    }
    securityComparisonChecks.append(item);
  }
}

async function openSecurityReport(id, profileId, button, view) {
  if (start.disabled) return;
  const selection = ++historySelection;
  const requestedView = view.request;
  const stillSelected = () => selection === historySelection && view.request === requestedView && !start.disabled;
  button.disabled = true;
  try {
    const report = await request(`/api/runs/${encodeURIComponent(id)}`);
    if (!stillSelected()) return;
    if (report.activeSecurity?.profile?.id !== profileId || report.status === 'running') {
      throw new Error('Dit rapport hoort niet bij de gekozen beveiligingsgeschiedenis.');
    }
    render(report);
    if (view === targetHistoryView) targetSecurityHistory.open = false;
    activeSecurityHeading.focus();
  } catch (failure) {
    if (stillSelected()) view.status.textContent = failure.message;
  } finally {
    button.disabled = false;
  }
}

function historyEntry(entry, currentRunId, profileId, configured, view) {
  const row = document.createElement('li');
  const header = document.createElement('div');
  header.className = 'security-history-entry';
  const time = document.createElement('time');
  const finished = entry.finishedAt ? new Date(entry.finishedAt) : null;
  time.textContent = Number.isFinite(finished?.getTime()) ? localDate.format(finished) : 'Tijdstip onbekend';
  if (Number.isFinite(finished?.getTime())) time.dateTime = finished.toISOString();
  const badge = document.createElement('span');
  badge.className = 'badge';
  badge.dataset.state = entry.status;
  badge.textContent = labels[entry.status] ?? entry.status;
  header.append(time, badge);
  if (entry.id === currentRunId) {
    row.setAttribute('aria-current', 'true');
    const current = document.createElement('span');
    current.textContent = 'Getoond rapport';
    header.append(current);
  } else {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'preset';
    button.textContent = 'Bekijk rapport';
    button.setAttribute('aria-label', `Bekijk rapport · ${time.textContent}`);
    button.addEventListener('click', () => openSecurityReport(entry.id, profileId, button, view));
    header.append(button);
  }
  row.append(header);
  const outcomes = document.createElement('p');
  const outcomeLabels = configured ? profileOutcomeLabels : labOutcomeLabels;
  outcomes.textContent = (entry.checks ?? [])
    .map(check => `${check.title} · ${outcomeLabels[check.status] ?? check.status}`)
    .join(' / ');
  if (outcomes.textContent) row.append(outcomes);
  return row;
}

async function loadSecurityHistory(view, profileId, currentRunId, configured) {
  const selection = { profileId, currentRunId };
  view.request = selection;
  view.status.textContent = 'Geschiedenis laden…';
  view.rows.replaceChildren();
  try {
    const query = new URLSearchParams({ profileId });
    const { runs } = await request(`/api/security/history?${query}`);
    if (view.request !== selection) return;
    view.status.textContent = runs.length ? '' : 'Er zijn nog geen opgeslagen controles voor dit profiel.';
    view.rows.replaceChildren(...runs.map(entry => historyEntry(entry, currentRunId, profileId, configured, view)));
  } catch {
    if (view.request === selection) view.status.textContent = 'De beveiligingsgeschiedenis kon niet worden geladen.';
  }
}

function renderSecurityHistory(run, profile) {
  securityHistory.hidden = !profile?.id || run.status === 'running';
  if (securityHistory.hidden) {
    reportHistoryView.request = undefined;
    securityHistory.open = false;
    return;
  }
  const requested = reportHistoryView.request;
  if (requested?.profileId === profile.id && requested.currentRunId === run.id) return;
  void loadSecurityHistory(reportHistoryView, profile.id, run.id, Boolean(run.activeProfile));
}

function updateTargetSecurityHistory(profileId, configured) {
  targetSecurityHistory.hidden = !profileId;
  if (targetHistoryProfile?.id === profileId) return;
  targetHistoryProfile = profileId ? { id: profileId, configured } : undefined;
  targetHistoryView.request = undefined;
  targetSecurityHistory.open = false;
}

targetSecurityHistory.addEventListener('toggle', () => {
  if (!targetSecurityHistory.open || !targetHistoryProfile) {
    targetHistoryView.request = undefined;
    return;
  }
  void loadSecurityHistory(targetHistoryView, targetHistoryProfile.id, latestRun?.id, targetHistoryProfile.configured);
});

function renderActiveSecurity(run) {
  activeSecurityPanel.hidden = run.mode !== 'lab';
  if (activeSecurityPanel.hidden) {
    lastActiveSecurityResults = undefined;
    reportHistoryView.request = undefined;
    securityHistory.open = false;
    return;
  }
  const { checks = [], browserCookies, explanation, comparison } = run.activeSecurity ?? {};
  const profile = run.activeSecurity?.profile ?? run.activeProfile;
  activeSecurityHeading.textContent = run.activeProfile ? 'Actieve beveiligingsresultaten' : 'Actieve labresultaten';
  activeSecurityProfile.hidden = !profile;
  activeSecurityProfile.textContent = profile ? [profile.name, profile.url].filter(Boolean).join(' · ') : '';
  activeSecurityExplanation.hidden = !explanation;
  const explanationText = explanation ?? '';
  if (activeSecurityExplanationText.textContent !== explanationText) activeSecurityExplanationText.textContent = explanationText;
  const scopeText = run.activeProfile ? 'Vaste controles uit het ingestelde profiel.' : 'Vaste controles met synthetische accounts en records.';
  const statusText = checks.length ? scopeText
    : run.status === 'running' ? 'De actieve controles worden uitgevoerd…' : 'De resultaten zijn niet beschikbaar.';
  if (activeSecurityStatus.textContent !== statusText) activeSecurityStatus.textContent = statusText;
  renderSecurityHistory(run, profile);
  const resultKey = JSON.stringify([run.id, checks, browserCookies, comparison]);
  if (lastActiveSecurityResults === resultKey) return;
  lastActiveSecurityResults = resultKey;
  activeSecurityChecks.hidden = !checks.length;
  activeSecurityChecks.replaceChildren(...checks.map(check => renderLabCheck(check, Boolean(run.activeProfile))));
  activeSecurityCookies.open = false;
  renderLabCookies(browserCookies, Boolean(run.activeProfile));
  renderSecurityComparison(comparison, checks, profile);
}

function render(run) {
  if (latestRun?.id !== run.id) {
    steps.replaceChildren();
    pinnedStepIndex = null;
  }
  latestRun = run;
  document.querySelector('#empty').hidden = run.steps.length > 0;
  const coverage = run.coverage ?? 'unknown';
  const modeName = run.mode === 'lab' && run.activeProfile ? 'Beveiliging' : modeLabels[run.mode] ?? modeLabels.ai;
  status.textContent = `${modeName} · ${labels[run.status]} · ${coverageLabels[coverage] ?? coverageLabels.unknown}`;
  status.dataset.state = run.status;
  status.dataset.coverage = coverage;
  const description = [run.summary, run.status !== 'error' && run.incompleteReason].filter(Boolean).join(' ');
  summary.hidden = !description;
  summary.textContent = description;
  renderCounts(run);
  renderSecurity(run);
  renderActiveSecurity(run);
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
  if (!response.ok) {
    const failure = new Error(data.error);
    failure.code = data.code;
    throw failure;
  }
  return data;
}

form.addEventListener('submit', async event => {
  event.preventDefault();
  historySelection++;
  targetSecurityHistory.open = false;
  targetHistoryView.request = undefined;
  start.disabled = true;
  error.hidden = true;
  let submittedOrigin;
  let submittedProfile;
  try {
    const submittedUrl = url.value;
    if (!isDemoTarget(targetUrl())) await capabilities;
    if (url.value !== submittedUrl || !form.reportValidity()) return;
    const target = targetUrl();
    const mode = targetMode(target);
    submittedOrigin = target?.origin;
    submittedProfile = mode === 'lab' ? matchingActiveProfile(target) : undefined;
    if (needsDomainVerification(target) && !isDomainVerified(submittedOrigin)) {
      renderDomainVerification(target);
      domainVerification.open = true;
      domainVerification.querySelector('summary').focus();
      return;
    }
    const input = { url: submittedUrl, authorized: authorized.checked };
    if (securityEnabled.checked && !securityEnabled.disabled) input.security = true;
    if (mode === 'lab') {
      input.activeSecurity = true;
      if (submittedProfile) input.activeProfileId = submittedProfile.id;
    }
    if (!task.disabled) input.task = task.value;
    const value = expectationText.value.trim();
    if (value && !expectation.disabled) {
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
    if (failure.code === 'DOMAIN_NOT_VERIFIED') {
      if (!submittedProfile) requireDomainVerification = true;
      verifiedOrigins.delete(submittedOrigin);
      const state = domainStates.get(submittedOrigin);
      if (state) state.verifiedUntil = undefined;
      renderDomainVerification();
    }
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
