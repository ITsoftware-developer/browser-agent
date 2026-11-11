const fillableTypes = new Set(['text', 'search', 'email', 'url', 'tel', 'number']);

function checkFields(value, fields, context) {
  if (!value || Object.getPrototypeOf(value) !== Object.prototype) {
    throw new Error(`${context} moet een JSON-object zijn.`);
  }
  if (Object.keys(value).some(key => !fields.includes(key))) {
    throw new Error(`${context} bevat een onbekend veld.`);
  }
}

function checkText(value, field, limit, allowEmpty = false) {
  if (typeof value !== 'string' || value.length > limit || (!allowEmpty && !value.trim())) {
    throw new Error(`Veld ${field} moet tekst van maximaal ${limit} tekens bevatten.`);
  }
  return value;
}

function checkControl(index, controls) {
  if (!Number.isInteger(index) || index < 0) {
    throw new Error('Veld index moet een niet-negatief geheel getal zijn.');
  }
  const control = controls.find(candidate => candidate.index === index);
  if (!control) throw new Error('Kies de index van een aangeboden element.');
  return control;
}

function parseCondition({ condition, value, expected }) {
  if (condition !== 'text_visible') throw new Error('Gebruik de voorwaarde text_visible.');
  if (typeof expected !== 'boolean') throw new Error('Veld expected moet true of false zijn.');
  return { condition, value: checkText(value, 'value', 300).trim(), expected };
}

function parseFinding(finding) {
  checkFields(finding, ['title', 'detail', 'fix', 'expected', 'actual', 'evidenceStepIds'], 'Een bevinding');
  const result = {
    title: checkText(finding.title, 'title', 150),
    detail: checkText(finding.detail, 'detail', 1500),
  };
  for (const field of ['fix', 'expected', 'actual']) {
    if (Object.hasOwn(finding, field)) result[field] = checkText(finding[field], field, 1000, true);
  }
  if (Object.hasOwn(finding, 'evidenceStepIds')) {
    if (!Array.isArray(finding.evidenceStepIds) || finding.evidenceStepIds.length > 20) {
      throw new Error('Veld evidenceStepIds moet een lijst met maximaal twintig stap-ID’s zijn.');
    }
    result.evidenceStepIds = finding.evidenceStepIds.map(id => checkText(id, 'evidenceStepIds', 256));
  }
  return result;
}

export function parseAgentAction(content, controls = []) {
  if (typeof content !== 'string' || content.length > 65536) {
    throw new Error('Geef één JSON-object als antwoord.');
  }
  const text = content.trim();
  const fence = '```';
  const json = text.startsWith(fence) && text.endsWith(fence)
    ? text.slice(fence.length, -fence.length).replace(/^json\b/i, '')
    : text;
  let input;
  try {
    input = JSON.parse(json);
  } catch {
    throw new Error('Het antwoord bevat ongeldige JSON.');
  }
  if (!input || Object.getPrototypeOf(input) !== Object.prototype) {
    throw new Error('Geef één JSON-object als antwoord.');
  }

  switch (input.action) {
    case 'click':
      checkFields(input, ['action', 'index'], 'De klikactie');
      checkControl(input.index, controls);
      return input;
    case 'fill': {
      checkFields(input, ['action', 'index', 'value'], 'De invulactie');
      const control = checkControl(input.index, controls);
      if (control.kind !== 'textarea' && !(control.kind === 'input' && fillableTypes.has(control.type))) {
        throw new Error('Kies een aangeboden invulveld voor de actie fill.');
      }
      checkText(input.value, 'value', 200, true);
      return input;
    }
    case 'assert':
      checkFields(input, ['action', 'condition', 'value', 'expected'], 'De controle');
      return { action: 'assert', ...parseCondition(input) };
    case 'wait': {
      checkFields(input, ['action', 'condition', 'value', 'expected', 'timeoutMs'], 'De wachtactie');
      const expected = Object.hasOwn(input, 'expected') ? input.expected : true;
      const timeoutMs = Object.hasOwn(input, 'timeoutMs') ? input.timeoutMs : 4000;
      if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 4000) {
        throw new Error('Veld timeoutMs moet een geheel getal tussen 1 en 4000 zijn.');
      }
      return { action: 'wait', ...parseCondition({ ...input, expected }), timeoutMs };
    }
    case 'screenshot':
      checkFields(input, ['action', 'index', 'label'], 'De screenshotactie');
      if (Object.hasOwn(input, 'index')) checkControl(input.index, controls);
      if (Object.hasOwn(input, 'label')) checkText(input.label, 'label', 150);
      return input;
    case 'finish': {
      checkFields(input, ['action', 'summary', 'findings'], 'De afrondactie');
      const summary = checkText(input.summary, 'summary', 1200);
      const findings = Object.hasOwn(input, 'findings') ? input.findings : [];
      if (!Array.isArray(findings) || findings.length > 6) {
        throw new Error('Veld findings moet een lijst met maximaal zes bevindingen zijn.');
      }
      return { action: 'finish', summary, findings: findings.map(parseFinding) };
    }
    default:
      throw new Error('Kies click, fill, assert, wait, screenshot of finish als action.');
  }
}

export function parseExpectations(value) {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.length > 10) {
    throw new Error('Geef maximaal tien expliciete verwachtingen op.');
  }
  return value.map(expectation => {
    checkFields(expectation, ['condition', 'value', 'expected'], 'Een verwachting');
    return parseCondition(expectation);
  });
}
