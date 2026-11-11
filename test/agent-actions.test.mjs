import assert from 'node:assert/strict';
import { test } from 'node:test';
import { parseAgentAction, parseExpectations } from '../agent-actions.mjs';

const controls = [
  { index: 0, kind: 'input', type: 'text' },
  { index: 1, kind: 'button', type: 'submit' },
  { index: 2, kind: 'textarea', type: 'textarea' },
];
const parse = action => parseAgentAction(JSON.stringify(action), controls);

test('the model must return a single JSON action with supported fields', () => {
  const click = { action: 'click', index: 1 };
  assert.deepEqual(parseAgentAction('```json\n{"action":"click","index":1}\n```', controls), click);
  assert.throws(() => parseAgentAction('{"action":"click","index":1} uitleg', controls), /ongeldige JSON/);
  assert.throws(() => parse([click]), /JSON-object/);
  assert.throws(() => parse({ ...click, selector: '#knop' }), /onbekend veld/);
  assert.throws(() => parse({ action: 'eval' }), /Kies click/);
});

test('click, fill and screenshot are limited to offered controls', () => {
  assert.deepEqual(parse({ action: 'click', index: 0 }), { action: 'click', index: 0 });
  assert.deepEqual(parse({ action: 'fill', index: 2, value: '' }), { action: 'fill', index: 2, value: '' });
  assert.deepEqual(parse({ action: 'screenshot', index: 1, label: 'Knop' }), { action: 'screenshot', index: 1, label: 'Knop' });
  assert.deepEqual(parse({ action: 'screenshot' }), { action: 'screenshot' });
  assert.throws(() => parse({ action: 'click', index: 3 }), /aangeboden element/);
  assert.throws(() => parse({ action: 'fill', index: 1, value: 'x' }), /invulveld/);
  assert.throws(() => parse({ action: 'fill', index: 0, value: 'x'.repeat(201) }), /maximaal 200/);
  assert.throws(() => parse({ action: 'screenshot', index: '1' }), /geheel getal/);
});

test('assert and wait require bounded visible text and a boolean expectation', () => {
  assert.deepEqual(parse({ action: 'assert', condition: 'text_visible', value: '  Opgeslagen  ', expected: false }), {
    action: 'assert', condition: 'text_visible', value: 'Opgeslagen', expected: false,
  });
  assert.deepEqual(parse({ action: 'wait', condition: 'text_visible', value: 'Opgeslagen' }), {
    action: 'wait', condition: 'text_visible', value: 'Opgeslagen', expected: true, timeoutMs: 4000,
  });
  const check = { action: 'assert', condition: 'text_visible', value: 'Opgeslagen', expected: true };
  assert.throws(() => parse({ ...check, condition: 'selector_exists' }), /voorwaarde text_visible/);
  assert.throws(() => parse({ ...check, value: '  ' }), /veld value/i);
  assert.throws(() => parse({ ...check, expected: 'true' }), /true of false/);
  assert.throws(() => parse({ ...check, action: 'wait', timeoutMs: 4001 }), /tussen 1 en 4000/);
});

test('finish validates every finding and preserves evidence IDs for the runner', () => {
  const finding = { title: 'Bevestiging ontbreekt', detail: 'Klik op Opslaan.', evidenceStepIds: ['step-002', 'step-999'] };
  assert.deepEqual(parse({ action: 'finish', summary: 'Afgerond', findings: [finding] }), {
    action: 'finish', summary: 'Afgerond', findings: [finding],
  });
  assert.deepEqual(parse({ action: 'finish', summary: 'Afgerond' }), {
    action: 'finish', summary: 'Afgerond', findings: [],
  });
  assert.throws(() => parse({ action: 'finish', summary: 'Afgerond', findings: [{ ...finding, screenshot: '/3.png' }] }), /onbekend veld/);
  assert.throws(() => parse({ action: 'finish', summary: 'Afgerond', findings: [{ ...finding, evidenceStepIds: [2] }] }), /evidenceStepIds/);
});

test('explicit expectations use the same normalized condition as model assertions', () => {
  const rule = { condition: 'text_visible', value: ' Opgeslagen ', expected: true };
  assert.deepEqual(parseExpectations(undefined), []);
  assert.deepEqual(parseExpectations([rule]), [{ ...rule, value: 'Opgeslagen' }]);
  assert.throws(() => parseExpectations([ { ...rule, action: 'assert' } ]), /onbekend veld/);
  assert.throws(() => parseExpectations([ { ...rule, expected: null } ]), /true of false/);
  assert.throws(() => parseExpectations(Array(11).fill(rule)), /maximaal tien/);
});
