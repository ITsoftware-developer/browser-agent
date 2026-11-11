import assert from 'node:assert/strict';
import { test } from 'node:test';
import { getRunOutcome, getRunStatus } from '../run-status.mjs';

test('a technical error takes precedence over failed checks and AI findings', () => {
  assert.equal(getRunStatus({
    error: true,
    coverage: 'partial',
    verifiedFailures: 1,
    unverifiedFindings: 2,
    technicalErrors: 3,
  }), 'error');
});

test('verified failures take precedence over AI findings and partial coverage', () => {
  assert.equal(getRunStatus({
    coverage: 'partial',
    verifiedFailures: 1,
    unverifiedFindings: 2,
    technicalErrors: 3,
  }), 'failed');
});

test('AI findings require review even with a summary or partial coverage', () => {
  assert.equal(getRunStatus({ coverage: 'full', unverifiedFindings: 1, summary: 'Test uitgevoerd.' }), 'review');
  assert.equal(getRunStatus({ coverage: 'partial', unverifiedFindings: 1, warnings: 2 }), 'review');
});

test('completion accounts for coverage as well as the summary', () => {
  assert.equal(getRunStatus({ coverage: 'partial', summary: 'Een deel getest.', warnings: 1 }), 'incomplete');
  assert.equal(getRunStatus({ coverage: 'unknown' }), 'incomplete');
  assert.equal(getRunStatus({ coverage: 'unknown', summary: 'Test uitgevoerd.' }), 'completed');
  assert.equal(getRunStatus({ coverage: 'full' }), 'completed');
});

test('a legacy completed report with an AI finding is read as requiring review', () => {
  assert.deepEqual(getRunOutcome({
    status: 'completed',
    summary: 'Test uitgevoerd.',
    steps: [{ status: 'passed' }, { status: 'finding' }],
  }), {
    status: 'review',
    coverage: 'unknown',
    incompleteReason: null,
    verifiedFailures: 0,
    unverifiedFindings: 1,
    technicalErrors: 0,
    warnings: 0,
    verifiedChecks: 0,
    totalChecks: 0,
  });
});

test('review retains the reason for partial coverage and counts findings', () => {
  assert.deepEqual(getRunOutcome({
    status: 'review',
    coverage: 'partial',
    incompleteReason: 'Testlimiet bereikt.',
    steps: [{ status: 'finding' }, { status: 'skipped' }, { status: 'finding' }],
  }), {
    status: 'review',
    coverage: 'partial',
    incompleteReason: 'Testlimiet bereikt.',
    verifiedFailures: 0,
    unverifiedFindings: 2,
    technicalErrors: 0,
    warnings: 0,
    verifiedChecks: 0,
    totalChecks: 0,
  });
});

test('a persisted technical error retains the counts from the partial report', () => {
  assert.deepEqual(getRunOutcome({
    status: 'error',
    coverage: 'partial',
    incompleteReason: 'Model gaf geen antwoord.',
    steps: [{ status: 'failed' }, { status: 'finding' }, { status: 'failed' }],
  }), {
    status: 'error',
    coverage: 'partial',
    incompleteReason: 'Model gaf geen antwoord.',
    verifiedFailures: 2,
    unverifiedFindings: 1,
    technicalErrors: 0,
    warnings: 0,
    verifiedChecks: 0,
    totalChecks: 0,
  });
});

test('a legacy incomplete report is read with partial coverage', () => {
  const outcome = getRunOutcome({
    status: 'incomplete',
    summary: 'Een deel getest.',
    steps: [{ status: 'observed' }],
  });
  assert.equal(outcome.status, 'incomplete');
  assert.equal(outcome.coverage, 'partial');
  assert.equal(outcome.verifiedFailures, 0);
  assert.equal(outcome.unverifiedFindings, 0);
});

test('completed coverage retains technical errors and warnings', () => {
  const checked = { condition: 'text_visible', value: 'Bestelling ontvangen', expected: true };
  const outcome = getRunOutcome({
    coverage: 'full',
    expectations: [checked],
    steps: [{ status: 'passed', check: checked }, { status: 'error' }, { status: 'warning' }],
  });
  assert.equal(outcome.status, 'completed_with_issues');
  assert.equal(outcome.coverage, 'full');
  assert.equal(outcome.technicalErrors, 1);
  assert.equal(outcome.warnings, 1);
  assert.equal(outcome.verifiedChecks, 1);
  assert.equal(outcome.totalChecks, 1);
});

test('coverage counts unique matching explicit checks that produced a result', () => {
  const check = { condition: 'text_visible', value: 'Ingelogd', expected: true };
  const failedCheck = { condition: 'text_visible', value: 'Profiel', expected: true };
  const unverifiedCheck = { condition: 'text_visible', value: 'Aanmeldformulier', expected: false };
  const outcome = getRunOutcome({
    coverage: 'partial',
    expectations: [check, { ...check }, failedCheck, unverifiedCheck],
    steps: [
      { status: 'passed', check },
      { status: 'passed', check: { ...check } },
      { status: 'failed', check: failedCheck },
      { status: 'observed', check: unverifiedCheck },
      { status: 'error', check: unverifiedCheck },
      { status: 'passed', check: { ...unverifiedCheck, expected: true } },
      { status: 'passed' },
    ],
  });
  assert.equal(outcome.status, 'failed');
  assert.equal(outcome.coverage, 'partial');
  assert.equal(outcome.verifiedChecks, 2);
  assert.equal(outcome.totalChecks, 3);
  assert.equal(outcome.technicalErrors, 1);
});
