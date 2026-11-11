export function getRunStatus({
  error = false,
  coverage,
  verifiedFailures = 0,
  unverifiedFindings = 0,
  technicalErrors = 0,
  warnings = 0,
  summary,
}) {
  if (error) return 'error';
  if (verifiedFailures > 0) return 'failed';
  if (unverifiedFindings > 0) return 'review';
  if (coverage === 'partial' || (!summary && coverage !== 'full')) return 'incomplete';
  if (technicalErrors > 0 || warnings > 0) return 'completed_with_issues';
  return 'completed';
}

export function checkKey({ condition, value, expected }) {
  return JSON.stringify([condition, value, expected]);
}

export function getRunOutcome(run) {
  const coverage = run.coverage ?? (run.status === 'incomplete' ? 'partial' : 'unknown');
  const verifiedFailures = run.steps.filter(step => step.status === 'failed').length;
  const unverifiedFindings = run.steps.filter(step => step.status === 'finding').length;
  const technicalErrors = run.steps.filter(step => step.status === 'error').length;
  const warnings = run.steps.filter(step => step.status === 'warning').length;
  const declaredChecks = new Set((run.expectations ?? []).map(checkKey));
  const verifiedChecks = new Set(run.steps
    .filter(step => step.check && (step.status === 'passed' || step.status === 'failed'))
    .map(step => checkKey(step.check))
    .filter(key => declaredChecks.has(key))).size;
  const status = getRunStatus({
    error: run.status === 'error',
    coverage,
    verifiedFailures,
    unverifiedFindings,
    technicalErrors,
    warnings,
    summary: run.summary,
  });
  return {
    status,
    coverage,
    incompleteReason: run.incompleteReason ?? null,
    verifiedFailures,
    unverifiedFindings,
    technicalErrors,
    warnings,
    verifiedChecks,
    totalChecks: declaredChecks.size,
  };
}
