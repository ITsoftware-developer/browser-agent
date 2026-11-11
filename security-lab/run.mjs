import { AgentError, requestModel } from '../runner.mjs';
import { runActiveSecurity } from './browser-probes.mjs';

const stepStatuses = { confirmed: 'failed', protected: 'passed', inconclusive: 'error' };

function evidenceText(check) {
  const result = check.id === 'object-authorization' ? check.observed.cross : check.observed.replay;
  const action = check.id === 'object-authorization' ? 'Opvraag van het andere dossier' : 'Opvraag met de oude sessie';
  const http = result?.httpStatus ? `HTTP ${result.httpStatus}` : 'geen HTTP-respons';
  const observation = result?.recordMatched ? 'het verwachte fictieve dossier is ontvangen' : 'het fictieve dossier is niet aangetroffen';
  return `${action} gaf ${http}. ${observation}.`;
}

export async function runLabChecks({ run, profile, model, endpoint, modelTimeoutMs = 5000 }) {
  let report;
  try {
    report = await runActiveSecurity(profile);
  } catch (error) {
    throw new AgentError('lab_unavailable', 'Het geconfigureerde Security Lab kon niet worden geverifieerd.', { cause: error });
  }
  run.activeSecurity = report;
  for (const check of report.checks) {
    const sequence = run.steps.length + 1;
    run.steps.push({
      id: `step-${String(sequence).padStart(3, '0')}`,
      sequence,
      title: check.title,
      status: stepStatuses[check.status],
      detail: evidenceText(check),
    });
  }
  const inconclusive = report.checks.some(check => check.status === 'inconclusive');
  run.coverage = inconclusive ? 'partial' : 'full';
  if (inconclusive) run.incompleteReason = 'Voor een of meer labcontroles ontbreekt beslissend browserbewijs.';
  run.summary = 'Autorisatie en sessie-intrekking zijn getest met fictieve accounts in het lokale Security Lab.';

  const findings = report.checks.filter(check => check.status === 'confirmed');
  if (model && endpoint && findings.length) {
    try {
      const explanation = await requestModel({ model, endpoint, modelTimeoutMs: Math.min(modelTimeoutMs, 5000) }, [
        {
          role: 'system',
          content: 'Leg in het Nederlands uit wat de vastgelegde HTTP-bewijzen in dit fictieve lab betekenen. Gebruik hoogstens 120 woorden. Beperk je tot het aangeleverde bewijs en algemeen hersteladvies.',
        },
        { role: 'user', content: JSON.stringify(findings.map(({ id, observed }) => ({ id, observed }))) },
      ]);
      if (typeof explanation === 'string' && explanation.trim()) report.explanation = explanation.trim().slice(0, 1600);
    } catch {
      // The optional model response cannot change evidence or the run outcome.
    }
  }
}
