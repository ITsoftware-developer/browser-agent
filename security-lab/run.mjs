import { AgentError, requestModel } from '../runner.mjs';
import { resolvePublicAddress } from '../public-network.mjs';
import { profileRevision, profileSummary } from '../security-profiles.mjs';
import { runActiveSecurity } from './browser-probes.mjs';

const stepStatuses = { confirmed: 'failed', protected: 'passed', inconclusive: 'error', not_tested: 'skipped' };

function evidenceText(check) {
  const result = check.id === 'object-authorization' ? check.observed.cross : check.observed.replay;
  const action = check.id === 'object-authorization' ? 'Opvraag van het andere dossier' : 'Opvraag met de oude sessie';
  const http = result?.httpStatus ? `HTTP ${result.httpStatus}` : 'geen HTTP-respons';
  const observation = result?.recordMatched ? 'het verwachte fictieve dossier is ontvangen' : 'het fictieve dossier is niet aangetroffen';
  return `${action} gaf ${http}. ${observation}.`;
}

export async function runLabChecks({ run, profile, model, endpoint, modelTimeoutMs = 5000 }) {
  const profileMetadata = { ...profileSummary(profile), revision: profileRevision(profile),
    approvalReference: profile.approval.reference };
  let report;
  try {
    const pinnedAddress = profile.origin.startsWith('https:') ? await resolvePublicAddress(profile.origin) : undefined;
    report = await runActiveSecurity(profile, { pinnedAddress });
  } catch (error) {
    run.activeSecurity = {
      profile: profileMetadata,
      checks: [
        { id: 'object-authorization', title: 'Toegang tot het record van een andere gebruiker', status: 'not_tested',
          route: `GET ${profile.accounts.a.record.path}` },
        { id: 'logout-replay', title: 'Hergebruik van de sessie na uitloggen', status: 'not_tested',
          route: `POST ${profile.session.logoutPath}` },
      ],
    };
    throw new AgentError('active_security_unavailable', 'Het goedgekeurde testdoel of het bewijs van toestemming kon niet worden vastgesteld.', { cause: error });
  }
  report.profile = profileMetadata;
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
  const inconclusive = report.checks.some(check => check.status === 'inconclusive' || check.status === 'not_tested');
  run.coverage = inconclusive ? 'partial' : 'full';
  if (inconclusive) run.incompleteReason = 'Voor een of meer beveiligingscontroles ontbreekt beslissend browserbewijs.';
  run.summary = 'Autorisatie en sessie-intrekking zijn beoordeeld met de fictieve accounts van het goedgekeurde testprofiel.';

  const findings = report.checks.filter(check => check.status === 'confirmed');
  if (model && endpoint && findings.length) {
    try {
      const explanation = await requestModel({ model, endpoint, modelTimeoutMs: Math.min(modelTimeoutMs, 5000) }, [
        {
          role: 'system',
          content: 'Leg in het Nederlands uit wat het vastgelegde browserbewijs voor de testaccounts betekent. Gebruik hoogstens 120 woorden. Beperk je tot de aangeleverde waarnemingen en algemeen hersteladvies.',
        },
        { role: 'user', content: JSON.stringify(findings.map(({ id, observed }) => ({ id, observed }))) },
      ]);
      if (typeof explanation === 'string' && explanation.trim()) report.explanation = explanation.trim().slice(0, 1600);
    } catch {
      // The optional model response cannot change evidence or the run outcome.
    }
  }
}
