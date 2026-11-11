import { readdir, readFile } from 'node:fs/promises';

const runDirectory = /^[a-f0-9-]{36}$/;
const determinate = new Set(['confirmed', 'protected']);

async function readStoredRun(root, id, owner, profileId) {
  const directory = new URL(`${id}/`, root);
  try {
    if (await readFile(new URL('owner', directory), 'utf8') !== owner) return null;
    const report = JSON.parse(await readFile(new URL('report.json', directory), 'utf8'));
    const security = report.activeSecurity;
    if (security?.profile?.id !== profileId || !report.finishedAt || !Array.isArray(security.checks)) return null;
    return {
      id,
      finishedAt: report.finishedAt,
      status: report.status,
      revision: security.profile.revision,
      checks: security.checks.map(({ id, title, status }) => ({ id, title, status })),
      comparison: security.comparison,
    };
  } catch (error) {
    if (error.code === 'ENOENT' || error instanceof SyntaxError) return null;
    throw error;
  }
}

export async function readSecurityHistory(root, owner, profileId) {
  let entries;
  try {
    entries = await readdir(root, { withFileTypes: true });
  } catch (error) {
    if (error.code === 'ENOENT') return [];
    throw error;
  }
  const ids = entries.filter(entry => entry.isDirectory() && runDirectory.test(entry.name)).map(entry => entry.name);
  const runs = [];
  for (let index = 0; index < ids.length; index += 24) {
    const group = await Promise.all(ids.slice(index, index + 24).map(id => readStoredRun(root, id, owner, profileId)));
    runs.push(...group.filter(Boolean));
  }
  return runs.sort((first, second) => second.finishedAt.localeCompare(first.finishedAt));
}

export function compareSecurityRuns(current, history) {
  const comparable = history.filter(run => run.revision === current.profile.revision);
  const ids = new Set([...current.checks, ...(comparable[0]?.checks ?? [])].map(check => check.id));
  const checks = [...ids].map(id => {
    const currentStatus = current.checks.find(check => check.id === id)?.status;
    const previous = comparable.flatMap(run => run.checks
      .filter(check => check.id === id && determinate.has(check.status))
      .map(check => ({ status: check.status, runId: run.id })));
    let status = 'unchanged';
    if (!determinate.has(currentStatus)) status = 'not_tested';
    else if (currentStatus === 'protected' && previous[0]?.status === 'confirmed') status = 'resolved';
    else if (currentStatus === 'protected' && !previous.length) status = 'baseline';
    else if (currentStatus === 'confirmed' && previous[0]?.status !== 'confirmed') {
      status = previous.some(check => check.status === 'confirmed') ? 'reappeared' : 'new';
    }
    return { id, status, comparedWithRunId: previous[0]?.runId ?? null };
  });
  return { previousRunId: comparable[0]?.id ?? null, checks };
}
