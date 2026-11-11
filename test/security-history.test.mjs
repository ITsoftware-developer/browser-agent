import assert from 'node:assert/strict';
import { test } from 'node:test';
import { compareSecurityRuns } from '../security-history.mjs';

function run(id, revision, access, logout) {
  return {
    id, revision,
    checks: [{ id: 'object-authorization', status: access }, { id: 'logout-replay', status: logout }],
  };
}

test('active comparisons use only the same profile revision and each control’s last decisive result', () => {
  const history = [
    run('other-scope', 'different', 'confirmed', 'confirmed'),
    run('partial', 'current', 'not_tested', 'confirmed'),
    run('baseline', 'current', 'confirmed', 'protected'),
  ];
  const current = { profile: { revision: 'current' }, checks: run('now', 'current', 'protected', 'inconclusive').checks };
  assert.deepEqual(compareSecurityRuns(current, history), {
    previousRunId: 'partial',
    checks: [
      { id: 'object-authorization', status: 'resolved', comparedWithRunId: 'baseline' },
      { id: 'logout-replay', status: 'not_tested', comparedWithRunId: 'partial' },
    ],
  });
  assert.deepEqual(compareSecurityRuns(current, history.slice(0, 1)), {
    previousRunId: null,
    checks: [
      { id: 'object-authorization', status: 'baseline', comparedWithRunId: null },
      { id: 'logout-replay', status: 'not_tested', comparedWithRunId: null },
    ],
  });
});
