import assert from 'node:assert/strict';
import { test } from 'node:test';
import { redactReportValue } from '../report-privacy.mjs';

test('report serialization strips query strings, fragments and URL credentials in diagnostic text', () => {
  const report = {
    url: 'https://example.com/account?session=private-query#private-fragment',
    steps: [{
      diagnostic: 'Pagina https://alice:private-password@example.com/next?token=private-token gaf een fout.',
      screenshot: '/api/runs/run-id/1.png',
    }, { url: 'data:text/html,private-document' }],
  };
  const json = JSON.stringify(report, redactReportValue);
  assert.doesNotMatch(json, /private-|alice:/);
  assert.deepEqual(JSON.parse(json), {
    url: 'https://example.com/account',
    steps: [{
      diagnostic: 'Pagina https://example.com/next gaf een fout.',
      screenshot: '/api/runs/run-id/1.png',
    }, { url: '[browseradres afgeschermd]' }],
  });
});
