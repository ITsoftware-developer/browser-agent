import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { isIP } from 'node:net';
import { isPublicUrl } from './public-network.mjs';

const maxProfiles = 32;
const maxFileBytes = 256 * 1024;
const maxJsonBytes = 4096;
const nonPublicSuffixes = new Set(['arpa', 'example', 'internal', 'invalid', 'onion', 'test']);
const refusedStatuses = new Set([401, 403, 404]);

function invalid(field) {
  throw new Error('Ongeldig beveiligingsprofiel. Controleer ' + field + '.');
}

function isObject(value) {
  return value !== null && typeof value === 'object' && Object.getPrototypeOf(value) === Object.prototype;
}

function checkShape(value, keys, field) {
  if (!isObject(value) || Object.keys(value).some(key => !keys.includes(key))) invalid(field);
}

function text(value, limit, field) {
  if (typeof value !== 'string' || value.length > limit || !value.trim() || /[\x00-\x1f\x7f]/.test(value)) {
    invalid(field);
  }
  return value.trim();
}

function originOf(value) {
  if (typeof value !== 'string' || value.length > 512 || !/^https?:\/\/[^/?#\\\s]+\/?$/i.test(value) ||
      /[\x00-\x20\x7f]/.test(value)) {
    invalid('origin');
  }
  let url;
  try {
    url = new URL(value);
  } catch {
    invalid('origin');
  }
  if (url.username || url.password || value.includes('@') || value.includes('%') || url.port === '0') invalid('origin');
  if (url.protocol === 'http:' && /^http:\/\/127\.0\.0\.1:[1-9]\d{0,4}\/?$/.test(value) && url.port) {
    return url.origin;
  }
  const labels = url.hostname.split('.');
  if (url.protocol !== 'https:' || !isPublicUrl(url) || isIP(url.hostname) || url.hostname.length > 253 ||
      labels.length < 2 || nonPublicSuffixes.has(labels.at(-1)) ||
      labels.some(label => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) invalid('origin');
  return url.origin;
}

function exactPath(value, field) {
  if (typeof value !== 'string' || value.length > 512 || !/^\/[A-Za-z0-9._~!$&'()+,=:@/-]*$/.test(value) ||
      value.includes('//') || value.split('/').some(segment => segment === '.' || segment === '..')) invalid(field);
  return value;
}

function isoExpiry(value) {
  const match = typeof value === 'string'
    ? /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.\d{1,3})?(?:Z|[+-]\d{2}:\d{2})$/.exec(value)
    : null;
  if (!match) invalid('approval.expiresAt');
  const date = new Date(value);
  const localDate = new Date(match[1] + 'Z');
  if (!Number.isFinite(date.getTime()) || !Number.isFinite(localDate.getTime()) ||
      localDate.toISOString().slice(0, 19) !== match[1]) invalid('approval.expiresAt');
  return date.toISOString();
}

function successfulStatus(value, field) {
  if (!Number.isInteger(value) || value < 200 || value > 299) invalid(field);
  return value;
}

function refusedStatus(value, field) {
  if (!refusedStatuses.has(value)) invalid(field);
  return value;
}

function boundedJsonObject(value, field) {
  if (!isObject(value) || !Object.keys(value).length) invalid(field);
  let entries = 0;
  function visit(part, depth) {
    entries++;
    if (entries > 128 || depth > 8) invalid(field);
    if (Array.isArray(part)) {
      for (const item of part) visit(item, depth + 1);
    } else if (isObject(part)) {
      for (const item of Object.values(part)) visit(item, depth + 1);
    } else if (part !== null && typeof part !== 'boolean' && typeof part !== 'string' && !Number.isFinite(part)) {
      invalid(field);
    }
    if (typeof part === 'string' && Buffer.byteLength(part) > maxJsonBytes) invalid(field);
  }
  visit(value, 0);
  if (Buffer.byteLength(JSON.stringify(value)) > maxJsonBytes) invalid(field);
  return value;
}

function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (isObject(value)) {
    return Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])]));
  }
  return value;
}

function matchesCanOverlap(left, right) {
  if (isObject(left) && isObject(right)) {
    return Object.keys(left).every(key => !Object.hasOwn(right, key) || matchesCanOverlap(left[key], right[key]));
  }
  if (Array.isArray(left) && Array.isArray(right)) {
    return left.length === right.length && left.every((item, index) => matchesCanOverlap(item, right[index]));
  }
  return left === right;
}

function approvalOf(approval) {
  checkShape(approval, ['reference', 'expiresAt', 'proof'], 'approval');
  const { proof } = approval;
  checkShape(proof, ['kind', 'path', 'value'], 'approval.proof');
  if (proof.kind !== undefined && proof.kind !== 'body') invalid('approval.proof.kind');
  if (typeof proof.value !== 'string' || !/^[A-Za-z0-9._~+=/-]{24,256}$/.test(proof.value)) invalid('approval.proof.value');
  return {
    reference: text(approval.reference, 200, 'approval.reference'),
    expiresAt: isoExpiry(approval.expiresAt),
    proof: { kind: 'body', path: exactPath(proof.path, 'approval.proof.path'), value: proof.value },
  };
}

function loginBodyOf(login, field) {
  if (login.bodyEnv === undefined) return { body: boundedJsonObject(login.body, field + '.body') };

  const body = login.body === undefined ? {} : login.body;
  if (!isObject(body)) invalid(field + '.body');
  if (!isObject(login.bodyEnv)) invalid(field + '.bodyEnv');
  const references = Object.entries(login.bodyEnv);
  if (!references.length || references.length > 128) invalid(field + '.bodyEnv');
  const emptyFields = references.map(([key, variable]) => {
    if (Object.hasOwn(body, key) || typeof variable !== 'string' || !/^[A-Z_][A-Z0-9_]{0,127}$/.test(variable)) {
      invalid(field + '.bodyEnv');
    }
    return [key, ''];
  });
  boundedJsonObject({ ...body, ...Object.fromEntries(emptyFields) }, field + '.body');
  return { body, bodyEnv: { ...login.bodyEnv } };
}

function accountOf(account, field) {
  checkShape(account, ['label', 'login', 'record'], field);
  checkShape(account.login, ['path', 'body', 'bodyEnv', 'status'], field + '.login');
  checkShape(account.record, ['path', 'match'], field + '.record');
  return {
    label: text(account.label, 80, field + '.label'),
    login: {
      path: exactPath(account.login.path, field + '.login.path'),
      ...loginBodyOf(account.login, field + '.login'),
      status: successfulStatus(account.login.status, field + '.login.status'),
    },
    record: {
      path: exactPath(account.record.path, field + '.record.path'),
      match: boundedJsonObject(account.record.match, field + '.record.match'),
    },
  };
}

function sessionOf(session) {
  checkShape(session, ['cookieName', 'logoutPath', 'logoutStatus', 'anonymousStatus'], 'session');
  if (typeof session.cookieName !== 'string' || !/^[!#$%&'*+.^_\x60|~0-9A-Za-z-]{1,128}$/.test(session.cookieName)) {
    invalid('session.cookieName');
  }
  return {
    cookieName: session.cookieName,
    logoutPath: exactPath(session.logoutPath, 'session.logoutPath'),
    logoutStatus: successfulStatus(session.logoutStatus, 'session.logoutStatus'),
    anonymousStatus: refusedStatus(session.anonymousStatus, 'session.anonymousStatus'),
  };
}

function requestsOf(allowedRequests, proof, accounts, session) {
  const expected = new Set([
    'GET ' + proof.path,
    'GET ' + accounts.a.record.path,
    'GET ' + accounts.b.record.path,
    'POST ' + accounts.a.login.path,
    'POST ' + accounts.b.login.path,
    'POST ' + session.logoutPath,
  ]);
  if (!Array.isArray(allowedRequests) || allowedRequests.length !== expected.size) invalid('allowedRequests');
  return allowedRequests.map(request => {
    checkShape(request, ['method', 'path'], 'allowedRequests');
    if (request.method !== 'GET' && request.method !== 'POST') invalid('allowedRequests.method');
    const path = exactPath(request.path, 'allowedRequests.path');
    if (!expected.delete(request.method + ' ' + path)) invalid('allowedRequests');
    return { method: request.method, path };
  });
}

function validateDistinctCredentials(accounts) {
  if (JSON.stringify(canonical(accounts.a.login.body)) === JSON.stringify(canonical(accounts.b.login.body))) {
    invalid('de afzonderlijke inloggegevens');
  }
}

function validateProfile(profile) {
  checkShape(profile, ['id', 'name', 'origin', 'entryPath', 'approval', 'accounts', 'session', 'authorization', 'allowedRequests'],
    'de profielvelden');
  const id = text(profile.id, 64, 'id');
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(id)) invalid('id');
  const approval = approvalOf(profile.approval);
  checkShape(profile.accounts, ['a', 'b'], 'accounts');
  const accounts = {
    a: accountOf(profile.accounts.a, 'accounts.a'),
    b: accountOf(profile.accounts.b, 'accounts.b'),
  };
  if (!accounts.a.login.bodyEnv && !accounts.b.login.bodyEnv) validateDistinctCredentials(accounts);
  if (accounts.a.record.path === accounts.b.record.path || matchesCanOverlap(accounts.a.record.match, accounts.b.record.match)) {
    invalid('de afzonderlijke recordpaden en onderscheidende recordgegevens');
  }
  const session = sessionOf(profile.session);
  if ([accounts.a.record.path, accounts.b.record.path].includes(approval.proof.path)) invalid('approval.proof.path');
  if ([accounts.a.login.path, accounts.b.login.path].includes(session.logoutPath)) invalid('session.logoutPath');
  checkShape(profile.authorization, ['deniedStatus'], 'authorization');
  return {
    id,
    name: text(profile.name, 120, 'name'),
    origin: originOf(profile.origin),
    entryPath: exactPath(profile.entryPath, 'entryPath'),
    approval,
    accounts,
    session,
    authorization: { deniedStatus: refusedStatus(profile.authorization.deniedStatus, 'authorization.deniedStatus') },
    allowedRequests: requestsOf(profile.allowedRequests, approval.proof, accounts, session),
  };
}

export function validateSecurityProfiles(value) {
  if (!Array.isArray(value) || value.length > maxProfiles) invalid('de lijst met profielen');
  const ids = new Set(['lab-vulnerable', 'lab-fixed']);
  const targets = new Set();
  return value.map(input => {
    const profile = validateProfile(input);
    const { id, url } = profileSummary(profile);
    if (ids.has(id)) invalid('de unieke profiel-ID’s');
    if (targets.has(url)) invalid('de unieke profiel-URL’s');
    ids.add(id);
    targets.add(url);
    return profile;
  });
}

export async function loadSecurityProfiles(file) {
  if (file === undefined || file === '') return [];
  let input;
  try {
    const bytes = await readFile(file);
    if (bytes.length > maxFileBytes) throw new Error('Bestand te groot.');
    input = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  } catch {
    throw new Error('Het bestand met beveiligingsprofielen moet geldige, begrensde UTF-8 JSON bevatten.');
  }
  return validateSecurityProfiles(input);
}

function resolveAccountCredentials(account, field, env) {
  const { bodyEnv, ...login } = account.login;
  if (!bodyEnv) return account;
  const credentials = Object.entries(bodyEnv).map(([key, variable]) => {
    const value = Object.hasOwn(env, variable) ? env[variable] : undefined;
    if (typeof value !== 'string' || !value.length || Buffer.byteLength(value) > maxJsonBytes) {
      invalid(field + '.login.bodyEnv');
    }
    return [key, value];
  });
  const body = boundedJsonObject({ ...login.body, ...Object.fromEntries(credentials) }, field + '.login.body');
  return { ...account, login: { ...login, body } };
}

export function resolveSecurityProfileCredentials(profile, env = process.env) {
  const { a, b } = profile.accounts;
  if (!a.login.bodyEnv && !b.login.bodyEnv) return profile;
  const accounts = {
    a: resolveAccountCredentials(a, 'accounts.a', env),
    b: resolveAccountCredentials(b, 'accounts.b', env),
  };
  validateDistinctCredentials(accounts);
  return { ...profile, accounts };
}

export function profileSummary({ id, name, origin, entryPath }) {
  return { id, name, url: origin + entryPath };
}

export function profileRevision(profile) {
  const { origin, entryPath, approval, accounts, session, authorization, allowedRequests } = profile;
  const account = ({ login, record }) => ({ login: { path: login.path, status: login.status }, record });
  const behavior = {
    probeEvidenceVersion: 2,
    origin,
    entryPath,
    approvalProof: { kind: approval.proof.kind, path: approval.proof.path },
    accounts: { a: account(accounts.a), b: account(accounts.b) },
    session,
    authorization,
    allowedRequests: allowedRequests.map(({ method, path }) => method + ' ' + path).sort(),
  };
  return createHash('sha256').update(JSON.stringify(canonical(behavior))).digest('hex');
}
