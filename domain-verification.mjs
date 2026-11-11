import { randomBytes } from 'node:crypto';
import { Resolver } from 'node:dns/promises';
import { isIP } from 'node:net';
import { isPublicUrl } from './public-network.mjs';

const challengeLifetime = 15 * 60 * 1000;
const verificationLifetime = 24 * 60 * 60 * 1000;
const maxClaimsPerOwner = 16;
const maxClaims = 1024;
const recordPrefix = '_browser-agent.';
const nonPublicSuffixes = new Set(['arpa', 'example', 'internal', 'invalid', 'onion', 'test']);

function verificationError(status, message) {
  return Object.assign(new Error(message), { status });
}

function parseOrigin(input) {
  if (!isPublicUrl(input)) {
    throw verificationError(400, 'Voer een geldige publieke domein-URL met HTTP of HTTPS in.');
  }
  const url = new URL(input);
  const hostname = url.hostname.replace(/\.$/, '');
  const labels = hostname.split('.');
  if (isIP(hostname.replace(/^\[|\]$/g, '')) || hostname.length + recordPrefix.length > 253 ||
    labels.length < 2 || nonPublicSuffixes.has(labels.at(-1)) ||
    labels.some(label => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) {
    throw verificationError(400, 'Gebruik een publieke domeinnaam voor DNS-verificatie.');
  }
  return { origin: url.origin, name: `${recordPrefix}${hostname}` };
}

function validateOwner(owner) {
  if (typeof owner !== 'string' || !owner || owner.length > 256) {
    throw verificationError(400, 'De verificatie-eigenaar ontbreekt.');
  }
}

async function resolveDomainTxt(name) {
  const resolver = new Resolver({ timeout: 2500, tries: 1 });
  const deadline = setTimeout(() => resolver.cancel(), 4000);
  deadline.unref();
  try {
    return await resolver.resolveTxt(`${name}.`);
  } finally {
    clearTimeout(deadline);
  }
}

export function createDomainVerification({ resolveTxt = resolveDomainTxt, now = Date.now } = {}) {
  const claims = new Map();

  function expireClaims(time) {
    for (const [key, claim] of claims) {
      if (claim.challenge?.expires <= time) claim.challenge = undefined;
      if (!claim.challenge && claim.verifiedUntil <= time) claims.delete(key);
    }
  }

  function challenge(owner, url) {
    validateOwner(owner);
    const { origin, name } = parseOrigin(url);
    const time = now();
    expireClaims(time);
    const key = JSON.stringify([owner, origin]);
    let claim = claims.get(key);
    if (!claim) {
      const ownerClaims = [...claims.values()].filter(claim => claim.owner === owner).length;
      if (claims.size >= maxClaims || ownerClaims >= maxClaimsPerOwner) {
        throw verificationError(429, 'Er zijn te veel actieve domeinverificaties. Probeer het later opnieuw.');
      }
      claim = { owner, origin, verifiedUntil: 0 };
      claims.set(key, claim);
    }
    claim.challenge ??= { value: `browser-agent=${randomBytes(24).toString('hex')}`, expires: time + challengeLifetime };
    return { origin, name, value: claim.challenge.value, expiresAt: new Date(claim.challenge.expires).toISOString() };
  }

  async function verify(owner, url) {
    validateOwner(owner);
    const { origin, name } = parseOrigin(url);
    expireClaims(now());
    const key = JSON.stringify([owner, origin]);
    const claim = claims.get(key);
    const active = claim?.challenge;
    if (!active) throw verificationError(409, 'Vraag eerst een nieuwe DNS-verificatiecode aan.');
    if (active.pending) throw verificationError(409, 'De DNS-verificatie is al bezig.');

    active.pending = true;
    let records;
    try {
      records = await resolveTxt(name);
    } catch {
      throw verificationError(409, 'Het TXT-record kon nog niet worden opgehaald. Probeer het opnieuw.');
    } finally {
      active.pending = false;
    }
    const time = now();
    expireClaims(time);
    if (claims.get(key)?.challenge !== active) {
      throw verificationError(409, 'De DNS-verificatiecode is verlopen. Vraag een nieuwe code aan.');
    }
    if (!Array.isArray(records) || !records.some(parts => Array.isArray(parts) &&
      parts.every(part => typeof part === 'string') && parts.join('') === active.value)) {
      throw verificationError(409, 'Het TXT-record bevat nog geen geldige DNS-verificatiecode.');
    }
    claim.challenge = undefined;
    claim.verifiedUntil = time + verificationLifetime;
    return { origin, verifiedUntil: new Date(claim.verifiedUntil).toISOString() };
  }

  function verifiedOrigins(owner) {
    validateOwner(owner);
    const time = now();
    expireClaims(time);
    return [...claims.values()]
      .filter(claim => claim.owner === owner && claim.verifiedUntil > time)
      .map(claim => claim.origin);
  }

  return { challenge, verify, verifiedOrigins };
}
