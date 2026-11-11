const records = {
  alice: { id: 'alice-record', owner: 'alice', content: 'Synthetisch dossier van Alice.' },
  bob: { id: 'bob-record', owner: 'bob', content: 'Synthetisch dossier van Bob.' },
};

const sessionCookies = {
  '/vulnerable': 'security_lab_session',
  '/fixed': '__Secure-security_lab_session',
};

function loopbackUrl(input) {
  try {
    const url = new URL(input);
    if (url.protocol === 'http:' && url.hostname === '127.0.0.1' && url.port &&
        url.href === `${url.origin}${url.pathname}`) return url;
  } catch {
    // Invalid input has no eligible lab profile.
  }
  return null;
}

export function configuredLabOrigin(input) {
  const url = loopbackUrl(input);
  return url?.pathname === '/' ? url.origin : null;
}

export function labProfile(input) {
  const url = loopbackUrl(input);
  if (!url || !Object.hasOwn(sessionCookies, url.pathname)) return null;
  return { origin: url.origin, basePath: url.pathname, records, cookieName: sessionCookies[url.pathname] };
}
