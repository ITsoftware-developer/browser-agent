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
  const entryPath = url.pathname;
  const loginPath = `${entryPath}/session`;
  const logoutPath = `${entryPath}/logout`;
  function account(user, label) {
    const record = records[user];
    return {
      label,
      login: { path: loginPath, body: { user }, status: 201 },
      record: { path: `${entryPath}/records/${record.id}`, match: { ...record } },
    };
  }
  const accounts = { a: account('alice', 'Alice'), b: account('bob', 'Bob') };
  return {
    id: `lab-${entryPath.slice(1)}`,
    name: entryPath === '/fixed' ? 'Security Lab · Herstelde variant' : 'Security Lab · Kwetsbare variant',
    origin: url.origin,
    entryPath,
    approval: {
      reference: 'Ingebouwd lokaal Security Lab',
      expiresAt: null,
      proof: { path: entryPath, kind: 'header', header: 'x-browser-agent-security-lab', value: '1' },
    },
    accounts,
    session: { cookieName: sessionCookies[entryPath], logoutPath, logoutStatus: 204, anonymousStatus: 401 },
    authorization: { deniedStatus: 403 },
    allowedRequests: [
      { method: 'GET', path: entryPath },
      { method: 'POST', path: loginPath },
      { method: 'GET', path: accounts.a.record.path },
      { method: 'GET', path: accounts.b.record.path },
      { method: 'POST', path: logoutPath },
    ],
  };
}
