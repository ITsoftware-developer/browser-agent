import { randomBytes } from 'node:crypto';
import { once } from 'node:events';
import { createServer } from 'node:http';
import { pathToFileURL } from 'node:url';

const bindHost = '127.0.0.1';
const sessionLifetimeMs = 15 * 60 * 1000;
const maxSessionsPerVariant = 256;
const maxBodyBytes = 1024;
const demoCookieValue = 'demo-sample';
const variants = {
  vulnerable: { title: 'Kwetsbare variant', cookie: 'security_lab_session', fixed: false },
  fixed: { title: 'Herstelde variant', cookie: '__Secure-security_lab_session', fixed: true },
};
const records = {
  'alice-record': { id: 'alice-record', owner: 'alice', content: 'Synthetisch dossier van Alice.' },
  'bob-record': { id: 'bob-record', owner: 'bob', content: 'Synthetisch dossier van Bob.' },
};

const policy = [
  "default-src 'none'", "style-src 'self'", "base-uri 'none'", "object-src 'none'",
  "frame-ancestors 'none'", "form-action 'self'",
].join('; ');

const stylesheet = `
  :root { font-family: system-ui, sans-serif; color: #ecf0f6; background: #141c27; color-scheme: dark; }
  body { margin: 0; }
  header { border-bottom: 1px solid #394759; }
  header, main { padding: 1.25rem max(1.25rem, calc((100vw - 880px) / 2)); }
  main { padding-top: 3rem; }
  h1 { font-size: clamp(2rem, 5vw, 3.4rem); letter-spacing: -.04em; margin: 0 0 1rem; }
  h2 { font-size: 1.15rem; margin: 0 0 .55rem; }
  p { color: #c6d2e2; line-height: 1.65; margin: 0 0 1rem; }
  a { color: #9cf1d1; }
  nav { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-top: 1.75rem; }
  section, .variant { border: 1px solid #43536a; border-radius: 12px; background: #1b2939; padding: 1.25rem; }
  section { margin-top: 1.75rem; }
  .variant p, section p:last-child { margin-bottom: 0; }
  code { color: #e0e8f4; overflow-wrap: anywhere; }
`;

function page(variant) {
  const details = variant ? variants[variant] : undefined;
  const title = details?.title ?? 'Security Lab';
  const content = details ? `
    <p>${details.fixed
      ? 'In deze variant controleert de server de eigenaar van het dossier en beëindigt uitloggen de sessie op de server.'
      : 'In deze variant kan een aangemelde gebruiker het dossier van iemand anders lezen en blijft de sessie na uitloggen bruikbaar.'}</p>
    <section>
      <h2>Lokale test-API</h2>
      <p><code>POST /${variant}/session</code> · Maak een sessie met <code>{"user":"alice"}</code> of <code>{"user":"bob"}</code>.</p>
      <p><code>GET /${variant}/records/alice-record</code> · Lees het dossier met de sessiecookie.</p>
      <p><code>POST /${variant}/logout</code> · Log uit met dezelfde cookie en controleer of de oude sessie nog werkt.</p>
    </section>
    <nav aria-label="Varianten">
      <a href="/vulnerable">Kwetsbare variant</a>
      <a href="/fixed">Herstelde variant</a>
    </nav>` : `
    <p>Vergelijk twee uitvoeringen van een lokale testsite met fictieve accounts en dossiers.</p>
    <nav aria-label="Varianten">
      <div class="variant"><h2><a href="/vulnerable">Kwetsbare variant</a></h2><p>Met de ingebouwde fouten in toegang en sessieafhandeling.</p></div>
      <div class="variant"><h2><a href="/fixed">Herstelde variant</a></h2><p>Met eigenaarscontrole, sessie-intrekking en aanvullende browserheaders.</p></div>
    </nav>`;
  return `<!doctype html>
<html lang="nl">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${title}</title>
  <link rel="stylesheet" href="/style.css">
</head>
<body>
  <header><a href="/">Security Lab</a></header>
  <main><h1>${title}</h1>${content}</main>
</body>
</html>`;
}

function json(response, status, payload) {
  response.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
  response.end(JSON.stringify(payload));
}

function onlyMethod(request, response, method) {
  if (request.method === method) return true;
  response.setHeader('Allow', method);
  json(response, 405, { error: 'Deze methode is hier niet toegestaan.' });
  return false;
}

function cookieValue(request, variant) {
  const name = `${variants[variant].cookie}=`;
  const pair = request.headers.cookie?.split(';').map(item => item.trim()).find(item => item.startsWith(name));
  return pair?.slice(name.length);
}

function sessionCookie(variant, token, maxAge) {
  const { cookie, fixed } = variants[variant];
  return `${cookie}=${token}; Path=/${variant}; Max-Age=${maxAge}${fixed ? '; Secure; HttpOnly; SameSite=Lax' : ''}`;
}

function setFixedHeaders(response) {
  response.setHeader('Content-Security-Policy', policy);
  response.setHeader('X-Content-Type-Options', 'nosniff');
}

function pruneSessions(sessions) {
  const now = Date.now();
  for (const [token, session] of sessions) {
    if (session.expiresAt <= now) sessions.delete(token);
  }
}

async function readUser(request, response) {
  const contentType = request.headers['content-type']?.split(';', 1)[0].trim().toLowerCase();
  if (contentType !== 'application/json') {
    json(response, 415, { error: 'Stuur een JSON-aanvraag.' });
    request.resume();
    return;
  }
  const chunks = [];
  let length = 0;
  for await (const chunk of request.iterator({ destroyOnReturn: false })) {
    length += chunk.length;
    if (length > maxBodyBytes) {
      json(response, 413, { error: 'De aanvraag is te groot.' });
      request.resume();
      return;
    }
    chunks.push(chunk);
  }
  let body;
  try {
    body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch {
    json(response, 400, { error: 'Ongeldige JSON-aanvraag.' });
    return;
  }
  if (body?.user !== 'alice' && body?.user !== 'bob') {
    json(response, 400, { error: 'Kies het fictieve account alice of bob.' });
    return;
  }
  return body.user;
}

export async function startSecurityLab({ port = 0 } = {}) {
  const sessions = { vulnerable: new Map(), fixed: new Map() };
  let origin;
  let authority;
  const server = createServer({
    requestTimeout: 5000, headersTimeout: 5000, connectionsCheckingInterval: 1000,
  }, async (request, response) => {
    response.setHeader('Cache-Control', 'no-store');
    try {
      if (request.headers.host !== authority ||
        (request.method === 'POST' && request.headers.origin && request.headers.origin !== origin)) {
        return json(response, 403, { error: 'Gebruik het loopbackadres van het lab.' });
      }
      const target = new URL(request.url, origin);
      if (target.origin !== origin) return json(response, 403, { error: 'Gebruik het loopbackadres van het lab.' });
      const path = target.pathname;
      if (path === '/' || path === '/style.css' || path === '/favicon.ico') {
        if (!onlyMethod(request, response, 'GET')) return;
        if (path === '/favicon.ico') return response.writeHead(204).end();
        setFixedHeaders(response);
        const css = path === '/style.css';
        response.writeHead(200, { 'Content-Type': css ? 'text/css; charset=utf-8' : 'text/html; charset=utf-8' });
        return response.end(css ? stylesheet : page());
      }
      const match = /^\/(vulnerable|fixed)(?:\/(session|logout|records\/(alice-record|bob-record)))?$/.exec(path);
      if (!match) return json(response, 404, { error: 'Labroute niet gevonden.' });
      const [, variant, action, recordId] = match;
      const { fixed } = variants[variant];
      if (fixed) setFixedHeaders(response);
      const variantSessions = sessions[variant];
      pruneSessions(variantSessions);
      const token = cookieValue(request, variant);
      const session = variantSessions.get(token);

      if (!action) {
        if (!onlyMethod(request, response, 'GET')) return;
        response.setHeader('X-Browser-Agent-Security-Lab', '1');
        if (!session) response.setHeader('Set-Cookie', sessionCookie(variant, demoCookieValue, sessionLifetimeMs / 1000));
        response.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        return response.end(page(variant));
      }
      if (action === 'session') {
        if (!onlyMethod(request, response, 'POST')) return;
        const user = await readUser(request, response);
        if (!user) return;
        if (variantSessions.size >= maxSessionsPerVariant) {
          return json(response, 429, { error: 'Er zijn te veel actieve labsessies.' });
        }
        const newToken = randomBytes(24).toString('hex');
        variantSessions.set(newToken, { user, expiresAt: Date.now() + sessionLifetimeMs });
        response.setHeader('Set-Cookie', sessionCookie(variant, newToken, sessionLifetimeMs / 1000));
        return json(response, 201, { user });
      }
      if (action === 'logout') {
        if (!onlyMethod(request, response, 'POST')) return;
        if (fixed) variantSessions.delete(token);
        response.setHeader('Set-Cookie', sessionCookie(variant, '', 0));
        return response.writeHead(204).end();
      }
      if (!onlyMethod(request, response, 'GET')) return;
      if (!session) return json(response, 401, { error: 'Maak eerst een fictieve labsessie aan.' });
      const record = records[recordId];
      if (fixed && record.owner !== session.user) return json(response, 403, { error: 'Dit dossier hoort bij een ander account.' });
      return json(response, 200, record);
    } catch {
      if (response.headersSent) return response.destroy();
      json(response, 500, { error: 'De labaanvraag kon niet worden verwerkt.' });
    }
  });
  server.listen(port, bindHost);
  await once(server, 'listening');
  authority = `${bindHost}:${server.address().port}`;
  origin = `http://${authority}`;
  let closing;
  return {
    origin,
    close() {
      closing ??= new Promise((resolve, reject) => {
        server.close(error => error ? reject(error) : resolve());
        server.closeAllConnections();
      });
      return closing;
    },
  };
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  const { origin } = await startSecurityLab({ port: Number(process.env.SECURITY_LAB_PORT ?? 4327) });
  console.log(`Security Lab draait op ${origin}`);
}
