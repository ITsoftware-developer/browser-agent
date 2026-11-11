const asvsRoot = 'https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/';
const frontend = `${asvsRoot}0x12-V3-Web-Frontend-Security.md`;
const transport = `${asvsRoot}0x21-V12-Secure-Communication.md`;
const cookieSection = `${frontend}#v33-cookie-setup`;
const headerSection = `${frontend}#v34-browser-security-mechanism-headers`;
const cookieApplicability = 'ASVS V3.3 richt zich op gevoelige cookies. De functie van de ontvangen cookies vraagt beoordeling in de applicatiecontext.';

const controls = {
  https: ['HTTPS op de documentrespons', '12.2.1', `${transport}#v122-https-communication-with-external-facing-services`],
  hsts: ['Strict-Transport-Security', '3.4.1', headerSection],
  csp: ['Content-Security-Policy', '3.4.3', headerSection],
  nosniff: ['X-Content-Type-Options', '3.4.4', headerSection],
  'cookie-secure': ['Cookie-instellingen voor Secure', '3.3.1', cookieSection, cookieApplicability],
  'cookie-prefix': ['Beveiligde naam-prefix voor cookies', '3.3.1', cookieSection, cookieApplicability],
  'cookie-samesite': ['Cookie-instellingen voor SameSite', '3.3.2', cookieSection],
  'cookie-httponly': ['Cookie-instellingen voor HttpOnly', '3.3.4', cookieSection],
  banner: ['Software-informatie in responseheaders'],
};

function summarizeCookie(header) {
  if (typeof header !== 'string') return null;
  const [assignment, ...parts] = header.split(';');
  const separator = assignment.indexOf('=');
  if (separator < 1) return null;
  const name = assignment.slice(0, separator).trim();
  if (!name) return null;
  const attributes = new Map(parts.map(part => {
    const [key, ...value] = part.split('=');
    return [key.trim().toLowerCase(), value.join('=').trim().toLowerCase()];
  }));
  const sameSite = attributes.get('samesite');
  return {
    secure: attributes.has('secure'),
    httpOnly: attributes.has('httponly'),
    securePrefix: name.startsWith('__Secure-') || name.startsWith('__Host-'),
    sameSite: ['strict', 'lax', 'none'].includes(sameSite) ? sameSite : null,
  };
}

export function observeSecurityResponse({ url, status, headers = {}, setCookies = [] }) {
  const address = new URL(url);
  const hsts = headers['strict-transport-security']?.trim() ?? '';
  const maxAges = hsts.split(';').filter(directive => /^\s*max-age\s*(?:=|$)/i.test(directive));
  const maxAgeMatch = maxAges.length === 1
    ? /^\s*max-age\s*=\s*(?:"(\d+)"|(\d+))\s*$/i.exec(maxAges[0])
    : null;
  const maxAge = maxAgeMatch ? Number(maxAgeMatch[1] ?? maxAgeMatch[2]) : null;
  return {
    url: `${address.origin}${address.pathname}`,
    https: address.protocol === 'https:',
    httpStatus: status,
    hstsPresent: Boolean(hsts),
    hstsMaxAge: Number.isSafeInteger(maxAge) ? maxAge : null,
    html: /^(text\/html|application\/xhtml\+xml)\s*(?:;|$)/i.test(headers['content-type'] ?? ''),
    csp: Boolean(headers['content-security-policy']?.trim()),
    reportOnlyCsp: Boolean(headers['content-security-policy-report-only']?.trim()),
    nosniff: headers['x-content-type-options']?.trim().toLowerCase() === 'nosniff',
    contentTypeOptionsPresent: Boolean(headers['x-content-type-options']?.trim()),
    cookies: setCookies.map(summarizeCookie).filter(Boolean),
    poweredBy: Boolean(headers['x-powered-by']?.trim()),
    serverVersion: /\b\d+\.\d+\b/.test(headers.server ?? ''),
  };
}

function check(id, status, evidence, advice, severity = 'info') {
  const [title, requirement, url, applicability] = controls[id];
  return {
    id, title, status, severity, evidence, advice,
    asvs: requirement ? [{ id: `v5.0.0-${requirement}`, url, ...(applicability ? { applicability } : {}) }] : [],
  };
}

function cookieChecks(cookies) {
  if (!cookies.length) {
    return ['cookie-secure', 'cookie-prefix', 'cookie-samesite', 'cookie-httponly'].map(id =>
      check(id, 'not_observed', 'Deze documentrespons bevatte geen leesbare Set-Cookie-headers.'));
  }
  const secureGaps = cookies.filter(cookie => !cookie.secure).length;
  const prefixGaps = cookies.filter(cookie => !cookie.securePrefix).length;
  const sameSiteGaps = cookies.filter(cookie => !cookie.sameSite || (cookie.sameSite === 'none' && !cookie.secure)).length;
  const httpOnlyGaps = cookies.filter(cookie => !cookie.httpOnly).length;
  return [
    secureGaps
      ? check('cookie-secure', 'review', `${secureGaps} van ${cookies.length} ontvangen cookies missen het Secure-attribuut.`,
        'Controleer welke cookies gevoelige gegevens bevatten en zet voor die cookies het Secure-attribuut.', 'low')
      : check('cookie-secure', 'observed', `Het Secure-attribuut is aanwezig bij alle ${cookies.length} ontvangen cookies.`),
    prefixGaps
      ? check('cookie-prefix', 'recommendation', `Bij ${prefixGaps} van ${cookies.length} ontvangen cookies ontbreekt een __Host- of __Secure-naam-prefix.`,
        'Beoordeel voor gevoelige cookies welke beveiligde naam-prefix bij het gebruik past.')
      : check('cookie-prefix', 'observed', `Een __Host- of __Secure-naam-prefix is aanwezig bij alle ${cookies.length} ontvangen cookies.`),
    sameSiteGaps
      ? check('cookie-samesite', 'review', `${sameSiteGaps} van ${cookies.length} cookies missen een geldige SameSite-instelling of combineren None met ontbrekend Secure.`,
        'Kies SameSite passend bij het gebruik van de cookie. Combineer None met Secure.', 'low')
      : check('cookie-samesite', 'observed', `Een SameSite-waarde waargenomen bij alle ${cookies.length} ontvangen cookies. Beoordeel de waarde per toepassing.`),
    httpOnlyGaps
      ? check('cookie-httponly', 'review', `${httpOnlyGaps} van ${cookies.length} cookies missen HttpOnly. Het doel van de cookies is onbekend.`,
        'Gebruik HttpOnly voor sessie- en authenticatiewaarden die JavaScript niet hoeft te lezen.', 'low')
      : check('cookie-httponly', 'observed', `HttpOnly waargenomen bij alle ${cookies.length} ontvangen cookies.`),
  ];
}

export function buildSecurityReport(observation, evidenceStepId) {
  const scope = {
    sample: observation
      ? 'Eén definitieve documentrespons. De resultaten beschrijven aangetroffen headerwaarden en cookie-attributen.'
      : 'Er is geen definitieve documentrespons vastgelegd.',
    untested: [
      'Andere pagina’s, redirects en subresources',
      'Effectiviteit van browserbeleid zoals CSP en HSTS, en TLS-configuratie',
      'Authenticatie, sessiebeheer en toegangscontrole',
      'Actieve kwetsbaarheidstests zoals XSS, SQL-injectie en CSRF',
    ],
  };
  const report = { mode: 'passive', standard: 'OWASP ASVS 5.0.0', scope, document: null, checks: [] };
  if (!observation) {
    report.checks = Object.keys(controls).map(id =>
      check(id, 'not_observed', 'Er is geen definitieve documentrespons vastgelegd.'));
    return report;
  }
  const {
    url, httpStatus, https, hstsPresent, hstsMaxAge, html, csp, reportOnlyCsp,
    nosniff, contentTypeOptionsPresent, cookies, poweredBy, serverVersion,
  } = observation;
  report.document = { url, httpStatus, evidenceStepId };
  report.checks = [
    https
      ? check('https', 'observed', 'De uiteindelijke documentrespons is via HTTPS ontvangen.')
      : check('https', 'review', 'De uiteindelijke documentrespons is via HTTP ontvangen.',
        'Serveer deze pagina via HTTPS en controleer de doorverwijzing vanaf HTTP.', 'medium'),
    !https
      ? check('hsts', 'not_observed', 'Deze controle vereist een HTTPS-documentrespons.')
      : hstsMaxAge !== null && hstsMaxAge >= 31536000
        ? check('hsts', 'observed', `HSTS max-age=${hstsMaxAge} seconden waargenomen.`)
        : check('hsts', 'review', hstsMaxAge !== null ? `HSTS max-age=${hstsMaxAge} seconden waargenomen.`
          : hstsPresent ? 'De HSTS-header bevat geen eenduidige max-age.' : 'De HSTS-header ontbreekt.',
        'Beoordeel de HSTS-configuratie voor dit HTTPS-domein. ASVS vraagt een max-age van minimaal één jaar.', 'low'),
    !html
      ? check('csp', 'not_observed', 'Het vastgelegde antwoord is niet als HTML-document aangeduid.')
      : csp
        ? check('csp', 'observed', 'Een Content-Security-Policy-header is aanwezig. De inhoud en werking van het beleid vragen beoordeling.')
        : check('csp', 'review', reportOnlyCsp ? 'Alleen een CSP Report-Only-header is aanwezig.'
          : 'De documentrespons bevat geen afdwingende CSP-header.',
        'Stel een afdwingend Content-Security-Policy-beleid in dat past bij de bronnen van de pagina.', 'low'),
    nosniff
      ? check('nosniff', 'observed', 'X-Content-Type-Options: nosniff waargenomen.')
      : check('nosniff', 'review', contentTypeOptionsPresent ? 'De header heeft geen geldige nosniff-waarde.'
        : 'De X-Content-Type-Options-header ontbreekt.',
      'Stel X-Content-Type-Options in op nosniff en geef bronnen het juiste Content-Type.', 'low'),
    ...cookieChecks(cookies),
    poweredBy || serverVersion
      ? check('banner', 'review', 'De respons toont een X-Powered-By-header of een versienummer in de Server-header.',
        'Beoordeel of deze software-informatie nodig is voor bezoekers.', 'info')
      : check('banner', 'observed', 'Geen X-Powered-By-header of versienummer in de Server-header aangetroffen.'),
  ];
  return report;
}
