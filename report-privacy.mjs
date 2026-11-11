import { createHash, randomBytes } from 'node:crypto';

const cookieName = 'browser_agent_owner';
const webAddress = /(?:https?|wss?):\/\/[^\s"'<>\x60]+/gi;

export function reportOwner(request, response) {
  const cookie = request.headers.cookie?.split(';')
    .map(part => part.trim())
    .find(part => part.startsWith(`${cookieName}=`));
  let token = cookie?.slice(cookieName.length + 1);
  if (!/^[a-f0-9]{64}$/.test(token ?? '')) {
    if (!response) return null;
    token = randomBytes(32).toString('hex');
    response.setHeader('Set-Cookie', `${cookieName}=${token}; Path=/; HttpOnly; SameSite=Strict`);
  }
  return createHash('sha256').update(token).digest('hex');
}

export function redactReportValue(key, value) {
  if (typeof value !== 'string') return value;
  if (key === 'url' && /^(data|file|blob):/i.test(value)) return '[browseradres afgeschermd]';
  return value.replace(webAddress, address =>
    address.split(/[?#]/, 1)[0].replace(/^((?:https?|wss?):\/\/)[^/]+@/i, '$1'));
}
