import { lookup as lookupDns } from 'node:dns/promises';
import { request as requestHttp } from 'node:http';
import { request as requestHttps } from 'node:https';
import { BlockList, isIP } from 'node:net';
import { promisify } from 'node:util';
import { brotliDecompress, gunzip, inflate } from 'node:zlib';

const privateV4 = new BlockList();
for (const [address, prefix] of [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8],
  ['169.254.0.0', 16], ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24],
  ['192.88.99.0', 24], ['192.168.0.0', 16], ['198.18.0.0', 15],
  ['198.51.100.0', 24], ['203.0.113.0', 24], ['224.0.0.0', 4], ['240.0.0.0', 4],
]) privateV4.addSubnet(address, prefix, 'ipv4');

const globalV6 = new BlockList();
globalV6.addSubnet('2000::', 3, 'ipv6');
const specialV6 = new BlockList();
for (const [address, prefix] of [
  ['2001::', 23], ['2001:db8::', 32], ['2002::', 16], ['3fff::', 20],
]) specialV6.addSubnet(address, prefix, 'ipv6');

function isPublicAddress(address) {
  if (address.includes('%')) return false;
  const family = isIP(address);
  if (family === 4) return !privateV4.check(address, 'ipv4');
  // This excludes IPv4-mapped and translation prefixes as well as local IPv6.
  return family === 6 && globalV6.check(address, 'ipv6') && !specialV6.check(address, 'ipv6');
}

function hostnameOf(url) {
  return url.hostname.replace(/^\[|\]$/g, '');
}

export function isPublicUrl(input) {
  let url;
  try {
    url = new URL(input);
  } catch {
    return false;
  }
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) return false;
  const host = hostnameOf(url);
  if (isIP(host)) return isPublicAddress(host);
  const name = host.toLowerCase().replace(/\.+$/, '');
  return Boolean(name) && !['localhost', 'local'].includes(name) &&
    !name.endsWith('.localhost') && !name.endsWith('.local');
}

function networkError(code, message, cause) {
  return Object.assign(new Error(message, { cause }), { code });
}

const publicAddressRequired = () => networkError(
  'PUBLIC_ADDRESS_REQUIRED', 'Het adres moet naar een publiek internetadres verwijzen.',
);

function lookupUntilAbort(host, lookup, signal) {
  return new Promise((resolve, reject) => {
    const abort = () => reject(signal.reason);
    signal.addEventListener('abort', abort, { once: true });
    Promise.resolve().then(() => lookup(host, { all: true })).then(resolve, reject)
      .finally(() => signal.removeEventListener('abort', abort));
  });
}

async function publicAddresses(host, lookup, signal) {
  const family = isIP(host);
  if (family) return [{ address: host, family }];
  let addresses;
  try {
    addresses = await lookupUntilAbort(host, lookup, signal);
  } catch (cause) {
    throw networkError('PUBLIC_LOOKUP_FAILED', 'De domeinnaam kon niet worden opgezocht.', cause);
  }
  if (!addresses.length || addresses.some(({ address, family }) =>
    family !== isIP(address) || !isPublicAddress(address))) {
    throw publicAddressRequired();
  }
  return addresses;
}

export async function resolvePublicAddress(input) {
  if (!isPublicUrl(input)) throw publicAddressRequired();
  const url = new URL(input);
  const addresses = await publicAddresses(hostnameOf(url), lookupDns, AbortSignal.timeout(4000));
  return (addresses.find(candidate => candidate.family === 4) ?? addresses[0]).address;
}

const requestHeaders = new Set([
  'accept', 'accept-language', 'cache-control', 'origin', 'range', 'user-agent',
]);
const hopHeaders = [
  'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
  'te', 'trailer', 'transfer-encoding', 'upgrade', 'content-length', 'content-encoding',
];
const decompress = new Map([
  ['gzip', promisify(gunzip)], ['x-gzip', promisify(gunzip)],
  ['deflate', promisify(inflate)], ['br', promisify(brotliDecompress)],
]);

function safeRequestHeaders(headers) {
  const forwarded = Object.create(null);
  for (const [name, value] of Object.entries(headers)) {
    if (requestHeaders.has(name.toLowerCase()) && typeof value === 'string') forwarded[name.toLowerCase()] = value;
  }
  forwarded['accept-encoding'] = 'identity';
  return forwarded;
}

function browserHeaders(headers) {
  const ignored = new Set([
    ...hopHeaders, 'set-cookie',
    ...(headers.connection ?? '').toLowerCase().split(',').map(header => header.trim()),
  ]);
  return Object.fromEntries(Object.entries(headers)
    .filter(([name, value]) => !ignored.has(name) && typeof value === 'string'));
}

function tooLarge() {
  return networkError('PUBLIC_RESPONSE_TOO_LARGE', 'De reactie van de website is te groot.');
}

async function collectResponse(response, method, maxBytes) {
  let length = 0;
  const chunks = [];
  for await (const chunk of response) {
    length += chunk.length;
    if (length > maxBytes) throw tooLarge();
    chunks.push(chunk);
  }
  let body = Buffer.concat(chunks, length);
  if (method !== 'HEAD' && length > 0) {
    const encoding = (response.headers['content-encoding'] ?? 'identity').trim().toLowerCase();
    if (encoding !== 'identity') {
      const decode = decompress.get(encoding);
      if (!decode) throw networkError('PUBLIC_UNSUPPORTED_ENCODING', 'De website gebruikt een onbekende inhoudscodering.');
      try {
        body = await decode(body, { maxOutputLength: maxBytes });
      } catch (error) {
        if (error.code === 'ERR_BUFFER_TOO_LARGE') throw tooLarge();
        throw error;
      }
    }
  }
  return { status: response.statusCode, headers: browserHeaders(response.headers), body };
}

function requestDirect(url, options, callback) {
  return (url.protocol === 'https:' ? requestHttps : requestHttp)(url, options, callback);
}

export function createPublicFetcher({
  lookup = lookupDns, request = requestDirect, timeoutMs = 10000, maxBytes = 8 * 1024 * 1024,
} = {}) {
  return async (input, { method = 'GET', headers = {}, onHeaders } = {}) => {
    if (!isPublicUrl(input)) throw publicAddressRequired();
    if (!['GET', 'HEAD'].includes(method)) {
      throw networkError('PUBLIC_METHOD_NOT_ALLOWED', 'Alleen GET- en HEAD-verzoeken zijn toegestaan.');
    }
    const url = new URL(input);
    const host = hostnameOf(url);
    const signal = AbortSignal.timeout(timeoutMs);
    try {
      const addresses = await publicAddresses(host, lookup, signal);
      const response = await new Promise((resolve, reject) => {
        const client = request(url, {
          method,
          headers: safeRequestHeaders(headers),
          agent: false,
          signal,
          rejectUnauthorized: true,
          // Keep the URL hostname for Host and TLS. The socket can connect only to
          // these resolved addresses, including when Node tries both IP families.
          lookup: (_hostname, options, callback) => {
            if (options.all) return callback(null, addresses);
            callback(null, addresses[0].address, addresses[0].family);
          },
        }, result => {
          try {
            onHeaders?.(result.statusCode, result.headers);
          } catch (error) {
            result.destroy();
            reject(error);
            return;
          }
          collectResponse(result, method, maxBytes).then(resolve, reject);
        });
        client.on('error', reject);
        client.end();
      });
      signal.throwIfAborted();
      return response;
    } catch (error) {
      if (signal.aborted) throw networkError('PUBLIC_REQUEST_TIMEOUT', 'De website antwoordde niet op tijd.', error);
      throw error;
    }
  };
}
