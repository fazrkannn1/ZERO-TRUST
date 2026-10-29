// gateway/proxy.js
// ═══════════════════════════════════════════════════════════════════════════
// Proxy Layer - Meneruskan request ke internal services
// Sesuai Zero Trust: gateway SELALU menyuntikkan X-Gateway-Secret
// dan informasi identitas actor sebelum meneruskan ke service.
//
// Service tidak boleh mempercayai request tanpa header ini.
// ═══════════════════════════════════════════════════════════════════════════

import { config } from '../shared/config.js';

/**
 * Meneruskan request ke service internal dengan menambahkan:
 *   - X-Gateway-Secret: shared secret untuk verifikasi asal request
 *   - X-Actor-NIM: NIM aktor yang sudah diverifikasi gateway
 *   - X-Actor-Role: role aktor
 *   - X-Actor-Nama: nama aktor
 *
 * @param {string} serviceUrl  - Base URL service tujuan
 * @param {string} path        - Path endpoint di service
 * @param {object} actor       - Objek {nim, nama, role} dari token JWT
 * @param {object} [options]   - Override fetch options (method, body, headers)
 */
export async function proxyToService(serviceUrl, path, actor, options = {}) {
  const url = `${serviceUrl}${path}`;

  const headers = {
    'Content-Type':    'application/json',
    'X-Gateway-Secret': config.gateway.secret,
    'X-Actor-NIM':     actor.nim,
    'X-Actor-Role':    actor.role,
    'X-Actor-Nama':    actor.nama,
    ...(options.headers ?? {}),
  };

  const fetchOptions = {
    method:  options.method  ?? 'GET',
    headers,
  };

  if (options.body) {
    fetchOptions.body = typeof options.body === 'string'
      ? options.body
      : JSON.stringify(options.body);
  }

  const response = await fetch(url, fetchOptions);
  const data     = await response.json();

  return { status: response.status, data };
}
