// gateway/audit.js
// ═══════════════════════════════════════════════════════════════════════════
// Modul Audit Logging - Zero Trust
// Mencatat setiap aktivitas dan keputusan akses (ALLOW / DENY) ke database.
// ═══════════════════════════════════════════════════════════════════════════

import db from '../db/database.js';

/**
 * Mencatat aktivitas ke tabel audit_log
 *
 * @param {Object} params
 * @param {string} [params.waktu] - Waktu ISO/lokal (default: waktu sekarang)
 * @param {string|number} [params.subject] - User ID, username, atau service pemanggil
 * @param {string} [params.endpoint] - URL path yang diakses (misal: /nilai)
 * @param {string} [params.device] - Device ID pengakses
 * @param {string} params.hasil - 'ALLOW', 'DENY', 'BERHASIL', atau 'GAGAL'
 * @param {string} [params.alasan] - Alasan keputusan atau deskripsi log
 */
export function logAudit({ waktu, subject, endpoint, device, hasil, alasan }) {
  try {
    const waktuFinal = waktu || new Date().toISOString().replace('T', ' ').slice(0, 19);

    db.prepare(`
      INSERT INTO audit_log (waktu, subject, endpoint, device, hasil, alasan)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(
      waktuFinal,
      subject !== undefined && subject !== null ? String(subject) : null,
      endpoint !== undefined && endpoint !== null ? String(endpoint) : null,
      device !== undefined && device !== null ? String(device) : null,
      String(hasil),
      alasan !== undefined && alasan !== null ? String(alasan) : null
    );

    console.log(`[AUDIT] [${hasil}] subject: ${subject || 'anon'} | endpoint: ${endpoint || '-'} | device: ${device || '-'} | ${alasan || '-'}`);
  } catch (err) {
    console.error('[AUDIT_ERROR] Gagal menulis audit log:', err.message);
  }
}

export default logAudit;
