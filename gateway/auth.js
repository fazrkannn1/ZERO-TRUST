// gateway/auth.js
// ═══════════════════════════════════════════════════════════════════════════
// Modul Autentikasi Zero Trust
// Mengelola pembuatan dan verifikasi JWT token untuk user dan antar-service.
// ═══════════════════════════════════════════════════════════════════════════

import jwt from 'jsonwebtoken';
import db from '../db/database.js';
import { config } from '../shared/config.js';

/**
 * Generate Access Token untuk user yang terautentikasi.
 * Expire: 10 menit
 * Payload: { sub, role }
 *
 * @param {Object} user - Objek user { id, role, ... }
 * @returns {string} JWT access token
 */
export function generateAccessToken(user) {
  const sub = user.id ?? user.sub ?? user.username;
  const role = user.role;
  const nim = user.nim ?? null;

  const payload = { sub, role };
  if (nim) {
    payload.nim = nim;
  }

  return jwt.sign(
    payload,
    config.jwt.secret,
    { expiresIn: '10m' }
  );
}

import crypto from 'crypto';

/**
 * Generate Refresh Token untuk user, menyimpannya ke database dengan status revoked = 0.
 * Expire: 1 hari
 *
 * @param {Object} user - Objek user { id, ... }
 * @returns {string} Refresh token
 */
export function generateRefreshToken(user) {
  const userId = user.id ?? user.sub;
  const jti = crypto.randomUUID();

  const token = jwt.sign(
    { sub: userId, type: 'refresh', jti },
    config.jwt.secret,
    { expiresIn: '1d' }
  );

  // Simpan refresh token ke database
  db.prepare(`
    INSERT INTO refresh_tokens (user_id, token, revoked)
    VALUES (?, ?, 0)
  `).run(userId, token);

  return token;
}

/**
 * Verifikasi validitas JWT token.
 * Mengembalikan payload hasil decode jika valid, atau null jika gagal/expired.
 *
 * @param {string} token - JWT token string
 * @returns {Object|null} Payload jika valid, atau null
 */
export function verifyToken(token) {
  try {
    return jwt.verify(token, config.jwt.secret);
  } catch (err) {
    return null;
  }
}

/**
 * Generate Service Token untuk komunikasi antar-service (machine-to-machine).
 * Expire: 5 menit
 * Payload: { sub: serviceName, role: 'service' }
 *
 * @param {string} serviceName - Nama service pemanggil
 * @returns {string} JWT service token
 */
export function generateServiceToken(serviceName) {
  return jwt.sign(
    { sub: serviceName, role: 'service' },
    config.jwt.secret,
    { expiresIn: '5m' }
  );
}

/**
 * Helper untuk mencatat aktivitas ke tabel audit_log
 *
 * @param {Object} logData - { subject, endpoint, device, hasil, alasan }
 */
import { logAudit } from './audit.js';

export { logAudit, logAudit as recordAuditLog };
