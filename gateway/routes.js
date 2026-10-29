// gateway/routes.js
// ═══════════════════════════════════════════════════════════════════════════
// Route Handler Gateway - Policy Enforcement Point (PEP)
// ═══════════════════════════════════════════════════════════════════════════

import express from 'express';
import { verifyJWT } from './auth.js';
import { proxyToService } from './proxy.js';
import { config } from '../shared/config.js';
import { getDb } from '../shared/db.js';
import {
  evaluateGetNilai,
  evaluateGetNilaiByMahasiswa,
  evaluateInputNilai,
  evaluateGetTranskrip,
  writeAuditLog,
} from './policyEngine.js';

export const apiRouter = express.Router();

// Semua route wajib melewati verifyJWT
apiRouter.use(verifyJWT);

function buildContext(req) {
  return {
    actor_nim:  req.user.nim,
    actor_role: req.user.role,
    ip_address: req.ip || req.socket?.remoteAddress,
  };
}

// ─── NILAI ROUTES ─────────────────────────────────────────────────────────

/**
 * GET /api/nilai/:nim
 * Ambil semua nilai milik seorang mahasiswa.
 */
apiRouter.get('/nilai/:nim', async (req, res) => {
  const targetNim = req.params.nim;
  const actor     = req.user;
  const ctx       = buildContext(req);

  const decision = await evaluateGetNilaiByMahasiswa(actor, targetNim, ctx);
  if (!decision.allowed) {
    return res.status(403).json({ error: 'Akses ditolak oleh Policy Engine.', reason: decision.reason, decision: 'DENY' });
  }

  try {
    const { status, data } = await proxyToService(config.services.nilai.url, `/internal/nilai/${targetNim}`, actor);
    return res.status(status).json(data);
  } catch (err) {
    writeAuditLog({ ...ctx, action: 'GET_NILAI_MAHASISWA', resource: req.path, decision: 'DENY', reason: `Service error: ${err.message}`, status_code: 502 });
    return res.status(502).json({ error: 'Service nilai tidak dapat dihubungi.' });
  }
});

/**
 * GET /api/nilai/:nim/:kode_mk
 * Ambil nilai spesifik satu mata kuliah.
 */
apiRouter.get('/nilai/:nim/:kode_mk', async (req, res) => {
  const { nim: targetNim, kode_mk } = req.params;
  const actor = req.user;
  const ctx   = buildContext(req);

  const decision = await evaluateGetNilai(actor, targetNim, kode_mk, ctx);
  if (!decision.allowed) {
    return res.status(403).json({ error: 'Akses ditolak oleh Policy Engine.', reason: decision.reason, decision: 'DENY' });
  }

  try {
    const { status, data } = await proxyToService(config.services.nilai.url, `/internal/nilai/${targetNim}/${kode_mk}`, actor);
    return res.status(status).json(data);
  } catch (err) {
    writeAuditLog({ ...ctx, action: 'GET_NILAI', resource: req.path, decision: 'DENY', reason: `Service error: ${err.message}`, status_code: 502 });
    return res.status(502).json({ error: 'Service nilai tidak dapat dihubungi.' });
  }
});

/**
 * PUT /api/nilai/:nim/:kode_mk
 * Input atau update nilai mahasiswa.
 * Body: { nilai_angka: number, semester?: string }
 */
apiRouter.put('/nilai/:nim/:kode_mk', async (req, res) => {
  const { nim: targetNim, kode_mk } = req.params;
  const actor = req.user;
  const ctx   = buildContext(req);

  const decision = await evaluateInputNilai(actor, targetNim, kode_mk, ctx);
  if (!decision.allowed) {
    return res.status(403).json({ error: 'Akses ditolak oleh Policy Engine.', reason: decision.reason, decision: 'DENY' });
  }

  try {
    const { status, data } = await proxyToService(
      config.services.nilai.url,
      `/internal/nilai/${targetNim}/${kode_mk}`,
      actor,
      { method: 'PUT', body: req.body }
    );
    return res.status(status).json(data);
  } catch (err) {
    writeAuditLog({ ...ctx, action: 'INPUT_NILAI', resource: req.path, decision: 'DENY', reason: `Service error: ${err.message}`, status_code: 502 });
    return res.status(502).json({ error: 'Service nilai tidak dapat dihubungi.' });
  }
});

// ─── TRANSKRIP ROUTES ─────────────────────────────────────────────────────

/**
 * GET /api/transkrip/:nim
 * Ambil transkrip lengkap mahasiswa (semua nilai + IPK).
 */
apiRouter.get('/transkrip/:nim', async (req, res) => {
  const targetNim = req.params.nim;
  const actor     = req.user;
  const ctx       = buildContext(req);

  const decision = await evaluateGetTranskrip(actor, targetNim, ctx);
  if (!decision.allowed) {
    return res.status(403).json({ error: 'Akses ditolak oleh Policy Engine.', reason: decision.reason, decision: 'DENY' });
  }

  try {
    const { status, data } = await proxyToService(config.services.transkrip.url, `/internal/transkrip/${targetNim}`, actor);
    return res.status(status).json(data);
  } catch (err) {
    writeAuditLog({ ...ctx, action: 'GET_TRANSKRIP', resource: req.path, decision: 'DENY', reason: `Service error: ${err.message}`, status_code: 502 });
    return res.status(502).json({ error: 'Service transkrip tidak dapat dihubungi.' });
  }
});

// ─── AUDIT LOG ROUTE (Admin Only) ─────────────────────────────────────────

/**
 * GET /api/audit
 * Lihat audit log (hanya admin).
 * Query: ?limit=100&actor_nim=M001&decision=DENY&action=GET_NILAI
 */
apiRouter.get('/audit', async (req, res) => {
  const actor = req.user;
  const ctx   = buildContext(req);

  if (actor.role !== 'admin') {
    writeAuditLog({ ...ctx, action: 'GET_AUDIT_LOG', resource: '/audit', decision: 'DENY', reason: 'Hanya admin yang dapat melihat audit log', status_code: 403 });
    return res.status(403).json({ error: 'Hanya admin yang dapat mengakses audit log.' });
  }

  writeAuditLog({ ...ctx, action: 'GET_AUDIT_LOG', resource: '/audit', decision: 'ALLOW', reason: 'Admin mengakses audit log', status_code: 200 });

  const { limit = 100, actor_nim, decision, action } = req.query;

  let sql    = 'SELECT * FROM audit_log';
  const conditions = [];
  const args       = [];

  if (actor_nim) { conditions.push('actor_nim = ?');        args.push(actor_nim); }
  if (decision)  { conditions.push('decision = ?');         args.push(decision.toUpperCase()); }
  if (action)    { conditions.push('action LIKE ?');        args.push(`%${action.toUpperCase()}%`); }

  if (conditions.length) sql += ' WHERE ' + conditions.join(' AND ');
  sql += ' ORDER BY id DESC LIMIT ?';
  args.push(parseInt(limit, 10));

  try {
    const result = await getDb().execute({ sql, args });
    return res.json({ total: result.rows.length, logs: result.rows });
  } catch (err) {
    return res.status(500).json({ error: 'Gagal membaca audit log.' });
  }
});
