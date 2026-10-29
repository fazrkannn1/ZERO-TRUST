// gateway/policyEngine.js
// ═══════════════════════════════════════════════════════════════════════════
// POLICY ENGINE - Inti dari Zero Trust Architecture
// Sesuai NIST SP 800-207: Policy Decision Point (PDP)
//
// Tugas Policy Engine:
//  1. Evaluasi identitas (siapa yang meminta?)
//  2. Evaluasi konteks (dari mana? kapan?)
//  3. Evaluasi kepemilikan resource (aktor punya hak? → baca dari DB!)
//  4. Buat keputusan ALLOW / DENY
//  5. Catat semua keputusan ke audit log (wajib)
// ═══════════════════════════════════════════════════════════════════════════

import { getDb } from '../shared/db.js';

// ─── Audit Logging ────────────────────────────────────────────────────────

/**
 * Mencatat setiap keputusan akses ke tabel audit_log.
 * WAJIB dipanggil untuk SETIAP keputusan (allow maupun deny).
 * Async tapi fire-and-forget (tidak menunggu di critical path).
 */
export function writeAuditLog(entry) {
  getDb().execute({
    sql: `INSERT INTO audit_log
            (actor_nim, actor_role, action, resource, target_nim, kode_mk, decision, reason, ip_address, status_code)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    args: [
      entry.actor_nim   ?? null,
      entry.actor_role  ?? null,
      entry.action,
      entry.resource,
      entry.target_nim  ?? null,
      entry.kode_mk     ?? null,
      entry.decision,
      entry.reason,
      entry.ip_address  ?? null,
      entry.status_code ?? null,
    ],
  }).catch(err => console.error('[AUDIT ERROR]', err.message));

  console.log(`[AUDIT] ${entry.decision} | ${entry.actor_nim ?? 'anon'} | ${entry.action} | ${entry.reason}`);
}

// ─── Helper Database (async) ──────────────────────────────────────────────

async function getUserByNim(nim) {
  const r = await getDb().execute({ sql: 'SELECT * FROM users WHERE nim = ?', args: [nim] });
  return r.rows[0] ?? null;
}

async function isEnrolled(mahasiswa_nim, kode_mk) {
  const r = await getDb().execute({
    sql:  'SELECT 1 FROM enrollment WHERE mahasiswa_nim = ? AND kode_mk = ?',
    args: [mahasiswa_nim, kode_mk],
  });
  return r.rows.length > 0;
}

async function isDosenPengampu(dosen_nim, kode_mk) {
  const r = await getDb().execute({
    sql:  'SELECT 1 FROM mata_kuliah WHERE kode = ? AND dosen_nim = ?',
    args: [kode_mk, dosen_nim],
  });
  return r.rows.length > 0;
}

async function dosenHasClassWithMahasiswa(dosen_nim, mahasiswa_nim) {
  const r = await getDb().execute({
    sql: `SELECT 1 FROM enrollment e
          JOIN mata_kuliah mk ON e.kode_mk = mk.kode
          WHERE e.mahasiswa_nim = ? AND mk.dosen_nim = ?`,
    args: [mahasiswa_nim, dosen_nim],
  });
  return r.rows.length > 0;
}

// ─── Keputusan Akhir ──────────────────────────────────────────────────────

function allow(entry) {
  writeAuditLog({ ...entry, decision: 'ALLOW' });
  return { allowed: true, reason: entry.reason };
}

function deny(entry) {
  writeAuditLog({ ...entry, decision: 'DENY' });
  return { allowed: false, reason: entry.reason };
}

// ─── Policy Evaluators (async) ────────────────────────────────────────────

/**
 * Policy: GET /nilai/:nim/:kode_mk
 */
export async function evaluateGetNilai(actor, targetNim, kodeMk, context) {
  const base = { action: 'GET_NILAI', resource: `/nilai/${targetNim}/${kodeMk}`, ...context };

  const dbUser = await getUserByNim(actor.nim);
  if (!dbUser || !Number(dbUser.is_active)) {
    return deny({ ...base, reason: 'Akun tidak ditemukan atau tidak aktif di database' });
  }

  if (actor.role === 'admin') {
    return allow({ ...base, target_nim: targetNim, kode_mk: kodeMk, reason: 'Admin memiliki akses penuh' });
  }

  if (actor.role === 'mahasiswa') {
    if (actor.nim !== targetNim) {
      return deny({ ...base, target_nim: targetNim, kode_mk: kodeMk, reason: 'Mahasiswa hanya boleh melihat nilai milik sendiri' });
    }
    if (!(await isEnrolled(actor.nim, kodeMk))) {
      return deny({ ...base, target_nim: targetNim, kode_mk: kodeMk, reason: 'Mahasiswa tidak terdaftar di mata kuliah ini' });
    }
    return allow({ ...base, target_nim: targetNim, kode_mk: kodeMk, reason: 'Mahasiswa mengakses nilai sendiri (terdaftar di kelas)' });
  }

  if (actor.role === 'dosen') {
    if (!(await isDosenPengampu(actor.nim, kodeMk))) {
      return deny({ ...base, target_nim: targetNim, kode_mk: kodeMk, reason: 'Dosen bukan pengampu mata kuliah ini (verifikasi DB)' });
    }
    if (!(await isEnrolled(targetNim, kodeMk))) {
      return deny({ ...base, target_nim: targetNim, kode_mk: kodeMk, reason: 'Mahasiswa tidak terdaftar di kelas yang diampu dosen ini' });
    }
    return allow({ ...base, target_nim: targetNim, kode_mk: kodeMk, reason: 'Dosen mengakses nilai kelas yang diampu (verifikasi DB)' });
  }

  return deny({ ...base, reason: `Role tidak dikenali: ${actor.role}` });
}

/**
 * Policy: GET /nilai/:nim (semua nilai seorang mahasiswa)
 */
export async function evaluateGetNilaiByMahasiswa(actor, targetNim, context) {
  const base = { action: 'GET_NILAI_MAHASISWA', resource: `/nilai/${targetNim}`, ...context };

  const dbUser = await getUserByNim(actor.nim);
  if (!dbUser || !Number(dbUser.is_active)) {
    return deny({ ...base, reason: 'Akun tidak ditemukan atau tidak aktif di database' });
  }

  if (actor.role === 'admin') {
    return allow({ ...base, target_nim: targetNim, reason: 'Admin memiliki akses penuh' });
  }

  if (actor.role === 'mahasiswa') {
    if (actor.nim !== targetNim) {
      return deny({ ...base, target_nim: targetNim, reason: 'Mahasiswa hanya boleh melihat nilai milik sendiri' });
    }
    return allow({ ...base, target_nim: targetNim, reason: 'Mahasiswa melihat semua nilai milik sendiri' });
  }

  if (actor.role === 'dosen') {
    if (!(await dosenHasClassWithMahasiswa(actor.nim, targetNim))) {
      return deny({ ...base, target_nim: targetNim, reason: 'Dosen tidak mengampu kelas manapun dari mahasiswa ini (verifikasi DB)' });
    }
    return allow({ ...base, target_nim: targetNim, reason: 'Dosen mengampu setidaknya satu kelas mahasiswa ini (verifikasi DB)' });
  }

  return deny({ ...base, reason: `Role tidak dikenali: ${actor.role}` });
}

/**
 * Policy: PUT /nilai/:nim/:kode_mk (input/update nilai)
 */
export async function evaluateInputNilai(actor, targetNim, kodeMk, context) {
  const base = { action: 'INPUT_NILAI', resource: `/nilai/${targetNim}/${kodeMk}`, ...context };

  const dbUser = await getUserByNim(actor.nim);
  if (!dbUser || !Number(dbUser.is_active)) {
    return deny({ ...base, reason: 'Akun tidak ditemukan atau tidak aktif di database' });
  }

  if (actor.role === 'mahasiswa') {
    return deny({ ...base, target_nim: targetNim, kode_mk: kodeMk, reason: 'Mahasiswa tidak diizinkan menginput nilai' });
  }

  if (actor.role === 'admin') {
    return allow({ ...base, target_nim: targetNim, kode_mk: kodeMk, reason: 'Admin dapat menginput nilai (akses koreksi)' });
  }

  if (actor.role === 'dosen') {
    if (!(await isDosenPengampu(actor.nim, kodeMk))) {
      return deny({ ...base, target_nim: targetNim, kode_mk: kodeMk, reason: 'Dosen bukan pengampu mata kuliah ini (verifikasi DB)' });
    }
    if (!(await isEnrolled(targetNim, kodeMk))) {
      return deny({ ...base, target_nim: targetNim, kode_mk: kodeMk, reason: 'Mahasiswa tidak terdaftar di mata kuliah ini' });
    }
    return allow({ ...base, target_nim: targetNim, kode_mk: kodeMk, reason: 'Dosen pengampu menginput nilai kelas sendiri (verifikasi DB)' });
  }

  return deny({ ...base, reason: `Role tidak dikenali: ${actor.role}` });
}

/**
 * Policy: GET /transkrip/:nim
 */
export async function evaluateGetTranskrip(actor, targetNim, context) {
  const base = { action: 'GET_TRANSKRIP', resource: `/transkrip/${targetNim}`, ...context };

  const dbUser = await getUserByNim(actor.nim);
  if (!dbUser || !Number(dbUser.is_active)) {
    return deny({ ...base, reason: 'Akun tidak ditemukan atau tidak aktif di database' });
  }

  if (actor.role === 'admin') {
    return allow({ ...base, target_nim: targetNim, reason: 'Admin memiliki akses penuh ke transkrip' });
  }

  if (actor.role === 'mahasiswa') {
    if (actor.nim !== targetNim) {
      return deny({ ...base, target_nim: targetNim, reason: 'Mahasiswa hanya boleh melihat transkrip sendiri' });
    }
    return allow({ ...base, target_nim: targetNim, reason: 'Mahasiswa mengakses transkrip sendiri' });
  }

  if (actor.role === 'dosen') {
    if (!(await dosenHasClassWithMahasiswa(actor.nim, targetNim))) {
      return deny({ ...base, target_nim: targetNim, reason: 'Dosen tidak mengampu kelas manapun dari mahasiswa ini' });
    }
    return allow({ ...base, target_nim: targetNim, reason: 'Dosen mengampu setidaknya satu kelas mahasiswa ini' });
  }

  return deny({ ...base, reason: `Role tidak dikenali: ${actor.role}` });
}
