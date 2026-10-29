// gateway/policy.js
// ═══════════════════════════════════════════════════════════════════════════
// POLICY ENGINE (PDP - Policy Decision Point)
// NIST SP 800-207 Zero Trust Architecture
//
// Mengembalikan: { allow: boolean, reason: string }
// Policy Engine WAJIB memvalidasi kepemilikan data langsung ke database.
// ═══════════════════════════════════════════════════════════════════════════

import db from '../db/database.js';
import { config } from '../shared/config.js';

/**
 * Mengecek apakah waktu saat ini berada di dalam jam operasional
 * Default: 07:00 - 21:00 (dapat diubah melalui config.accessHours / .env)
 *
 * @param {Date} [now=new Date()]
 * @returns {boolean}
 */
export function isWithinAccessHours(now = new Date()) {
  const startStr = config.accessHours?.start || '07:00';
  const endStr = config.accessHours?.end || '21:00';

  const [startHour, startMinute] = startStr.split(':').map(Number);
  const [endHour, endMinute] = endStr.split(':').map(Number);

  const curMinutes = now.getHours() * 60 + now.getMinutes();
  const startMinutes = startHour * 60 + startMinute;
  const endMinutes = endHour * 60 + endMinute;

  return curMinutes >= startMinutes && curMinutes <= endMinutes;
}

/**
 * Helper untuk mengambil data pengguna dari database berdasarkan ID di token (sub)
 *
 * @param {Object} user
 * @returns {Object|null}
 */
function getDbUser(user) {
  if (!user || user.sub === undefined || user.sub === null) return null;
  return db.prepare('SELECT * FROM users WHERE id = ?').get(user.sub) || null;
}

/**
 * Evaluasi izin akses berdasarkan aturan Zero Trust
 *
 * @param {Object} req - Objek request Express atau context { method, path, query, params, user }
 * @param {Date} [customNow=new Date()] - Waktu evaluasi (opsional, untuk testing)
 * @returns {{ allow: boolean, reason: string }}
 */
export function evaluatePolicy(req, customNow = new Date()) {
  const method = (req.method || 'GET').toUpperCase();
  let path = req.originalUrl ? req.originalUrl.split('?')[0] : (req.path || req.url || '/');

  // Hapus query string jika masih menempel pada path
  if (path.includes('?')) {
    path = path.split('?')[0];
  }

  const query = req.query || {};
  const params = req.params || {};
  const user = req.user || null;

  // ─── 1. Endpoint /auth/* → allow (sudah ditangani auth) ──────────────────
  if (path.startsWith('/auth')) {
    return {
      allow: true,
      reason: 'Endpoint /auth/* diizinkan untuk keperluan autentikasi',
    };
  }

  // Semua endpoint lainnya memerlukan autentikasi
  if (!user) {
    return {
      allow: false,
      reason: 'Autentikasi diperlukan: token JWT tidak disertakan atau tidak valid',
    };
  }

  // Sinkronkan data user dengan database untuk verifikasi kepemilikan
  const dbUser = getDbUser(user);
  const userId = user.sub;
  const userRole = user.role;
  const userNim = user.nim || dbUser?.nim;

  // ─── 2. GET /nilai ───────────────────────────────────────────────────────
  if (method === 'GET' && path === '/nilai') {
    // Mahasiswa: allow hanya jika query NIM == NIM di token
    if (userRole === 'mahasiswa') {
      const queryNim = query.nim;
      if (!queryNim) {
        return {
          allow: false,
          reason: 'Mahasiswa wajib menyertakan query parameter nim',
        };
      }
      if (queryNim !== userNim) {
        return {
          allow: false,
          reason: `Mahasiswa hanya boleh melihat nilai miliknya sendiri (NIM token: ${userNim}, NIM query: ${queryNim})`,
        };
      }
      return {
        allow: true,
        reason: 'Mahasiswa mengakses nilai miliknya sendiri yang sesuai dengan NIM di token',
      };
    }

    // Dosen: allow hanya jika kelas yang diminta miliknya
    if (userRole === 'dosen') {
      const kelasId = query.kelas_id || query.kelasId;
      if (!kelasId) {
        return {
          allow: false,
          reason: 'Dosen wajib menyertakan query parameter kelas_id',
        };
      }

      // Verifikasi kepemilikan kelas via query database
      const kelas = db.prepare('SELECT * FROM kelas WHERE id = ?').get(kelasId);
      if (!kelas) {
        return {
          allow: false,
          reason: `Kelas dengan ID ${kelasId} tidak ditemukan di database`,
        };
      }

      if (kelas.dosen_id !== userId) {
        return {
          allow: false,
          reason: `Dosen tidak memiliki hak akses: bukan pengampu kelas '${kelas.nama}' (verifikasi database)`,
        };
      }

      return {
        allow: true,
        reason: `Dosen mengakses nilai untuk kelas '${kelas.nama}' yang diampunya`,
      };
    }

    // Admin: allow untuk inspeksi
    if (userRole === 'admin') {
      return {
        allow: true,
        reason: 'Admin memiliki akses penuh ke daftar nilai',
      };
    }

    return {
      allow: false,
      reason: `Role '${userRole}' tidak memiliki hak akses ke endpoint /nilai`,
    };
  }

  // ─── 3. PUT /nilai/:id ───────────────────────────────────────────────────
  const matchPutNilai = path.match(/^\/nilai\/([^/]+)$/);
  if (method === 'PUT' && matchPutNilai) {
    const nilaiId = params.id || matchPutNilai[1];

    // Hanya dosen yang diizinkan mengubah nilai
    if (userRole !== 'dosen') {
      return {
        allow: false,
        reason: 'Hanya dosen pengampu yang diizinkan untuk mengubah nilai',
      };
    }

    // Cek batasan jam akses (07.00 - 21.00)
    if (!isWithinAccessHours(customNow)) {
      const start = config.accessHours?.start || '07:00';
      const end = config.accessHours?.end || '21:00';
      return {
        allow: false,
        reason: `Perubahan nilai ditolak: di luar jam kerja operasional dosen (${start} - ${end})`,
      };
    }

    // Query database untuk verifikasi kepemilikan kelas dan status nilai (final: 0/1)
    const nilaiRecord = db.prepare(`
      SELECT n.id, n.nilai, n.final, n.kelas_id, k.dosen_id, k.nama AS nama_kelas
      FROM nilai n
      JOIN kelas k ON n.kelas_id = k.id
      WHERE n.id = ?
    `).get(nilaiId);

    if (!nilaiRecord) {
      return {
        allow: false,
        reason: `Data nilai dengan ID ${nilaiId} tidak ditemukan di database`,
      };
    }

    if (nilaiRecord.dosen_id !== userId) {
      return {
        allow: false,
        reason: `Dosen bukan pengampu kelas '${nilaiRecord.nama_kelas}' (verifikasi database)`,
      };
    }

    if (nilaiRecord.final === 1) {
      return {
        allow: false,
        reason: 'Nilai sudah final (terkunci) dan tidak dapat diubah lagi',
      };
    }

    return {
      allow: true,
      reason: 'Dosen pengampu mengubah nilai yang belum final di dalam jam akses',
    };
  }

  // ─── 4. POST /kelas/:id/finalisasi ───────────────────────────────────────
  const matchFinalisasi = path.match(/^\/kelas\/([^/]+)\/finalisasi$/);
  if (method === 'POST' && matchFinalisasi) {
    const kelasId = params.id || matchFinalisasi[1];

    if (userRole !== 'dosen') {
      return {
        allow: false,
        reason: 'Hanya dosen pengampu yang dapat melakukan finalisasi kelas',
      };
    }

    // Cek batasan jam akses
    if (!isWithinAccessHours(customNow)) {
      const start = config.accessHours?.start || '07:00';
      const end = config.accessHours?.end || '21:00';
      return {
        allow: false,
        reason: `Finalisasi kelas ditolak: di luar jam kerja operasional dosen (${start} - ${end})`,
      };
    }

    // Query database untuk cek kepemilikan kelas
    const kelas = db.prepare('SELECT * FROM kelas WHERE id = ?').get(kelasId);
    if (!kelas) {
      return {
        allow: false,
        reason: `Kelas dengan ID ${kelasId} tidak ditemukan di database`,
      };
    }

    if (kelas.dosen_id !== userId) {
      return {
        allow: false,
        reason: `Dosen bukan pengampu kelas '${kelas.nama}' (verifikasi database)`,
      };
    }

    return {
      allow: true,
      reason: `Dosen pengampu memfinalisasi nilai pada kelas '${kelas.nama}' di dalam jam akses`,
    };
  }

  // ─── 5. GET /transkrip/:nim ──────────────────────────────────────────────
  const matchTranskrip = path.match(/^\/transkrip\/([^/]+)$/);
  if (method === 'GET' && matchTranskrip && matchTranskrip[1] !== 'sinkron') {
    const targetNim = params.nim || matchTranskrip[1];

    // Admin: allow semua
    if (userRole === 'admin') {
      return {
        allow: true,
        reason: 'Admin memiliki hak akses penuh untuk melihat seluruh transkrip',
      };
    }

    // Mahasiswa: allow jika :nim == NIM di token
    if (userRole === 'mahasiswa') {
      if (targetNim === userNim) {
        return {
          allow: true,
          reason: 'Mahasiswa mengakses transkrip miliknya sendiri sesuai NIM di token',
        };
      }
      return {
        allow: false,
        reason: `Mahasiswa hanya diizinkan melihat transkrip milik sendiri (NIM token: ${userNim}, NIM diminta: ${targetNim})`,
      };
    }

    return {
      allow: false,
      reason: `Role '${userRole}' tidak memiliki hak akses melihat transkrip mahasiswa`,
    };
  }

  // ─── 6. POST /transkrip/sinkron ──────────────────────────────────────────
  if (method === 'POST' && path === '/transkrip/sinkron') {
    if (userRole === 'service') {
      return {
        allow: true,
        reason: 'Service token terotorisasi untuk melakukan sinkronisasi transkrip',
      };
    }

    return {
      allow: false,
      reason: `Akses ditolak: endpoint sinkronisasi transkrip hanya dapat diakses dengan role 'service'`,
    };
  }

  // ─── Default: Deny (Zero Trust Default Deny) ────────────────────────────
  return {
    allow: false,
    reason: `Default Deny: Tidak ada aturan policy yang mengizinkan ${method} ${path} untuk role '${userRole}'`,
  };
}

/**
 * Middleware Express untuk penegakan kebijakan (Policy Enforcement Point)
 */
export function policyMiddleware(req, res, next) {
  const decision = evaluatePolicy(req);

  if (!decision.allow) {
    return res.status(403).json({
      error: 'Akses ditolak oleh Policy Engine.',
      reason: decision.reason,
      allow: false,
    });
  }

  next();
}

export default {
  evaluatePolicy,
  policyMiddleware,
  isWithinAccessHours,
};
