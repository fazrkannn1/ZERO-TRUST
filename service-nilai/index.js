// service-nilai/index.js
// ═══════════════════════════════════════════════════════════════════════════
// SERVICE NILAI & KELAS (Port 3001) - Zero Trust Protected Resource
//
// Prinsip Keamanan "Assume Breach" (NIST SP 800-207):
//   1. Verifikasi header X-Gateway-Secret == env GATEWAY_SECRET
//   2. Verifikasi ulang JWT token di header Authorization (Defense in Depth:
//      Service tidak mempercayai Gateway secara buta-buta)
//   3. Pengecekan ulang status final nilai saat update
// ═══════════════════════════════════════════════════════════════════════════

import express from 'express';
import jwt from 'jsonwebtoken';
import db from '../db/database.js';
import { config } from '../shared/config.js';
import { generateServiceToken } from '../gateway/auth.js';

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Request logger
app.use((req, _res, next) => {
  const ts = new Date().toISOString();
  console.log(`[SERVICE NILAI] ${ts} | ${req.method} ${req.originalUrl || req.path}`);
  next();
});

// ─── 1. Middleware Wajib Zero Trust (Assume Breach) ───────────────────────

function zeroTrustInternalAuth(req, res, next) {
  // A. Verifikasi X-Gateway-Secret
  const gatewaySecret = req.headers['x-gateway-secret'];
  if (!gatewaySecret || gatewaySecret !== config.gateway.secret) {
    console.warn(`[SERVICE NILAI] Akses ditolak: X-Gateway-Secret salah/tidak ada dari IP ${req.ip}`);
    return res.status(403).json({
      error: 'Akses ditolak: X-Gateway-Secret tidak valid atau tidak disertakan.',
    });
  }

  // B. Verifikasi ulang JWT di header Authorization: Bearer <token>
  //    (Service tidak mempercayai gateway buta-buta, wajib validasi kriptografis ulang)
  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    console.warn(`[SERVICE NILAI] Akses ditolak: Authorization header Bearer token tidak ada`);
    return res.status(401).json({
      error: 'Akses ditolak: Token autentikasi diperlukan (Bearer <token>).',
    });
  }

  const token = authHeader.slice(7).trim();

  try {
    const decoded = jwt.verify(token, config.jwt.secret);
    req.user = decoded; // { sub, role, nim, ... }
  } catch (err) {
    console.warn(`[SERVICE NILAI] Akses ditolak: JWT verifikasi ulang gagal (${err.message})`);
    return res.status(401).json({
      error: 'Akses ditolak: Token JWT tidak valid atau telah kedaluwarsa (verifikasi ulang internal).',
      reason: err.message,
    });
  }

  next();
}

// Pasang middleware Zero Trust untuk semua endpoint di service ini
app.use(zeroTrustInternalAuth);

// ─── 2. Endpoint: GET /nilai ──────────────────────────────────────────────

app.get('/nilai', (req, res) => {
  const { nim, kelas_id } = req.query;

  try {
    if (nim) {
      // Ambil seluruh nilai mahasiswa berdasarkan NIM
      const rows = db.prepare(`
        SELECT 
          n.id,
          n.mahasiswa_id,
          n.kelas_id,
          n.nilai,
          n.final,
          k.nama AS nama_kelas,
          u.nim,
          u.username AS nama_mahasiswa
        FROM nilai n
        JOIN kelas k ON n.kelas_id = k.id
        JOIN users u ON n.mahasiswa_id = u.id
        WHERE u.nim = ?
        ORDER BY k.id ASC
      `).all(nim);

      return res.json({
        total: rows.length,
        filter: { nim },
        data: rows,
      });
    }

    if (kelas_id) {
      // Ambil seluruh nilai pada kelas tertentu
      const rows = db.prepare(`
        SELECT 
          n.id,
          n.mahasiswa_id,
          n.kelas_id,
          n.nilai,
          n.final,
          k.nama AS nama_kelas,
          u.nim,
          u.username AS nama_mahasiswa
        FROM nilai n
        JOIN kelas k ON n.kelas_id = k.id
        JOIN users u ON n.mahasiswa_id = u.id
        WHERE n.kelas_id = ?
        ORDER BY u.nim ASC
      `).all(kelas_id);

      return res.json({
        total: rows.length,
        kelas_id: parseInt(kelas_id, 10),
        filter: { kelas_id: parseInt(kelas_id, 10) },
        data: rows,
      });
    }

    // Jika tanpa parameter, tampilkan seluruh nilai
    const rows = db.prepare(`
      SELECT 
        n.id,
        n.mahasiswa_id,
        n.kelas_id,
        n.nilai,
        n.final,
        k.nama AS nama_kelas,
        u.nim,
        u.username AS nama_mahasiswa
      FROM nilai n
      JOIN kelas k ON n.kelas_id = k.id
      JOIN users u ON n.mahasiswa_id = u.id
      ORDER BY n.id ASC
    `).all();

    return res.json({
      total: rows.length,
      data: rows,
    });
  } catch (err) {
    console.error('[SERVICE NILAI ERROR]', err);
    return res.status(500).json({ error: 'Terjadi kesalahan internal saat mengambil data nilai.' });
  }
});

// ─── 3. Endpoint: PUT /nilai/:id ──────────────────────────────────────────

app.put('/nilai/:id', (req, res) => {
  const { id } = req.params;
  const { nilai } = req.body ?? {};

  // Validasi input angka
  if (nilai === undefined || nilai === null) {
    return res.status(400).json({ error: 'Field nilai wajib disertakan.' });
  }

  const numNilai = parseFloat(nilai);
  if (isNaN(numNilai) || numNilai < 0 || numNilai > 100) {
    return res.status(400).json({ error: 'Nilai harus berupa angka valid antara 0 dan 100.' });
  }

  try {
    // Ambil data nilai terkini beserta info kelas
    const existing = db.prepare(`
      SELECT n.id, n.nilai, n.final, n.kelas_id, k.dosen_id, k.nama AS nama_kelas
      FROM nilai n
      JOIN kelas k ON n.kelas_id = k.id
      WHERE n.id = ?
    `).get(id);

    if (!existing) {
      return res.status(404).json({ error: `Data nilai dengan ID ${id} tidak ditemukan.` });
    }

    // Defense in Depth: Cek status final nilai secara redundan di level service
    if (existing.final === 1) {
      console.warn(`[SERVICE NILAI] Penolakan (Defense in Depth): Nilai ID ${id} sudah final`);
      return res.status(422).json({
        error: 'Akses ditolak: Nilai sudah berstatus final (terkunci) dan tidak dapat diubah lagi.',
        final: 1,
      });
    }

    // Defense in Depth: Pastikan dosen pengampu sesuai jika actor adalah dosen
    if (req.user && req.user.role === 'dosen' && existing.dosen_id !== req.user.sub) {
      return res.status(403).json({
        error: 'Akses ditolak: Anda bukan dosen pengampu untuk kelas ini (verifikasi service).',
      });
    }

    // Update nilai di database
    db.prepare('UPDATE nilai SET nilai = ? WHERE id = ?').run(numNilai, id);

    const updated = db.prepare(`
      SELECT 
        n.id,
        n.mahasiswa_id,
        n.kelas_id,
        n.nilai,
        n.final,
        k.nama AS nama_kelas,
        u.nim,
        u.username AS nama_mahasiswa
      FROM nilai n
      JOIN kelas k ON n.kelas_id = k.id
      JOIN users u ON n.mahasiswa_id = u.id
      WHERE n.id = ?
    `).get(id);

    return res.json({
      message: 'Nilai berhasil diperbarui.',
      data: updated,
    });
  } catch (err) {
    console.error('[SERVICE NILAI ERROR]', err);
    return res.status(500).json({ error: 'Terjadi kesalahan internal saat memperbarui nilai.' });
  }
});

// ─── 4. Endpoint: POST /kelas/:id/finalisasi ──────────────────────────────

app.post('/kelas/:id/finalisasi', async (req, res) => {
  const { id } = req.params;

  try {
    const kelas = db.prepare('SELECT * FROM kelas WHERE id = ?').get(id);
    if (!kelas) {
      return res.status(404).json({ error: `Kelas dengan ID ${id} tidak ditemukan.` });
    }

    // Defense in Depth: Jika actor adalah dosen, pastikan memang pengampu kelas
    if (req.user && req.user.role === 'dosen' && kelas.dosen_id !== req.user.sub) {
      return res.status(403).json({
        error: 'Akses ditolak: Anda bukan dosen pengampu kelas ini.',
      });
    }

    // Update semua nilai pada kelas ini menjadi final = 1
    const info = db.prepare('UPDATE nilai SET final = 1 WHERE kelas_id = ?').run(id);

    console.log(`[SERVICE NILAI] Kelas ID ${id} ('${kelas.nama}') difinalisasi. ${info.changes} nilai berstatus final.`);

    // ─── Panggil Gateway POST /transkrip/sinkron dengan Service Token (fetch) ──
    let sinkronResult = null;
    let sinkronStatus = 'TIDAK_DIPANGGIL';

    try {
      // Generate service token (role: 'service') untuk otentikasi Machine-to-Machine
      const serviceToken = generateServiceToken('service-nilai');
      const gatewaySyncUrl = `http://localhost:${config.gateway.port}/transkrip/sinkron`;

      console.log(`[SERVICE NILAI] Memanggil Gateway ${gatewaySyncUrl} untuk sinkronisasi transkrip...`);

      const syncResponse = await fetch(gatewaySyncUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${serviceToken}`,
          'X-Gateway-Secret': config.gateway.secret,
        },
        body: JSON.stringify({
          triggered_by: 'finalisasi_kelas',
          kelas_id: parseInt(id, 10),
          kelas_nama: kelas.nama,
          nilai_terdampak: info.changes,
          waktu: new Date().toISOString(),
        }),
      });

      sinkronResult = await syncResponse.json();
      sinkronStatus = syncResponse.ok ? 'BERHASIL' : `GAGAL_HTTP_${syncResponse.status}`;
      console.log(`[SERVICE NILAI] Hasil sinkronisasi transkrip: ${sinkronStatus}`);
    } catch (syncErr) {
      console.error('[SERVICE NILAI ERROR] Gagal memanggil gateway sinkronisasi:', syncErr.message);
      sinkronStatus = `ERROR_${syncErr.message}`;
    }

    return res.json({
      message: `Kelas '${kelas.nama}' berhasil difinalisasi.`,
      kelas_id: parseInt(id, 10),
      kelas_nama: kelas.nama,
      nilai_terdampak: info.changes,
      sinkron_transkrip: sinkronStatus,
      sinkron_detail: sinkronResult,
    });
  } catch (err) {
    console.error('[SERVICE NILAI ERROR]', err);
    return res.status(500).json({ error: 'Terjadi kesalahan internal saat finalisasi kelas.' });
  }
});

// ─── 404 & Error Handler ──────────────────────────────────────────────────

app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint tidak ditemukan pada Service Nilai.', path: req.path });
});

app.use((err, _req, res, _next) => {
  console.error('[SERVICE NILAI UNHANDLED ERROR]', err);
  if (!res.headersSent) {
    res.status(500).json({ error: 'Internal server error pada Service Nilai.' });
  }
});

// ─── Start Server ─────────────────────────────────────────────────────────

app.listen(config.services.nilai.port, () => {
  console.log(`[SERVICE NILAI] Berjalan di port ${config.services.nilai.port} (Internal Zero Trust)`);
});
