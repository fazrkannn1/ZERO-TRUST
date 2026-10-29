// service-transkrip/index.js
// ═══════════════════════════════════════════════════════════════════════════
// SERVICE TRANSKRIP (Port 3002) - Zero Trust Protected Resource
//
// 1. Middleware Wajib (Prinsip Assume Breach):
//    - Verifikasi header X-Gateway-Secret == env GATEWAY_SECRET
//    - Verifikasi ulang JWT di header Authorization: Bearer <token>
// 2. Endpoint:
//    - GET /transkrip/:nim    → Mengembalikan transkrip resmi mahasiswa
//    - POST /transkrip/sinkron → Menerima dan menyinkronkan nilai final ke tabel transkrip
//      (HANYA boleh dipanggil dengan token role === 'service')
// ═══════════════════════════════════════════════════════════════════════════

import express from 'express';
import jwt from 'jsonwebtoken';
import db from '../db/database.js';
import { config } from '../shared/config.js';
import { toHuruf, toBobot, toPredikat } from '../shared/nilaiHelper.js';

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Request logger
app.use((req, _res, next) => {
  const ts = new Date().toISOString();
  console.log(`[SERVICE TRANSKRIP] ${ts} | ${req.method} ${req.originalUrl || req.path}`);
  next();
});

// ─── 1. Middleware Wajib Zero Trust (Assume Breach) ───────────────────────

function zeroTrustInternalAuth(req, res, next) {
  // A. Verifikasi X-Gateway-Secret
  const gatewaySecret = req.headers['x-gateway-secret'];
  if (!gatewaySecret || gatewaySecret !== config.gateway.secret) {
    console.warn(`[SERVICE TRANSKRIP] Akses ditolak: X-Gateway-Secret salah/tidak ada dari IP ${req.ip}`);
    return res.status(403).json({
      error: 'Akses ditolak: X-Gateway-Secret tidak valid atau tidak disertakan.',
    });
  }

  // B. Verifikasi ulang JWT di header Authorization: Bearer <token>
  //    (Service tidak mempercayai gateway buta-buta, wajib validasi kriptografis ulang)
  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    console.warn(`[SERVICE TRANSKRIP] Akses ditolak: Authorization header Bearer token tidak ada`);
    return res.status(401).json({
      error: 'Akses ditolak: Token autentikasi diperlukan (Bearer <token>).',
    });
  }

  const token = authHeader.slice(7).trim();

  try {
    const decoded = jwt.verify(token, config.jwt.secret);
    req.user = decoded; // { sub, role, ... }
  } catch (err) {
    console.warn(`[SERVICE TRANSKRIP] Akses ditolak: JWT verifikasi ulang gagal (${err.message})`);
    return res.status(401).json({
      error: 'Akses ditolak: Token JWT tidak valid atau telah kedaluwarsa (verifikasi ulang internal).',
      reason: err.message,
    });
  }

  next();
}

// Pasang middleware Zero Trust untuk semua rute
app.use(zeroTrustInternalAuth);

// ─── 2. Endpoint: GET /transkrip/:nim ─────────────────────────────────────

app.get('/transkrip/:nim', (req, res) => {
  const { nim } = req.params;

  try {
    // 1. Cek keberadaan mahasiswa di database
    const student = db.prepare('SELECT id, username, nim, role FROM users WHERE nim = ?').get(nim);
    if (!student) {
      return res.status(404).json({ error: `Mahasiswa dengan NIM ${nim} tidak ditemukan.` });
    }

    if (student.role !== 'mahasiswa') {
      return res.status(400).json({ error: `NIM ${nim} bukan merupakan akun mahasiswa.` });
    }

    // 2. Ambil data transkrip resmi dari tabel `transkrip`
    //    (Snapshot data akademik yang sudah difinalisasi)
    let transcriptRows = db.prepare(`
      SELECT 
        id,
        kelas_id,
        nama_kelas,
        nilai_angka,
        nilai_huruf,
        bobot,
        disinkron_pada
      FROM transkrip
      WHERE nim = ?
      ORDER BY kelas_id ASC
    `).all(nim);

    // Jika tabel transkrip masih kosong tetapi ada nilai final di tabel nilai (sinkronisasi fallback)
    if (transcriptRows.length === 0) {
      const finalGrades = db.prepare(`
        SELECT 
          n.id,
          n.kelas_id,
          k.nama AS nama_kelas,
          n.nilai AS nilai_angka
        FROM nilai n
        JOIN kelas k ON n.kelas_id = k.id
        WHERE n.mahasiswa_id = ? AND n.final = 1
      `).all(student.id);

      if (finalGrades.length > 0) {
        // Otomatis sinkronkan nilai final ke tabel transkrip
        const insertTx = db.transaction(() => {
          for (const g of finalGrades) {
            const huruf = toHuruf(g.nilai_angka);
            const bbt = toBobot(g.nilai_angka);
            db.prepare(`
              INSERT INTO transkrip 
                (mahasiswa_id, nim, nama_mahasiswa, kelas_id, nama_kelas, nilai_angka, nilai_huruf, bobot)
              VALUES (?, ?, ?, ?, ?, ?, ?, ?)
              ON CONFLICT(mahasiswa_id, kelas_id) DO UPDATE SET
                nilai_angka = excluded.nilai_angka,
                nilai_huruf = excluded.nilai_huruf,
                bobot = excluded.bobot,
                disinkron_pada = datetime('now', 'localtime')
            `).run(student.id, student.nim, student.username, g.kelas_id, g.nama_kelas, g.nilai_angka, huruf, bbt);
          }
        });
        insertTx();

        // Ambil kembali data yang baru disinkronkan
        transcriptRows = db.prepare(`
          SELECT id, kelas_id, nama_kelas, nilai_angka, nilai_huruf, bobot, disinkron_pada
          FROM transkrip WHERE nim = ? ORDER BY kelas_id ASC
        `).all(nim);
      }
    }

    // 3. Kalkulasi IPK Kumulatif & Predikat Kelulusan
    let totalBobot = 0;
    transcriptRows.forEach((r) => {
      totalBobot += r.bobot;
    });

    const totalMataKuliah = transcriptRows.length;
    const ipk = totalMataKuliah > 0
      ? parseFloat((totalBobot / totalMataKuliah).toFixed(2))
      : 0.0;

    const predikat = toPredikat(ipk);

    return res.json({
      transkrip: {
        mahasiswa: {
          id: student.id,
          nama: student.username,
          nim: student.nim,
        },
        ringkasan: {
          total_mata_kuliah: totalMataKuliah,
          ipk: ipk,
          predikat: predikat,
          status_arsip: 'RESMI',
        },
        detail_nilai: transcriptRows,
        digenerate_pada: new Date().toISOString(),
      },
    });
  } catch (err) {
    console.error('[SERVICE TRANSKRIP ERROR]', err);
    return res.status(500).json({ error: 'Terjadi kesalahan internal saat mengambil transkrip.' });
  }
});

// ─── 3. Endpoint: POST /transkrip/sinkron ──────────────────────────────────

app.post('/transkrip/sinkron', (req, res) => {
  // A. Validasi ketat bahwa /transkrip/sinkron HANYA bisa dipanggil dengan token role === 'service'
  if (!req.user || req.user.role !== 'service') {
    console.warn(`[SERVICE TRANSKRIP] Akses ditolak: role '${req.user?.role}' mencoba mengakses /transkrip/sinkron`);
    return res.status(403).json({
      error: "Akses ditolak: Endpoint /transkrip/sinkron hanya dapat dipanggil dengan token ber-role 'service'.",
      required_role: 'service',
      current_role: req.user?.role || 'anonymous',
    });
  }

  const body = req.body ?? {};
  const kelasId = body.kelas_id;

  console.log(`[SERVICE TRANSKRIP] Sinkronisasi nilai final dipicu oleh service '${req.user.sub}':`, body);

  try {
    // B. Ambil data nilai berstatus final (final = 1) dari tabel nilai
    let query = `
      SELECT 
        n.mahasiswa_id,
        u.nim,
        u.username AS nama_mahasiswa,
        n.kelas_id,
        k.nama AS nama_kelas,
        n.nilai AS nilai_angka
      FROM nilai n
      JOIN users u ON n.mahasiswa_id = u.id
      JOIN kelas k ON n.kelas_id = k.id
      WHERE n.final = 1
    `;
    const params = [];

    if (kelasId) {
      query += ' AND n.kelas_id = ?';
      params.push(kelasId);
    }

    const finalGrades = db.prepare(query).all(...params);

    // C. Upsert data ke tabel transkrip (Arsip Permanen Akademik)
    const upsertTranskrip = db.prepare(`
      INSERT INTO transkrip 
        (mahasiswa_id, nim, nama_mahasiswa, kelas_id, nama_kelas, nilai_angka, nilai_huruf, bobot, disinkron_pada)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now', 'localtime'))
      ON CONFLICT(mahasiswa_id, kelas_id) DO UPDATE SET
        nilai_angka = excluded.nilai_angka,
        nilai_huruf = excluded.nilai_huruf,
        bobot = excluded.bobot,
        disinkron_pada = datetime('now', 'localtime')
    `);

    let syncedCount = 0;
    const syncTx = db.transaction((rows) => {
      for (const row of rows) {
        const huruf = toHuruf(row.nilai_angka);
        const bbt = toBobot(row.nilai_angka);
        upsertTranskrip.run(
          row.mahasiswa_id,
          row.nim,
          row.nama_mahasiswa,
          row.kelas_id,
          row.nama_kelas,
          row.nilai_angka,
          huruf,
          bbt
        );
        syncedCount++;
      }
    });

    syncTx(finalGrades);

    console.log(`[SERVICE TRANSKRIP] Berhasil menyinkronkan ${syncedCount} record nilai final ke tabel transkrip.`);

    return res.json({
      message: 'Sinkronisasi nilai final ke tabel transkrip berhasil.',
      status: 'SINKRON_OK',
      total_disinkron: syncedCount,
      kelas_id: kelasId || 'SEMUA_KELAS_FINAL',
      service_caller: req.user.sub,
      timestamp: new Date().toISOString(),
    });
  } catch (err) {
    console.error('[SERVICE TRANSKRIP ERROR]', err);
    return res.status(500).json({ error: 'Terjadi kesalahan internal saat sinkronisasi transkrip.' });
  }
});

// ─── 404 & Error Handler ──────────────────────────────────────────────────

app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint tidak ditemukan pada Service Transkrip.', path: req.path });
});

app.use((err, _req, res, _next) => {
  console.error('[SERVICE TRANSKRIP UNHANDLED ERROR]', err);
  if (!res.headersSent) {
    res.status(500).json({ error: 'Internal server error pada Service Transkrip.' });
  }
});

// ─── Start Server ─────────────────────────────────────────────────────────

app.listen(config.services.transkrip.port, () => {
  console.log(`[SERVICE TRANSKRIP] Berjalan di port ${config.services.transkrip.port} (Internal Zero Trust)`);
});
