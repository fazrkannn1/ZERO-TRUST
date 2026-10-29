import { config } from './shared/config.js';
import db from './db/database.js';

const SERVICE_URL = 'http://localhost:3001';
const GATEWAY_URL = 'http://localhost:3000';

let passed = 0;
let failed = 0;

function assert(condition, message) {
  if (!condition) {
    console.error(`  ❌ GAGAL: ${message}`);
    failed++;
  } else {
    console.log(`  ✅ LULUS: ${message}`);
    passed++;
  }
}

async function login(username, password, device_id) {
  const res = await fetch(`${GATEWAY_URL}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password, device_id }),
  });
  return await res.json();
}

async function test() {
  console.log('═══════════════════════════════════════════════════════════════════════');
  console.log('      PENGUJIAN SERVICE NILAI (Port 3001) - ZERO TRUST (ASSUME BREACH) ');
  console.log('═══════════════════════════════════════════════════════════════════════\n');

  // Ambil token untuk testing
  const andiAuth = await login('dosen_andi', 'dosenPassword123!', 'DEV-DSN-MAC-01');
  const tokenValid = andiAuth.access_token;
  const secretValid = config.gateway.secret;

  // ── 1. Middleware Wajib (Assume Breach) ───────────────────────────────────
  console.log('【1】 Verifikasi Middleware Wajib (Assume Breach)');

  // A. Tanpa X-Gateway-Secret
  const rNoSecret = await fetch(`${SERVICE_URL}/nilai`, {
    headers: { Authorization: `Bearer ${tokenValid}` },
  });
  assert(rNoSecret.status === 403, 'Akses tanpa X-Gateway-Secret ditolak (403)');

  // B. X-Gateway-Secret salah
  const rWrongSecret = await fetch(`${SERVICE_URL}/nilai`, {
    headers: {
      Authorization: `Bearer ${tokenValid}`,
      'X-Gateway-Secret': 'SECRET_PALSU_12345',
    },
  });
  assert(rWrongSecret.status === 403, 'Akses dengan X-Gateway-Secret salah ditolak (403)');

  // C. X-Gateway-Secret benar, tapi tanpa Authorization Bearer
  const rNoAuth = await fetch(`${SERVICE_URL}/nilai`, {
    headers: { 'X-Gateway-Secret': secretValid },
  });
  assert(rNoAuth.status === 401, 'Akses tanpa Authorization header ditolak (401)');

  // D. X-Gateway-Secret benar, tapi JWT invalid
  const rBadJwt = await fetch(`${SERVICE_URL}/nilai`, {
    headers: {
      'X-Gateway-Secret': secretValid,
      Authorization: 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.token_palsu_disini',
    },
  });
  assert(rBadJwt.status === 401, 'Akses dengan JWT invalid/rusak ditolak saat verifikasi ulang (401)');

  // ── 2. Endpoint GET /nilai ───────────────────────────────────────────────
  console.log('\n【2】 Endpoint GET /nilai');

  // Query by NIM
  const rGetNim = await fetch(`${SERVICE_URL}/nilai?nim=2024001`, {
    headers: {
      'X-Gateway-Secret': secretValid,
      Authorization: `Bearer ${tokenValid}`,
    },
  });
  const dataNim = await rGetNim.json();
  assert(rGetNim.status === 200, 'GET /nilai?nim=... berhasil (200)');
  assert(Array.isArray(dataNim.data) && dataNim.data.length > 0, 'Data nilai mahasiswa ditemukan');

  // Query by kelas_id
  const rGetKelas = await fetch(`${SERVICE_URL}/nilai?kelas_id=1`, {
    headers: {
      'X-Gateway-Secret': secretValid,
      Authorization: `Bearer ${tokenValid}`,
    },
  });
  const dataKelas = await rGetKelas.json();
  assert(rGetKelas.status === 200, 'GET /nilai?kelas_id=... berhasil (200)');
  assert(dataKelas.filter?.kelas_id === 1, 'Data nilai sesuai filter kelas_id');

  // ── 3. Endpoint PUT /nilai/:id & Cek Final (Defense in Depth) ─────────────
  console.log('\n【3】 Endpoint PUT /nilai/:id & Status Final (Defense in Depth)');

  // Cari nilai non-final di kelas 1
  const nonFinalRow = db.prepare('SELECT id, nilai FROM nilai WHERE kelas_id = 1 AND final = 0 LIMIT 1').get();
  assert(nonFinalRow !== undefined, 'Ditemukan sampel nilai berstatus draft/non-final');

  if (nonFinalRow) {
    const rUpdate = await fetch(`${SERVICE_URL}/nilai/${nonFinalRow.id}`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        'X-Gateway-Secret': secretValid,
        Authorization: `Bearer ${tokenValid}`,
      },
      body: JSON.stringify({ nilai: 89.5 }),
    });
    const updateResult = await rUpdate.json();
    assert(rUpdate.status === 200, 'Update nilai non-final berhasil (200)');
    assert(updateResult.data?.nilai === 89.5, 'Nilai terupdate menjadi 89.5 di DB');
  }

  // Coba update nilai yang SUDAH FINAL
  const finalRow = db.prepare('SELECT id FROM nilai WHERE final = 1 LIMIT 1').get();
  assert(finalRow !== undefined, 'Ditemukan sampel nilai berstatus final');

  if (finalRow) {
    const rUpdateFinal = await fetch(`${SERVICE_URL}/nilai/${finalRow.id}`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        'X-Gateway-Secret': secretValid,
        Authorization: `Bearer ${tokenValid}`,
      },
      body: JSON.stringify({ nilai: 99.0 }),
    });
    assert(rUpdateFinal.status === 422, 'Update nilai yang sudah final ditolak service (422 - Defense in Depth)');
  }

  // ── 4. Endpoint POST /kelas/:id/finalisasi & Trigger Sinkron ──────────────
  console.log('\n【4】 Endpoint POST /kelas/:id/finalisasi & Trigger Sinkron via fetch');

  const rFinalisasi = await fetch(`${SERVICE_URL}/kelas/1/finalisasi`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Gateway-Secret': secretValid,
      Authorization: `Bearer ${tokenValid}`,
    },
  });
  const dataFinalisasi = await rFinalisasi.json();
  assert(rFinalisasi.status === 200, 'POST /kelas/:id/finalisasi berhasil (200)');
  assert(dataFinalisasi.sinkron_transkrip === 'BERHASIL', 'Trigger panggil Gateway /transkrip/sinkron dengan service token BERHASIL');

  // Pastikan setelah finalisasi, seluruh nilai di kelas 1 terkunci (final = 1)
  const cekFinal = db.prepare('SELECT COUNT(*) as nonFinalCount FROM nilai WHERE kelas_id = 1 AND final = 0').get();
  assert(cekFinal.nonFinalCount === 0, 'Semua nilai pada kelas 1 telah berubah menjadi final = 1');

  // Coba update nilai di kelas 1 sekarang (harus ditolak karena baru difinalisasi)
  if (nonFinalRow) {
    const rUpdateSetelahFinal = await fetch(`${SERVICE_URL}/nilai/${nonFinalRow.id}`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        'X-Gateway-Secret': secretValid,
        Authorization: `Bearer ${tokenValid}`,
      },
      body: JSON.stringify({ nilai: 95.0 }),
    });
    assert(rUpdateSetelahFinal.status === 422, 'Nilai yang baru difinalisasi terkunci dari update (422)');
  }

  // ── Hasil Akhir ───────────────────────────────────────────────────────────
  console.log('\n═══════════════════════════════════════════════════════════════════════');
  console.log(` HASIL PENGUJIAN SERVICE NILAI: ${passed} LULUS ✅  |  ${failed} GAGAL ❌`);
  console.log('═══════════════════════════════════════════════════════════════════════\n');

  if (failed > 0) process.exit(1);
}

test().catch((err) => {
  console.error('Fatal test error:', err);
  process.exit(1);
});
