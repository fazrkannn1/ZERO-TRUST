import { config } from './shared/config.js';
import { generateServiceToken } from './gateway/auth.js';
import db from './db/database.js';

const SERVICE_URL = 'http://localhost:3002';
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
  console.log('   PENGUJIAN SERVICE TRANSKRIP (Port 3002) - ZERO TRUST (ASSUME BREACH)');
  console.log('═══════════════════════════════════════════════════════════════════════\n');

  // Ambil token untuk testing
  const citraAuth = await login('mhs_citra', 'mhsPassword123!', 'DEV-MHS-AND-01');
  const andiAuth = await login('dosen_andi', 'dosenPassword123!', 'DEV-DSN-MAC-01');

  const tokenMahasiswa = citraAuth.access_token;
  const tokenDosen = andiAuth.access_token;
  const secretValid = config.gateway.secret;

  // ── 1. Verifikasi Middleware Wajib (Assume Breach) ───────────────────────
  console.log('【1】 Verifikasi Middleware Wajib (Assume Breach)');

  // A. Tanpa X-Gateway-Secret
  const rNoSecret = await fetch(`${SERVICE_URL}/transkrip/2024001`, {
    headers: { Authorization: `Bearer ${tokenMahasiswa}` },
  });
  assert(rNoSecret.status === 403, 'Akses tanpa X-Gateway-Secret ditolak (403)');

  // B. X-Gateway-Secret salah
  const rWrongSecret = await fetch(`${SERVICE_URL}/transkrip/2024001`, {
    headers: {
      Authorization: `Bearer ${tokenMahasiswa}`,
      'X-Gateway-Secret': 'SECRET_PALSU_54321',
    },
  });
  assert(rWrongSecret.status === 403, 'Akses dengan X-Gateway-Secret salah ditolak (403)');

  // C. X-Gateway-Secret benar, tapi tanpa Authorization Bearer
  const rNoAuth = await fetch(`${SERVICE_URL}/transkrip/2024001`, {
    headers: { 'X-Gateway-Secret': secretValid },
  });
  assert(rNoAuth.status === 401, 'Akses tanpa Authorization header ditolak (401)');

  // D. X-Gateway-Secret benar, tapi JWT invalid
  const rBadJwt = await fetch(`${SERVICE_URL}/transkrip/2024001`, {
    headers: {
      'X-Gateway-Secret': secretValid,
      Authorization: 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.invalid_signature',
    },
  });
  assert(rBadJwt.status === 401, 'Akses dengan JWT invalid/rusak ditolak saat verifikasi ulang (401)');

  // ── 2. Endpoint GET /transkrip/:nim ───────────────────────────────────────
  console.log('\n【2】 Endpoint GET /transkrip/:nim');

  const rGetTranskrip = await fetch(`${SERVICE_URL}/transkrip/2024001`, {
    headers: {
      'X-Gateway-Secret': secretValid,
      Authorization: `Bearer ${tokenMahasiswa}`,
    },
  });
  const dataTranskrip = await rGetTranskrip.json();

  assert(rGetTranskrip.status === 200, 'GET /transkrip/:nim berhasil (200)');
  assert(dataTranskrip.transkrip?.mahasiswa?.nim === '2024001', 'NIM mahasiswa pada transkrip sesuai');
  assert(dataTranskrip.transkrip?.ringkasan?.ipk !== undefined, 'IPK kumulatif berhasil dihitung');
  assert(Array.isArray(dataTranskrip.transkrip?.detail_nilai), 'Detail nilai transkrip berupa array');

  // Request NIM yang tidak ada
  const rNotFound = await fetch(`${SERVICE_URL}/transkrip/9999999`, {
    headers: {
      'X-Gateway-Secret': secretValid,
      Authorization: `Bearer ${tokenMahasiswa}`,
    },
  });
  assert(rNotFound.status === 404, 'NIM tidak terdaftar menghasilkan 404 Not Found');

  // ── 3. Endpoint POST /transkrip/sinkron & Validasi Role Service ───────────
  console.log('\n【3】 Endpoint POST /transkrip/sinkron (Validasi Role Service)');

  // A. Panggil dengan token Mahasiswa (role: 'mahasiswa')
  const rSyncMhs = await fetch(`${SERVICE_URL}/transkrip/sinkron`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Gateway-Secret': secretValid,
      Authorization: `Bearer ${tokenMahasiswa}`,
    },
    body: JSON.stringify({ kelas_id: 1 }),
  });
  assert(rSyncMhs.status === 403, 'Akses sinkronisasi dengan token mahasiswa ditolak (403)');

  // B. Panggil dengan token Dosen (role: 'dosen')
  const rSyncDosen = await fetch(`${SERVICE_URL}/transkrip/sinkron`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Gateway-Secret': secretValid,
      Authorization: `Bearer ${tokenDosen}`,
    },
    body: JSON.stringify({ kelas_id: 1 }),
  });
  const dataSyncDosen = await rSyncDosen.json();
  assert(rSyncDosen.status === 403, `Akses sinkronisasi dengan token dosen ditolak (403 - got ${rSyncDosen.status}: ${JSON.stringify(dataSyncDosen)})`);

  // C. Panggil dengan Service Token (role: 'service')
  const serviceToken = generateServiceToken('service-nilai-test');
  const rSyncService = await fetch(`${SERVICE_URL}/transkrip/sinkron`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Gateway-Secret': secretValid,
      Authorization: `Bearer ${serviceToken}`,
    },
    body: JSON.stringify({
      triggered_by: 'test_service_transkrip',
      kelas_id: 1,
    }),
  });
  const dataSync = await rSyncService.json();

  assert(rSyncService.status === 200, 'Akses sinkronisasi dengan service token (role: service) BERHASIL (200)');
  assert(dataSync.status === 'SINKRON_OK', 'Status sinkronisasi SINKRON_OK');

  // D. Verifikasi data tersimpan di tabel transkrip SQLite
  const transkripCount = db.prepare('SELECT COUNT(*) as count FROM transkrip').get();
  assert(transkripCount.count > 0, `Data tersimpan di tabel transkrip SQLite (Total record: ${transkripCount.count})`);

  // ── Hasil Akhir ───────────────────────────────────────────────────────────
  console.log('\n═══════════════════════════════════════════════════════════════════════');
  console.log(` HASIL PENGUJIAN SERVICE TRANSKRIP: ${passed} LULUS ✅  |  ${failed} GAGAL ❌`);
  console.log('═══════════════════════════════════════════════════════════════════════\n');

  if (failed > 0) process.exit(1);
}

test().catch((err) => {
  console.error('Fatal test error:', err);
  process.exit(1);
});
