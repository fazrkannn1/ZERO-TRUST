import db from './db/database.js';

const GATEWAY = 'http://localhost:3000';

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
  const res = await fetch(`${GATEWAY}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password, device_id }),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(`Login failed for ${username}: ${JSON.stringify(data)}`);
  return data;
}

async function run() {
  console.log('═══════════════════════════════════════════════════════════════════════');
  console.log('      PENGUJIAN END-TO-END GATEWAY, PROXY, & POLICY ENGINE             ');
  console.log('═══════════════════════════════════════════════════════════════════════\n');

  // ── 1. Login user dan ambil token ──────────────────────────────────────────
  console.log('【1】 Autentikasi Pengguna & Pengambilan Token');
  const citraAuth = await login('mhs_citra', 'mhsPassword123!', 'DEV-MHS-AND-01');
  const daniAuth = await login('mhs_dani', 'mhsPassword123!', 'DEV-MHS-IOS-02');
  const andiAuth = await login('dosen_andi', 'dosenPassword123!', 'DEV-DSN-MAC-01');
  const budiAuth = await login('dosen_budi', 'dosenPassword123!', 'DEV-DSN-LNX-02');
  const adminAuth = await login('admin', 'adminPassword123!', 'DEV-ADMIN-WIN-01');

  assert(citraAuth.access_token, 'Login Mahasiswa Citra berhasil');
  assert(andiAuth.access_token, 'Login Dosen Andi berhasil');
  assert(adminAuth.access_token, 'Login Admin berhasil');

  // ── 2. Uji Middleware Verifikasi ───────────────────────────────────────────
  console.log('\n【2】 Uji Middleware Verifikasi Zero Trust (Gateway PEP)');

  // Tanpa token
  const rNoToken = await fetch(`${GATEWAY}/nilai?nim=2024001`);
  assert(rNoToken.status === 401, 'Request tanpa Authorization header ditolak (401)');

  // Token invalid
  const rBadToken = await fetch(`${GATEWAY}/nilai?nim=2024001`, {
    headers: { Authorization: 'Bearer token_ngawur' },
  });
  assert(rBadToken.status === 401, 'Request dengan token invalid ditolak (401)');

  // Tanpa X-Device-ID
  const rNoDevice = await fetch(`${GATEWAY}/nilai?nim=2024001`, {
    headers: { Authorization: `Bearer ${citraAuth.access_token}` },
  });
  assert(rNoDevice.status === 403, 'Request tanpa header X-Device-ID ditolak (403)');

  // X-Device-ID salah / tidak cocok
  const rWrongDevice = await fetch(`${GATEWAY}/nilai?nim=2024001`, {
    headers: {
      Authorization: `Bearer ${citraAuth.access_token}`,
      'X-Device-ID': 'DEVICE-UNKNOWN-HACK',
    },
  });
  assert(rWrongDevice.status === 403, 'Request dengan X-Device-ID salah ditolak (403)');

  // ── 3. Uji Proxy /nilai* & Policy Engine ───────────────────────────────────
  console.log('\n【3】 Uji Proxy /nilai* (Forward ke :3001) & Policy Engine');

  // Mahasiswa Citra lihat nilai sendiri
  const rNilaiCitra = await fetch(`${GATEWAY}/nilai?nim=2024001`, {
    headers: {
      Authorization: `Bearer ${citraAuth.access_token}`,
      'X-Device-ID': 'DEV-MHS-AND-01',
    },
  });
  const dataNilaiCitra = await rNilaiCitra.json();
  assert(rNilaiCitra.status === 200, 'Mahasiswa lihat nilai sendiri berhasil melalui proxy (200)');
  assert(Array.isArray(dataNilaiCitra.data), 'Data nilai mahasiswa berupa array');

  // Mahasiswa Citra intip nilai Dani
  const rNilaiIntip = await fetch(`${GATEWAY}/nilai?nim=2024002`, {
    headers: {
      Authorization: `Bearer ${citraAuth.access_token}`,
      'X-Device-ID': 'DEV-MHS-AND-01',
    },
  });
  assert(rNilaiIntip.status === 403, 'Mahasiswa intip nilai orang lain ditolak Policy (403)');

  // Dosen Andi lihat nilai kelas 1 (miliknya)
  const rNilaiDosenOk = await fetch(`${GATEWAY}/nilai?kelas_id=1`, {
    headers: {
      Authorization: `Bearer ${andiAuth.access_token}`,
      'X-Device-ID': 'DEV-DSN-MAC-01',
    },
  });
  const dataNilaiDosen = await rNilaiDosenOk.json();
  assert(rNilaiDosenOk.status === 200, 'Dosen lihat nilai kelas yang diampu berhasil (200)');
  assert(dataNilaiDosen.kelas_id === 1, 'Hasil query sesuai kelas_id');

  // Dosen Andi intip nilai kelas 2 (milik Dosen Budi)
  const rNilaiDosenIntip = await fetch(`${GATEWAY}/nilai?kelas_id=2`, {
    headers: {
      Authorization: `Bearer ${andiAuth.access_token}`,
      'X-Device-ID': 'DEV-DSN-MAC-01',
    },
  });
  assert(rNilaiDosenIntip.status === 403, 'Dosen akses kelas dosen lain ditolak Policy (403)');

  // ── 4. Uji Proxy PUT /nilai/:id ───────────────────────────────────────────
  console.log('\n【4】 Uji Proxy PUT /nilai/:id (Update Nilai)');

  // Pastikan ada sampel nilai kelas 1 yang belum final untuk diuji
  db.prepare('UPDATE nilai SET final = 0 WHERE id = (SELECT id FROM nilai WHERE kelas_id = 1 LIMIT 1)').run();
  const nilaiRecord = db.prepare('SELECT id FROM nilai WHERE kelas_id = 1 AND final = 0 LIMIT 1').get();

  if (nilaiRecord) {
    const rPutNilai = await fetch(`${GATEWAY}/nilai/${nilaiRecord.id}`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${andiAuth.access_token}`,
        'X-Device-ID': 'DEV-DSN-MAC-01',
      },
      body: JSON.stringify({ nilai: 88.0 }),
    });
    const putData = await rPutNilai.json();
    assert(rPutNilai.status === 200, 'Dosen pengampu update nilai non-final berhasil (200)');
    assert(putData.data?.nilai === 88.0, 'Nilai berhasil diupdate di database');

    // Dosen Budi coba update nilai kelas 1
    const rPutIlegal = await fetch(`${GATEWAY}/nilai/${nilaiRecord.id}`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${budiAuth.access_token}`,
        'X-Device-ID': 'DEV-DSN-LNX-02',
      },
      body: JSON.stringify({ nilai: 99.0 }),
    });
    assert(rPutIlegal.status === 403, 'Dosen lain coba update nilai ditolak Policy (403)');
  }

  // ── 5. Uji Proxy /transkrip* & M2M Sinkron ─────────────────────────────────
  console.log('\n【5】 Uji Proxy /transkrip* (Forward ke :3002)');

  // Mahasiswa Citra lihat transkrip sendiri
  const rTrskpCitra = await fetch(`${GATEWAY}/transkrip/2024001`, {
    headers: {
      Authorization: `Bearer ${citraAuth.access_token}`,
      'X-Device-ID': 'DEV-MHS-AND-01',
    },
  });
  const dataTrskp = await rTrskpCitra.json();
  assert(rTrskpCitra.status === 200, 'Mahasiswa lihat transkrip sendiri berhasil (200)');
  assert(dataTrskp.transkrip?.ringkasan?.ipk !== undefined, 'Transkrip memuat IPK kalkulasi');

  // Mahasiswa Citra intip transkrip Dani
  const rTrskpIntip = await fetch(`${GATEWAY}/transkrip/2024002`, {
    headers: {
      Authorization: `Bearer ${citraAuth.access_token}`,
      'X-Device-ID': 'DEV-MHS-AND-01',
    },
  });
  assert(rTrskpIntip.status === 403, 'Mahasiswa intip transkrip orang lain ditolak Policy (403)');

  // Admin lihat transkrip siapapun
  const rTrskpAdmin = await fetch(`${GATEWAY}/transkrip/2024001`, {
    headers: {
      Authorization: `Bearer ${adminAuth.access_token}`,
      'X-Device-ID': 'DEV-ADMIN-WIN-01',
    },
  });
  assert(rTrskpAdmin.status === 200, 'Admin lihat transkrip siapapun diizinkan (200)');

  // ── 6. Uji Finalisasi Kelas & Trigger Sinkron M2M ──────────────────────────
  console.log('\n【6】 Uji POST /kelas/:id/finalisasi & Trigger Sinkron M2M');

  const rFin = await fetch(`${GATEWAY}/kelas/1/finalisasi`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${andiAuth.access_token}`,
      'X-Device-ID': 'DEV-DSN-MAC-01',
    },
  });
  const dataFin = await rFin.json();
  assert(rFin.status === 200, 'Dosen finalisasi kelas berhasil (200)');
  assert(dataFin.sinkron_transkrip === 'BERHASIL', 'Trigger sinkron transkrip ke Service Transkrip BERHASIL');

  // ── 7. Uji Keberadaan Log di Audit Table ───────────────────────────────────
  console.log('\n【7】 Verifikasi Pencatatan Audit Log');
  const auditCount = db.prepare('SELECT COUNT(*) as count FROM audit_log').get();
  assert(auditCount.count > 0, `Audit log tercatat di SQLite (Total log: ${auditCount.count})`);

  const lastLogs = db.prepare('SELECT hasil, endpoint, alasan FROM audit_log ORDER BY id DESC LIMIT 3').all();
  console.log('     Contoh log terakhir:');
  lastLogs.forEach((l) => console.log(`       - [${l.hasil}] ${l.endpoint}: ${l.alasan}`));

  // ── Hasil Akhir ───────────────────────────────────────────────────────────
  console.log('\n═══════════════════════════════════════════════════════════════════════');
  console.log(` HASIL PENGUJIAN END-TO-END: ${passed} LULUS ✅  |  ${failed} GAGAL ❌`);
  console.log('═══════════════════════════════════════════════════════════════════════\n');

  if (failed > 0) process.exit(1);
}

run().catch((err) => {
  console.error('Fatal error during E2E test:', err);
  process.exit(1);
});
