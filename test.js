#!/usr/bin/env node
// test.js — Script pengujian komprehensif Zero Trust Akademik
// Jalankan SETELAH semua server berjalan:
//   node gateway/index.js
//   node service-nilai/index.js
//   node service-transkrip/index.js

const BASE = 'http://localhost:3000';

let passed = 0;
let failed = 0;

// ─── Helper ───────────────────────────────────────────────────────────────

async function req(method, path, body, token) {
  const headers = { 'Content-Type': 'application/json' };
  if (token) headers['Authorization'] = `Bearer ${token}`;

  const opts = { method, headers };
  if (body) opts.body = JSON.stringify(body);

  const res  = await fetch(`${BASE}${path}`, opts);
  const data = await res.json();
  return { status: res.status, data };
}

async function test(desc, fn) {
  try {
    await fn();
    console.log(`  ✅ ${desc}`);
    passed++;
  } catch (err) {
    console.log(`  ❌ ${desc}`);
    console.log(`     → ${err.message}`);
    failed++;
  }
}

function expect(val, msg) {
  if (!val) throw new Error(msg || `Assertion gagal: ${JSON.stringify(val)}`);
}

// ─── Login dan ambil token ─────────────────────────────────────────────────

async function login(nim, password) {
  const r = await req('POST', '/auth/login', { nim, password });
  expect(r.status === 200, `Login ${nim} gagal: ${JSON.stringify(r.data)}`);
  return r.data.token;
}

// ─── Test Suites ──────────────────────────────────────────────────────────

async function main() {
  console.log('\n═══════════════════════════════════════════════════════════');
  console.log('  ZERO TRUST AKADEMIK - Pengujian Komprehensif');
  console.log('═══════════════════════════════════════════════════════════\n');

  // ── 1. Autentikasi ────────────────────────────────────────────────────
  console.log('【1】 Autentikasi & JWT');

  let tokenAdmin, tokenD001, tokenD002, tokenM001, tokenM002, tokenM003;

  await test('Login admin berhasil', async () => {
    tokenAdmin = await login('ADMIN001', 'password_admin');
    expect(typeof tokenAdmin === 'string' && tokenAdmin.length > 10, 'Token tidak valid');
  });

  await test('Login dosen D001 berhasil', async () => {
    tokenD001 = await login('D001', 'password_dosen1');
  });

  await test('Login dosen D002 berhasil', async () => {
    tokenD002 = await login('D002', 'password_dosen2');
  });

  await test('Login mahasiswa M001 berhasil', async () => {
    tokenM001 = await login('M001', 'password_mhs1');
  });

  await test('Login mahasiswa M002 berhasil', async () => {
    tokenM002 = await login('M002', 'password_mhs2');
  });

  await test('Login mahasiswa M003 berhasil', async () => {
    tokenM003 = await login('M003', 'password_mhs3');
  });

  await test('Login dengan password salah → 401', async () => {
    const r = await req('POST', '/auth/login', { nim: 'M001', password: 'salah' });
    expect(r.status === 401, `Expected 401, got ${r.status}`);
  });

  await test('Request tanpa token → 401', async () => {
    const r = await req('GET', '/nilai/M001');
    expect(r.status === 401, `Expected 401, got ${r.status}`);
  });

  // ── 2. Akses Service Langsung (harus ditolak) ─────────────────────────
  console.log('\n【2】 Proteksi Service Internal (Zero Trust - No Direct Access)');

  await test('Akses service-nilai langsung tanpa secret → 404', async () => {
    const r = await fetch('http://localhost:3001/internal/nilai/M001');
    expect(r.status === 404, `Expected 404, got ${r.status}`);
  });

  await test('Akses service-transkrip langsung tanpa secret → 404', async () => {
    const r = await fetch('http://localhost:3002/internal/transkrip/M001');
    expect(r.status === 404, `Expected 404, got ${r.status}`);
  });

  await test('Akses service-nilai dengan secret salah → 404', async () => {
    const r = await fetch('http://localhost:3001/internal/nilai/M001', {
      headers: { 'X-Gateway-Secret': 'secret_palsu_123' },
    });
    expect(r.status === 404, `Expected 404, got ${r.status}`);
  });

  // ── 3. Policy - Mahasiswa Lihat Nilai Sendiri ─────────────────────────
  console.log('\n【3】 Policy: Mahasiswa Lihat Nilai');

  await test('M001 lihat nilai sendiri → ALLOW', async () => {
    const r = await req('GET', '/nilai/M001', null, tokenM001);
    expect(r.status === 200, `Expected 200, got ${r.status}: ${JSON.stringify(r.data)}`);
    expect(r.data.mahasiswa?.nim === 'M001', 'NIM tidak sesuai');
  });

  await test('M001 lihat nilai M002 → DENY (403)', async () => {
    const r = await req('GET', '/nilai/M002', null, tokenM001);
    expect(r.status === 403, `Expected 403, got ${r.status}`);
    expect(r.data.decision === 'DENY', 'Tidak ada DENY decision');
  });

  await test('M001 lihat nilai IF4001 (terdaftar) → ALLOW', async () => {
    const r = await req('GET', '/nilai/M001/IF4001', null, tokenM001);
    expect(r.status === 200, `Expected 200, got ${r.status}: ${JSON.stringify(r.data)}`);
  });

  await test('M001 lihat nilai IF4005 (tidak terdaftar) → DENY (403)', async () => {
    const r = await req('GET', '/nilai/M001/IF4005', null, tokenM001);
    expect(r.status === 403, `Expected 403, got ${r.status}`);
  });

  // ── 4. Policy - Dosen Lihat Nilai ────────────────────────────────────
  console.log('\n【4】 Policy: Dosen Lihat Nilai');

  await test('D001 lihat nilai M001/IF4001 (mengampu) → ALLOW', async () => {
    const r = await req('GET', '/nilai/M001/IF4001', null, tokenD001);
    expect(r.status === 200, `Expected 200, got ${r.status}`);
  });

  await test('D001 lihat nilai M001/IF4003 (tidak mengampu IF4003) → DENY', async () => {
    const r = await req('GET', '/nilai/M001/IF4003', null, tokenD001);
    expect(r.status === 403, `Expected 403, got ${r.status}`);
  });

  await test('D002 lihat nilai M002/IF4003 (mengampu) → ALLOW', async () => {
    const r = await req('GET', '/nilai/M002/IF4003', null, tokenD002);
    expect(r.status === 200, `Expected 200, got ${r.status}`);
  });

  await test('D002 lihat nilai M004 (D002 tidak mengampu kelas M004) → DENY', async () => {
    const r = await req('GET', '/nilai/M004', null, tokenD002);
    expect(r.status === 403, `Expected 403, got ${r.status}`);
  });

  // ── 5. Policy - Input Nilai ────────────────────────────────────────────
  console.log('\n【5】 Policy: Input Nilai');

  await test('D001 input nilai M001/IF4001 (pengampu) → ALLOW', async () => {
    const r = await req('PUT', '/nilai/M001/IF4001', { nilai_angka: 91 }, tokenD001);
    expect(r.status === 200, `Expected 200, got ${r.status}: ${JSON.stringify(r.data)}`);
    expect(r.data.nilai?.nilai_angka === 91, 'Nilai tidak terupdate');
  });

  await test('D001 input nilai M001/IF4003 (bukan pengampu) → DENY', async () => {
    const r = await req('PUT', '/nilai/M001/IF4003', { nilai_angka: 80 }, tokenD001);
    expect(r.status === 403, `Expected 403, got ${r.status}`);
  });

  await test('M001 coba input nilai sendiri → DENY', async () => {
    const r = await req('PUT', '/nilai/M001/IF4001', { nilai_angka: 100 }, tokenM001);
    expect(r.status === 403, `Expected 403, got ${r.status}`);
  });

  await test('Admin input nilai → ALLOW', async () => {
    const r = await req('PUT', '/nilai/M002/IF4001', { nilai_angka: 75 }, tokenAdmin);
    expect(r.status === 200, `Expected 200, got ${r.status}: ${JSON.stringify(r.data)}`);
  });

  await test('Input nilai dengan angka tidak valid (>100) → 400', async () => {
    const r = await req('PUT', '/nilai/M001/IF4001', { nilai_angka: 150 }, tokenD001);
    expect(r.status === 400, `Expected 400, got ${r.status}`);
  });

  // ── 6. Policy - Transkrip ─────────────────────────────────────────────
  console.log('\n【6】 Policy: Transkrip');

  await test('M001 lihat transkrip sendiri → ALLOW', async () => {
    const r = await req('GET', '/transkrip/M001', null, tokenM001);
    expect(r.status === 200, `Expected 200, got ${r.status}: ${JSON.stringify(r.data)}`);
    expect(r.data.transkrip?.ringkasan?.ipk !== undefined, 'IPK tidak ada');
    console.log(`     IPK M001: ${r.data.transkrip.ringkasan.ipk} (${r.data.transkrip.ringkasan.predikat})`);
  });

  await test('M002 lihat transkrip M001 → DENY', async () => {
    const r = await req('GET', '/transkrip/M001', null, tokenM002);
    expect(r.status === 403, `Expected 403, got ${r.status}`);
  });

  await test('D001 lihat transkrip M001 (mengampu kelas M001) → ALLOW', async () => {
    const r = await req('GET', '/transkrip/M001', null, tokenD001);
    expect(r.status === 200, `Expected 200, got ${r.status}`);
  });

  await test('D002 lihat transkrip M004 (tidak mengampu kelas M004) → DENY', async () => {
    const r = await req('GET', '/transkrip/M004', null, tokenD002);
    expect(r.status === 403, `Expected 403, got ${r.status}`);
  });

  await test('Admin lihat transkrip siapapun → ALLOW', async () => {
    const r = await req('GET', '/transkrip/M003', null, tokenAdmin);
    expect(r.status === 200, `Expected 200, got ${r.status}`);
  });

  // ── 7. Audit Log ──────────────────────────────────────────────────────
  console.log('\n【7】 Audit Log');

  await test('Admin lihat audit log → ALLOW', async () => {
    const r = await req('GET', '/audit?limit=20', null, tokenAdmin);
    expect(r.status === 200, `Expected 200, got ${r.status}`);
    expect(Array.isArray(r.data.logs), 'Logs bukan array');
    expect(r.data.logs.length > 0, 'Tidak ada log sama sekali');
    console.log(`     Total log tercatat: ${r.data.total}`);
  });

  await test('Admin filter audit log DENY saja', async () => {
    const r = await req('GET', '/audit?decision=DENY&limit=10', null, tokenAdmin);
    expect(r.status === 200, `Expected 200, got ${r.status}`);
    expect(r.data.logs.every(l => l.decision === 'DENY'), 'Ada log bukan DENY');
  });

  await test('Mahasiswa coba lihat audit log → DENY', async () => {
    const r = await req('GET', '/audit', null, tokenM001);
    expect(r.status === 403, `Expected 403, got ${r.status}`);
  });

  // ─── Hasil Akhir ───────────────────────────────────────────────────────
  console.log('\n═══════════════════════════════════════════════════════════');
  console.log(`  HASIL: ${passed} lulus ✅  |  ${failed} gagal ❌`);
  console.log('═══════════════════════════════════════════════════════════\n');

  if (failed > 0) process.exit(1);
}

main().catch(err => {
  console.error('\n[ERROR FATAL]', err.message);
  process.exit(1);
});
