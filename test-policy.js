import { evaluatePolicy, isWithinAccessHours } from './gateway/policy.js';
import db from './db/database.js';

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

console.log('═══════════════════════════════════════════════════════════════════════');
console.log('              PENGUJIAN MODUL POLICY ENGINE (Zero Trust)               ');
console.log('═══════════════════════════════════════════════════════════════════════\n');

// Ambil data users dari DB
const admin = db.prepare("SELECT * FROM users WHERE role = 'admin'").get();
const dosenAndi = db.prepare("SELECT * FROM users WHERE username = 'dosen_andi'").get();
const dosenBudi = db.prepare("SELECT * FROM users WHERE username = 'dosen_budi'").get();
const mhsCitra = db.prepare("SELECT * FROM users WHERE username = 'mhs_citra'").get();
const mhsDani = db.prepare("SELECT * FROM users WHERE username = 'mhs_dani'").get();

// Kelas 1 diampu dosenAndi, Kelas 2 diampu dosenBudi
const kelas1 = db.prepare("SELECT * FROM kelas WHERE dosen_id = ?").get(dosenAndi.id);
const kelas2 = db.prepare("SELECT * FROM kelas WHERE dosen_id = ?").get(dosenBudi.id);

// Pastikan ada sampel nilai non-final dan final untuk kelas 1
db.prepare("UPDATE nilai SET final = 0 WHERE id = (SELECT id FROM nilai WHERE kelas_id = ? LIMIT 1)").run(kelas1.id);
db.prepare("UPDATE nilai SET final = 1 WHERE id = (SELECT id FROM nilai WHERE kelas_id = ? AND id != (SELECT id FROM nilai WHERE kelas_id = ? AND final = 0 LIMIT 1) LIMIT 1)").run(kelas1.id, kelas1.id);

let nilaiNonFinal = db.prepare("SELECT * FROM nilai WHERE kelas_id = ? AND final = 0 LIMIT 1").get(kelas1.id);
let nilaiFinal = db.prepare("SELECT * FROM nilai WHERE kelas_id = ? AND final = 1 LIMIT 1").get(kelas1.id);

// Setup waktu: siang jam 10:00 (dalam jam akses) dan malam jam 23:00 (di luar jam akses)
const waktuSiang = new Date();
waktuSiang.setHours(10, 0, 0, 0);

const waktuMalam = new Date();
waktuMalam.setHours(23, 0, 0, 0);

// ─── 1. Endpoint /auth/* ──────────────────────────────────────────────────
console.log('【1】 Aturan: Endpoint /auth/*');
const r1 = evaluatePolicy({ method: 'POST', path: '/auth/login' });
assert(r1.allow === true, 'POST /auth/login harus allow');

const r2 = evaluatePolicy({ method: 'POST', path: '/auth/refresh' });
assert(r2.allow === true, 'POST /auth/refresh harus allow');

// ─── 2. GET /nilai ────────────────────────────────────────────────────────
console.log('\n【2】 Aturan: GET /nilai');
// Mahasiswa: allow jika query NIM == NIM token
const rMhsOk = evaluatePolicy({
  method: 'GET',
  path: '/nilai',
  query: { nim: mhsCitra.nim },
  user: { sub: mhsCitra.id, role: 'mahasiswa', nim: mhsCitra.nim },
});
assert(rMhsOk.allow === true, 'Mahasiswa lihat nilai sendiri dengan NIM cocok harus allow');

const rMhsDeny = evaluatePolicy({
  method: 'GET',
  path: '/nilai',
  query: { nim: mhsDani.nim },
  user: { sub: mhsCitra.id, role: 'mahasiswa', nim: mhsCitra.nim },
});
assert(rMhsDeny.allow === false, 'Mahasiswa lihat nilai NIM lain harus deny');

const rMhsNoQuery = evaluatePolicy({
  method: 'GET',
  path: '/nilai',
  query: {},
  user: { sub: mhsCitra.id, role: 'mahasiswa', nim: mhsCitra.nim },
});
assert(rMhsNoQuery.allow === false, 'Mahasiswa tanpa query nim harus deny');

// Dosen: allow jika kelas yang diminta miliknya
const rDosenKelasOk = evaluatePolicy({
  method: 'GET',
  path: '/nilai',
  query: { kelas_id: kelas1.id },
  user: { sub: dosenAndi.id, role: 'dosen' },
});
assert(rDosenKelasOk.allow === true, 'Dosen lihat nilai kelas yang diampu harus allow');

const rDosenKelasBukanMilik = evaluatePolicy({
  method: 'GET',
  path: '/nilai',
  query: { kelas_id: kelas2.id },
  user: { sub: dosenAndi.id, role: 'dosen' },
});
assert(rDosenKelasBukanMilik.allow === false, 'Dosen lihat nilai kelas bukan miliknya harus deny');

// ─── 3. PUT /nilai/:id ────────────────────────────────────────────────────
console.log('\n【3】 Aturan: PUT /nilai/:id');
// Dosen: allow jika kelas diampu, nilai belum final, jam 07:00-21:00
const rPutOk = evaluatePolicy(
  {
    method: 'PUT',
    path: `/nilai/${nilaiNonFinal.id}`,
    params: { id: nilaiNonFinal.id },
    user: { sub: dosenAndi.id, role: 'dosen' },
  },
  waktuSiang
);
assert(rPutOk.allow === true, 'Dosen ubah nilai miliknya belum final di jam akses harus allow');

// Dosen ubah nilai yang sudah final
const rPutFinal = evaluatePolicy(
  {
    method: 'PUT',
    path: `/nilai/${nilaiFinal.id}`,
    params: { id: nilaiFinal.id },
    user: { sub: dosenAndi.id, role: 'dosen' },
  },
  waktuSiang
);
assert(rPutFinal.allow === false, 'Dosen ubah nilai yang sudah final harus deny');

// Dosen ubah nilai di luar jam kerja (23:00)
const rPutMalam = evaluatePolicy(
  {
    method: 'PUT',
    path: `/nilai/${nilaiNonFinal.id}`,
    params: { id: nilaiNonFinal.id },
    user: { sub: dosenAndi.id, role: 'dosen' },
  },
  waktuMalam
);
assert(rPutMalam.allow === false, 'Dosen ubah nilai di luar jam akses (23:00) harus deny');

// Mahasiswa coba ubah nilai
const rPutMhs = evaluatePolicy(
  {
    method: 'PUT',
    path: `/nilai/${nilaiNonFinal.id}`,
    params: { id: nilaiNonFinal.id },
    user: { sub: mhsCitra.id, role: 'mahasiswa' },
  },
  waktuSiang
);
assert(rPutMhs.allow === false, 'Mahasiswa ubah nilai harus deny');

// ─── 4. POST /kelas/:id/finalisasi ────────────────────────────────────────
console.log('\n【4】 Aturan: POST /kelas/:id/finalisasi');
// Dosen: allow jika kelas diampu, dalam jam akses
const rFinOk = evaluatePolicy(
  {
    method: 'POST',
    path: `/kelas/${kelas1.id}/finalisasi`,
    params: { id: kelas1.id },
    user: { sub: dosenAndi.id, role: 'dosen' },
  },
  waktuSiang
);
assert(rFinOk.allow === true, 'Dosen finalisasi kelas miliknya dalam jam akses harus allow');

// Dosen finalisasi kelas milik dosen lain
const rFinBukanMilik = evaluatePolicy(
  {
    method: 'POST',
    path: `/kelas/${kelas2.id}/finalisasi`,
    params: { id: kelas2.id },
    user: { sub: dosenAndi.id, role: 'dosen' },
  },
  waktuSiang
);
assert(rFinBukanMilik.allow === false, 'Dosen finalisasi kelas milik dosen lain harus deny');

// Dosen finalisasi di luar jam kerja
const rFinMalam = evaluatePolicy(
  {
    method: 'POST',
    path: `/kelas/${kelas1.id}/finalisasi`,
    params: { id: kelas1.id },
    user: { sub: dosenAndi.id, role: 'dosen' },
  },
  waktuMalam
);
assert(rFinMalam.allow === false, 'Dosen finalisasi di luar jam akses harus deny');

// ─── 5. GET /transkrip/:nim ───────────────────────────────────────────────
console.log('\n【5】 Aturan: GET /transkrip/:nim');
// Mahasiswa: allow jika :nim == NIM di token
const rTransMhsOk = evaluatePolicy({
  method: 'GET',
  path: `/transkrip/${mhsCitra.nim}`,
  params: { nim: mhsCitra.nim },
  user: { sub: mhsCitra.id, role: 'mahasiswa', nim: mhsCitra.nim },
});
assert(rTransMhsOk.allow === true, 'Mahasiswa lihat transkrip sendiri harus allow');

const rTransMhsDeny = evaluatePolicy({
  method: 'GET',
  path: `/transkrip/${mhsDani.nim}`,
  params: { nim: mhsDani.nim },
  user: { sub: mhsCitra.id, role: 'mahasiswa', nim: mhsCitra.nim },
});
assert(rTransMhsDeny.allow === false, 'Mahasiswa lihat transkrip mahasiswa lain harus deny');

// Admin: allow semua
const rTransAdmin = evaluatePolicy({
  method: 'GET',
  path: `/transkrip/${mhsCitra.nim}`,
  params: { nim: mhsCitra.nim },
  user: { sub: admin.id, role: 'admin' },
});
assert(rTransAdmin.allow === true, 'Admin lihat transkrip siapapun harus allow');

// ─── 6. POST /transkrip/sinkron ───────────────────────────────────────────
console.log('\n【6】 Aturan: POST /transkrip/sinkron');
// Hanya allow jika role === 'service'
const rSyncService = evaluatePolicy({
  method: 'POST',
  path: '/transkrip/sinkron',
  user: { sub: 'service-worker', role: 'service' },
});
assert(rSyncService.allow === true, 'Role service akses POST /transkrip/sinkron harus allow');

const rSyncAdmin = evaluatePolicy({
  method: 'POST',
  path: '/transkrip/sinkron',
  user: { sub: admin.id, role: 'admin' },
});
assert(rSyncAdmin.allow === false, 'Role admin akses POST /transkrip/sinkron harus deny');

const rSyncDosen = evaluatePolicy({
  method: 'POST',
  path: '/transkrip/sinkron',
  user: { sub: dosenAndi.id, role: 'dosen' },
});
assert(rSyncDosen.allow === false, 'Role dosen akses POST /transkrip/sinkron harus deny');

// ─── Ringkasan ────────────────────────────────────────────────────────────
console.log('\n═══════════════════════════════════════════════════════════════════════');
console.log(` HASIL PENGUJIAN: ${passed} LULUS ✅  |  ${failed} GAGAL ❌`);
console.log('═══════════════════════════════════════════════════════════════════════\n');

if (failed > 0) process.exit(1);
