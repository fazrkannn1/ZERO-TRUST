// shared/initDb.js
// Script inisialisasi database — jalankan SEKALI sebelum memulai server.
// Menggunakan @libsql/client (async API).
//
// Jalankan: node shared/initDb.js

import { getDb } from './db.js';

const db = getDb();

console.log('🗄️  Menginisialisasi database Zero Trust Akademik...');

// ─── DDL: Buat Tabel ──────────────────────────────────────────────────────

const tables = [
  `CREATE TABLE IF NOT EXISTS users (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    nim         TEXT    UNIQUE NOT NULL,
    nama        TEXT    NOT NULL,
    role        TEXT    NOT NULL,
    password    TEXT    NOT NULL,
    is_active   INTEGER NOT NULL DEFAULT 1,
    created_at  TEXT    NOT NULL DEFAULT (datetime('now','localtime'))
  )`,

  `CREATE TABLE IF NOT EXISTS mata_kuliah (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    kode        TEXT    UNIQUE NOT NULL,
    nama        TEXT    NOT NULL,
    sks         INTEGER NOT NULL DEFAULT 3,
    dosen_nim   TEXT    NOT NULL,
    semester    TEXT    NOT NULL
  )`,

  `CREATE TABLE IF NOT EXISTS enrollment (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    mahasiswa_nim TEXT    NOT NULL,
    kode_mk       TEXT    NOT NULL,
    UNIQUE(mahasiswa_nim, kode_mk)
  )`,

  `CREATE TABLE IF NOT EXISTS nilai (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    mahasiswa_nim TEXT    NOT NULL,
    kode_mk       TEXT    NOT NULL,
    nilai_angka   REAL    NOT NULL,
    semester      TEXT    NOT NULL,
    input_oleh    TEXT    NOT NULL,
    updated_at    TEXT    NOT NULL DEFAULT (datetime('now','localtime')),
    UNIQUE(mahasiswa_nim, kode_mk)
  )`,

  `CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TEXT    NOT NULL DEFAULT (datetime('now','localtime')),
    actor_nim   TEXT,
    actor_role  TEXT,
    action      TEXT    NOT NULL,
    resource    TEXT    NOT NULL,
    target_nim  TEXT,
    kode_mk     TEXT,
    decision    TEXT    NOT NULL,
    reason      TEXT    NOT NULL,
    ip_address  TEXT,
    status_code INTEGER
  )`,
];

for (const sql of tables) {
  await db.execute(sql);
}

// ─── SEED: Data Awal ──────────────────────────────────────────────────────

// Helper upsert
async function upsertUser(nim, nama, role, password) {
  await db.execute({
    sql: `INSERT OR IGNORE INTO users (nim, nama, role, password) VALUES (?, ?, ?, ?)`,
    args: [nim, nama, role, password],
  });
}

async function upsertMK(kode, nama, sks, dosen_nim, semester) {
  await db.execute({
    sql: `INSERT OR IGNORE INTO mata_kuliah (kode, nama, sks, dosen_nim, semester) VALUES (?, ?, ?, ?, ?)`,
    args: [kode, nama, sks, dosen_nim, semester],
  });
}

async function upsertEnrollment(mahasiswa_nim, kode_mk) {
  await db.execute({
    sql: `INSERT OR IGNORE INTO enrollment (mahasiswa_nim, kode_mk) VALUES (?, ?)`,
    args: [mahasiswa_nim, kode_mk],
  });
}

async function upsertNilai(mahasiswa_nim, kode_mk, nilai_angka, semester, input_oleh) {
  await db.execute({
    sql: `INSERT OR IGNORE INTO nilai (mahasiswa_nim, kode_mk, nilai_angka, semester, input_oleh) VALUES (?, ?, ?, ?, ?)`,
    args: [mahasiswa_nim, kode_mk, nilai_angka, semester, input_oleh],
  });
}

// ── Users ──────────────────────────────────────────────────────────────────
await upsertUser('ADMIN001', 'Administrator Sistem', 'admin',     'password_admin');
await upsertUser('D001',     'Dr. Andi Prasetyo',    'dosen',     'password_dosen1');
await upsertUser('D002',     'Prof. Budi Santoso',   'dosen',     'password_dosen2');
await upsertUser('M001',     'Siti Rahayu',          'mahasiswa', 'password_mhs1');
await upsertUser('M002',     'Budi Hartono',         'mahasiswa', 'password_mhs2');
await upsertUser('M003',     'Citra Dewi',           'mahasiswa', 'password_mhs3');
await upsertUser('M004',     'Dani Setiawan',        'mahasiswa', 'password_mhs4');

// ── Mata Kuliah ─────────────────────────────────────────────────────────────
await upsertMK('IF4001', 'Keamanan Informasi',  3, 'D001', 'Ganjil 2024/2025');
await upsertMK('IF4002', 'Jaringan Komputer',   3, 'D001', 'Ganjil 2024/2025');
await upsertMK('IF4003', 'Basis Data Lanjut',   3, 'D002', 'Ganjil 2024/2025');
await upsertMK('IF4004', 'Pemrograman Web',     3, 'D002', 'Ganjil 2024/2025');
await upsertMK('IF4005', 'Kecerdasan Buatan',   3, 'D001', 'Genap 2024/2025');

// ── Enrollment ──────────────────────────────────────────────────────────────
// M001 - Siti
await upsertEnrollment('M001', 'IF4001');
await upsertEnrollment('M001', 'IF4002');
await upsertEnrollment('M001', 'IF4003');
// M002 - Budi
await upsertEnrollment('M002', 'IF4001');
await upsertEnrollment('M002', 'IF4003');
await upsertEnrollment('M002', 'IF4004');
// M003 - Citra
await upsertEnrollment('M003', 'IF4002');
await upsertEnrollment('M003', 'IF4004');
await upsertEnrollment('M003', 'IF4005');
// M004 - Dani
await upsertEnrollment('M004', 'IF4001');
await upsertEnrollment('M004', 'IF4002');

// ── Nilai ────────────────────────────────────────────────────────────────────
await upsertNilai('M001', 'IF4001', 88,  'Ganjil 2024/2025', 'D001');
await upsertNilai('M001', 'IF4002', 76,  'Ganjil 2024/2025', 'D001');
await upsertNilai('M001', 'IF4003', 82,  'Ganjil 2024/2025', 'D002');
await upsertNilai('M002', 'IF4001', 70,  'Ganjil 2024/2025', 'D001');
await upsertNilai('M002', 'IF4003', 65,  'Ganjil 2024/2025', 'D002');
await upsertNilai('M002', 'IF4004', 90,  'Ganjil 2024/2025', 'D002');
await upsertNilai('M003', 'IF4002', 55,  'Ganjil 2024/2025', 'D001');
await upsertNilai('M003', 'IF4004', 78,  'Ganjil 2024/2025', 'D002');
await upsertNilai('M004', 'IF4001', 92,  'Ganjil 2024/2025', 'D001');
await upsertNilai('M004', 'IF4002', 85,  'Ganjil 2024/2025', 'D001');

console.log('✅ Database berhasil diinisialisasi!');
console.log('\n📋 Data Akun untuk Testing:');
console.log('   NIM       | Nama                | Role       | Password');
console.log('   ----------|---------------------|------------|------------------');
console.log('   ADMIN001  | Administrator       | admin      | password_admin');
console.log('   D001      | Dr. Andi Prasetyo   | dosen      | password_dosen1');
console.log('   D002      | Prof. Budi Santoso  | dosen      | password_dosen2');
console.log('   M001      | Siti Rahayu         | mahasiswa  | password_mhs1');
console.log('   M002      | Budi Hartono        | mahasiswa  | password_mhs2');
console.log('   M003      | Citra Dewi          | mahasiswa  | password_mhs3');
console.log('   M004      | Dani Setiawan       | mahasiswa  | password_mhs4');
console.log('\n🚀 Jalankan: node gateway/index.js | node service-nilai/index.js | node service-transkrip/index.js');
