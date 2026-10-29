import Database from 'better-sqlite3';
import { fileURLToPath } from 'url';
import path from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'database.sqlite');

const db = new Database(DB_PATH);

// Konfigurasi SQLite
db.pragma('foreign_keys = ON');
db.pragma('journal_mode = WAL');

/**
 * Inisialisasi skema tabel database
 */
export function initDatabase() {
  db.exec(`
    -- Tabel Users
    CREATE TABLE IF NOT EXISTS users (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      username      TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role          TEXT NOT NULL CHECK(role IN ('mahasiswa', 'dosen', 'admin')),
      nim           TEXT UNIQUE,
      device_id     TEXT NOT NULL
    );

    -- Tabel Kelas
    CREATE TABLE IF NOT EXISTS kelas (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      nama          TEXT NOT NULL,
      dosen_id      INTEGER NOT NULL,
      FOREIGN KEY (dosen_id) REFERENCES users(id) ON DELETE CASCADE
    );

    -- Tabel Nilai
    CREATE TABLE IF NOT EXISTS nilai (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      mahasiswa_id  INTEGER NOT NULL,
      kelas_id      INTEGER NOT NULL,
      nilai         REAL NOT NULL,
      final         INTEGER NOT NULL DEFAULT 0 CHECK(final IN (0, 1)),
      FOREIGN KEY (mahasiswa_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY (kelas_id) REFERENCES kelas(id) ON DELETE CASCADE,
      UNIQUE(mahasiswa_id, kelas_id)
    );

    -- Tabel Refresh Tokens
    CREATE TABLE IF NOT EXISTS refresh_tokens (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id       INTEGER NOT NULL,
      token         TEXT UNIQUE NOT NULL,
      revoked       INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN (0, 1)),
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    -- Tabel Audit Log
    CREATE TABLE IF NOT EXISTS audit_log (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      waktu         TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),
      subject       TEXT,
      endpoint      TEXT,
      device        TEXT,
      hasil         TEXT NOT NULL,
      alasan        TEXT
    );

    -- Tabel Transkrip (Pemisahan Arsip Akademik Resmi)
    CREATE TABLE IF NOT EXISTS transkrip (
      id              INTEGER PRIMARY KEY AUTOINCREMENT,
      mahasiswa_id    INTEGER NOT NULL,
      nim             TEXT NOT NULL,
      nama_mahasiswa  TEXT NOT NULL,
      kelas_id        INTEGER NOT NULL,
      nama_kelas      TEXT NOT NULL,
      nilai_angka     REAL NOT NULL,
      nilai_huruf     TEXT NOT NULL,
      bobot           REAL NOT NULL,
      disinkron_pada  TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),
      FOREIGN KEY (mahasiswa_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY (kelas_id) REFERENCES kelas(id) ON DELETE CASCADE,
      UNIQUE(mahasiswa_id, kelas_id)
    );
  `);
}

// Jalankan pembuatan tabel
initDatabase();

export { db };
export default db;
