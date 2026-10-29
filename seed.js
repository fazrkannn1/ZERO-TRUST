import bcrypt from 'bcrypt';
import db from './db/database.js';

const SALT_ROUNDS = 10;

async function seed() {
  console.log('🌱 Memulai proses seeding database...\n');

  // Bersihkan data lama jika ada (idempotent)
  db.exec(`
    DELETE FROM transkrip;
    DELETE FROM audit_log;
    DELETE FROM refresh_tokens;
    DELETE FROM nilai;
    DELETE FROM kelas;
    DELETE FROM users;
    DELETE FROM sqlite_sequence;
  `);

  // Data akun yang akan di-seed
  const usersToSeed = [
    // 1 Admin
    {
      username: 'admin',
      password: 'adminPassword123!',
      role: 'admin',
      nim: 'ADM-001',
      device_id: 'DEV-ADMIN-WIN-01',
    },
    // 2 Dosen
    {
      username: 'dosen_andi',
      password: 'dosenPassword123!',
      role: 'dosen',
      nim: 'DSN-101',
      device_id: 'DEV-DSN-MAC-01',
    },
    {
      username: 'dosen_budi',
      password: 'dosenPassword123!',
      role: 'dosen',
      nim: 'DSN-102',
      device_id: 'DEV-DSN-LNX-02',
    },
    // 3 Mahasiswa
    {
      username: 'mhs_citra',
      password: 'mhsPassword123!',
      role: 'mahasiswa',
      nim: '2024001',
      device_id: 'DEV-MHS-AND-01',
    },
    {
      username: 'mhs_dani',
      password: 'mhsPassword123!',
      role: 'mahasiswa',
      nim: '2024002',
      device_id: 'DEV-MHS-IOS-02',
    },
    {
      username: 'mhs_eka',
      password: 'mhsPassword123!',
      role: 'mahasiswa',
      nim: '2024003',
      device_id: 'DEV-MHS-WIN-03',
    },
  ];

  // Prepared statement untuk insert user
  const insertUser = db.prepare(`
    INSERT INTO users (username, password_hash, role, nim, device_id)
    VALUES (?, ?, ?, ?, ?)
  `);

  // Insert user dalam transaksi
  const seededUsers = [];
  const insertUsersTx = db.transaction((users) => {
    for (const u of users) {
      const password_hash = bcrypt.hashSync(u.password, SALT_ROUNDS);
      const info = insertUser.run(u.username, password_hash, u.role, u.nim, u.device_id);
      seededUsers.push({
        id: info.lastInsertRowid,
        username: u.username,
        role: u.role,
        nim: u.nim,
        device_id: u.device_id,
        plain_password: u.password,
      });
    }
  });

  insertUsersTx(usersToSeed);

  // Ambil ID dosen untuk relasi kelas
  const dosenAndi = seededUsers.find((u) => u.username === 'dosen_andi');
  const dosenBudi = seededUsers.find((u) => u.username === 'dosen_budi');

  // Insert 2 kelas diampu dosen berbeda
  const insertKelas = db.prepare(`
    INSERT INTO kelas (nama, dosen_id)
    VALUES (?, ?)
  `);

  const seededKelas = [];
  const insertKelasTx = db.transaction(() => {
    const k1 = insertKelas.run('Keamanan Sistem & Zero Trust', dosenAndi.id);
    seededKelas.push({ id: k1.lastInsertRowid, nama: 'Keamanan Sistem & Zero Trust', dosen: dosenAndi.username });

    const k2 = insertKelas.run('Kriptografi & Keamanan Jaringan', dosenBudi.id);
    seededKelas.push({ id: k2.lastInsertRowid, nama: 'Kriptografi & Keamanan Jaringan', dosen: dosenBudi.username });
  });

  insertKelasTx();

  // Ambil ID mahasiswa untuk data sampel nilai
  const mhsCitra = seededUsers.find((u) => u.username === 'mhs_citra');
  const mhsDani = seededUsers.find((u) => u.username === 'mhs_dani');
  const mhsEka = seededUsers.find((u) => u.username === 'mhs_eka');

  // Seed sample nilai awal
  const insertNilai = db.prepare(`
    INSERT INTO nilai (mahasiswa_id, kelas_id, nilai, final)
    VALUES (?, ?, ?, ?)
  `);

  const insertNilaiTx = db.transaction(() => {
    // Kelas 1 (Dosen Andi)
    insertNilai.run(mhsCitra.id, seededKelas[0].id, 88.5, 1);
    insertNilai.run(mhsDani.id, seededKelas[0].id, 76.0, 0);

    // Kelas 2 (Dosen Budi)
    insertNilai.run(mhsEka.id, seededKelas[1].id, 91.0, 1);
    insertNilai.run(mhsCitra.id, seededKelas[1].id, 84.0, 0);
  });

  insertNilaiTx();

  // Seed data awal ke tabel transkrip untuk nilai yang berstatus final = 1
  const insertTranskrip = db.prepare(`
    INSERT INTO transkrip (mahasiswa_id, nim, nama_mahasiswa, kelas_id, nama_kelas, nilai_angka, nilai_huruf, bobot)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const insertTranskripTx = db.transaction(() => {
    insertTranskrip.run(mhsCitra.id, mhsCitra.nim, mhsCitra.username, seededKelas[0].id, seededKelas[0].nama, 88.5, 'A', 4.0);
    insertTranskrip.run(mhsEka.id, mhsEka.nim, mhsEka.username, seededKelas[1].id, seededKelas[1].nama, 91.0, 'A', 4.0);
  });

  insertTranskripTx();

  console.log('✅ Seeding berhasil selesai!\n');

  console.log('═══════════════════════════════════════════════════════════════════════════════════════════');
  console.log('                                DAFTAR AKUN TERDAFTAR                                      ');
  console.log('═══════════════════════════════════════════════════════════════════════════════════════════');
  console.table(
    seededUsers.map((u) => ({
      ID: u.id,
      Username: u.username,
      Role: u.role,
      NIM: u.nim,
      'Device ID': u.device_id,
      'Password (Plain)': u.plain_password,
    }))
  );

  console.log('═══════════════════════════════════════════════════════════════════════════════════════════');
  console.log('                                DAFTAR KELAS & DOSEN                                       ');
  console.log('═══════════════════════════════════════════════════════════════════════════════════════════');
  console.table(
    seededKelas.map((k) => ({
      ID: k.id,
      'Nama Kelas': k.nama,
      'Dosen Pengampu': k.dosen,
    }))
  );
}

seed().catch((err) => {
  console.error('❌ Terjadi kesalahan saat seeding:', err);
  process.exit(1);
});
