# Sistem Nilai Akademik — Zero Trust Architecture (NIST SP 800-207)

Proyek ini mengimplementasikan arsitektur keamanan **Zero Trust (NIST SP 800-207)** pada sistem backend nilai dan transkrip akademik menggunakan Node.js, Express, better-sqlite3, dan JSON Web Token (JWT).

---

## 🏛️ Arsitektur Sistem (NIST SP 800-207)

```
[ Klien / Mahasiswa / Dosen / Admin ]
                 │
                 ▼ (Hanya port 3000 yang terbuka untuk publik)
     ┌────────────────────────────────────────────────────────┐
     │           API GATEWAY (Port 3000)                      │
     │  - PEP (Policy Enforcement Point)                      │
     │  - Verifikasi Device ID & Autentikasi JWT              │
     │  - Policy Engine (PDP - Policy Decision Point)         │
     │  - Logging Audit Log ke Database                       │
     └───────────┬────────────────────────────────┬───────────┘
                 │ (Internal Network)             │ (Internal Network)
                 │ Header: X-Gateway-Secret       │ Header: X-Gateway-Secret
                 │ Header: Authorization Bearer   │ Header: Authorization Bearer
                 ▼                                ▼
┌─────────────────────────────────┐   ┌─────────────────────────────────┐
│     SERVICE NILAI (Port 3001)   │   │   SERVICE TRANSKRIP (Port 3002) │
│ - Proteksi X-Gateway-Secret     │   │ - Proteksi X-Gateway-Secret     │
│ - Verifikasi ulang JWT          │   │ - Verifikasi ulang JWT          │
│ - Defense in Depth (Cek Final)  │   │ - Sinkronisasi M2M (Role:svc)   │
└────────────────┬────────────────┘   └────────────────┬────────────────┘
                 │                                     │
                 └──────────────────┬──────────────────┘
                                    ▼
                 ┌─────────────────────────────────────┐
                 │       DATABASE (SQLite)             │
                 │ users, kelas, nilai, transkrip,     │
                 │ audit_log, refresh_tokens           │
                 └─────────────────────────────────────┘
```

---

## 🚀 Panduan Instalasi & Menjalankan

### 1. Install Dependencies
```bash
npm install
```

### 2. Inisialisasi & Seeding Database
Eksekusi script `seed.js` untuk membuat tabel dan mengisi akun awal:
```bash
node seed.js
```

### 3. Menjalankan Layanan (Buka 3 Terminal Terpisah)
Layanan harus dijalankan secara terpisah untuk mencerminkan isolasi microservices:

* **Terminal 1 — API Gateway (PEP & Policy Engine):**
  ```bash
  node gateway/index.js
  ```
  *(Berjalan di port 3000 — satu-satunya pintu masuk klien)*

* **Terminal 2 — Service Nilai (Internal Service):**
  ```bash
  node service-nilai/index.js
  ```
  *(Berjalan di port 3001)*

* **Terminal 3 — Service Transkrip (Internal Service):**
  ```bash
  node service-transkrip/index.js
  ```
  *(Berjalan di port 3002)*

---

## 🧪 Menjalankan Pengujian (Testing)

Untuk menguji seluruh fungsionalitas dan kepatuhan Zero Trust, gunakan perintah:

### A. Pengujian Komprehensif (Unit & Integrasi E2E)
```bash
npm test
```
Perintah ini akan menjalankan 4 suite pengujian otomatis:
1. `node test-policy.js` — Evaluasi 20 skenario PDP (Policy Engine)
2. `node test-service-nilai.js` — Uji proteksi internal port 3001
3. `node test-service-transkrip.js` — Uji proteksi internal port 3002 & sinkronisasi
4. `node test-e2e.js` — Pengujian integrasi menyeluruh via API Gateway

### B. Pengujian via Shell / cURL
```bash
bash test.sh
```

> **Catatan Penting Mengenai `test.js`:**
> File `test.js` lama tidak menyertakan `device_id` pada login dan tidak mengirim header `X-Device-ID`, sehingga akan ditolak gateway (401/403). Gunakan `node test-e2e.js` atau `npm test`.

---

## 👥 Data Akun Default (Hasil Seeding)

Semua password default: `adminPassword123!`, `dosenPassword123!`, `mhsPassword123!`.

| Role | Username | Password | NIM / Identitas | Registered Device ID |
| :--- | :--- | :--- | :--- | :--- |
| **Admin** | `admin` | `adminPassword123!` | ADM-001 | `DEV-ADMIN-WIN-01` |
| **Dosen** | `dosen_andi` | `dosenPassword123!` | DSN-101 | `DEV-DSN-MAC-01` |
| **Dosen** | `dosen_budi` | `dosenPassword123!` | DSN-102 | `DEV-DSN-LNX-02` |
| **Mahasiswa** | `mhs_citra` | `mhsPassword123!` | 2024001 | `DEV-MHS-AND-01` |
| **Mahasiswa** | `mhs_dani` | `mhsPassword123!` | 2024002 | `DEV-MHS-IOS-02` |
| **Mahasiswa** | `mhs_eko` | `mhsPassword123!` | 2024003 | `DEV-MHS-AND-03` |

### Data Kelas:
- **Kelas 1**: *Kriptografi & Keamanan Data* — Diampu oleh: `dosen_andi`
- **Kelas 2**: *Jaringan Komputer Lanjut* — Diampu oleh: `dosen_budi`

---

## 📋 Matriks Endpoint & Hak Akses

Semua request non-auth ke Gateway (Port 3000) wajib menyertakan:
- Header `Authorization: Bearer <access_token>`
- Header `X-Device-ID: <device_id_terdaftar>`

| Method | Endpoint | Target Proxy | Role / Pengguna yang Diizinkan | Ketentuan Tambahan |
| :--- | :--- | :--- | :--- | :--- |
| `POST` | `/auth/login` | Lokal Gateway | Publik | Wajib `username`, `password`, dan `device_id` valid di DB |
| `POST` | `/auth/refresh` | Lokal Gateway | User terautentikasi | Refresh token belum dicabut/revoked |
| `POST` | `/auth/logout` | Lokal Gateway | User terautentikasi | Mencabut refresh token di DB |
| `POST` | `/auth/service` | Lokal Gateway | M2M / Service | Menggunakan client credentials yang sah |
| `GET` | `/nilai?nim=:nim` | `service-nilai` (:3001) | Mahasiswa, Admin | Mahasiswa hanya boleh melihat nilai dengan NIM miliknya |
| `GET` | `/nilai?kelas_id=:id`| `service-nilai` (:3001) | Dosen, Admin | Dosen hanya boleh melihat kelas yang ia ampu |
| `PUT` | `/nilai/:id` | `service-nilai` (:3001) | Dosen, Admin | Dosen pengampu, nilai belum final, dalam jam 07:00–21:00 |
| `POST` | `/kelas/:id/finalisasi`| `service-nilai` (:3001) | Dosen, Admin | Dosen pengampu, dalam jam akses 07:00–21:00. Memicu sinkronisasi |
| `GET` | `/transkrip/:nim` | `service-transkrip` (:3002) | Mahasiswa, Admin | Mahasiswa hanya boleh melihat NIM miliknya. Admin bebas |
| `POST` | `/transkrip/sinkron` | `service-transkrip` (:3002) | **Service Only** (`role: 'service'`) | Digunakan untuk sinkronisasi otomatis antar-layanan (M2M) |

---

## 🔒 Penerapan Prinsip Zero Trust (NIST SP 800-207)

Berikut adalah pemetaan prinsip NIST SP 800-207 langsung ke dalam baris kode:

### 1. Never Trust, Always Verify (Verifikasi Per-Request Secara Menyeluruh)
Setiap permintaan dievaluasi ulang secara dinamis tanpa mengasumsikan sesi aman:
- **Validasi Device ID & Token**: [gateway/index.js](file:///d:/KULIAH/KEAMANAN I/ZERO TRUST/gateway/index.js#L180-L240)
  Gateway memeriksa apakah `X-Device-ID` yang dikirim benar-benar terdaftar untuk pengguna bersangkutan di tabel database.
- **Verifikasi Ulang di Setiap Microservice ("Assume Breach")**: 
  - [service-nilai/index.js](file:///d:/KULIAH/KEAMANAN I/ZERO TRUST/service-nilai/index.js#L30-L75)
  - [service-transkrip/index.js](file:///d:/KULIAH/KEAMANAN I/ZERO TRUST/service-transkrip/index.js#L30-L75)
  Layanan backend **tidak mempercayai gateway secara buta**. Setiap service memeriksa `X-Gateway-Secret` DAN memverifikasi ulang tanda tangan JWT sebelum melayani data.

### 2. Policy-Based Access Control Berbasis Database (PDP & PEP)
Keputusan akses tidak hanya mengandalkan claim role di JWT, melainkan mengecek kepemilikan data aktual di database:
- **Evaluasi Kepemilikan Mahasiswa & Dosen**: [gateway/policy.js](file:///d:/KULIAH/KEAMANAN I/ZERO TRUST/gateway/policy.js#L85-L165)
  Mahasiswa hanya boleh membaca nilai jika `query.nim === user.nim`. Dosen hanya boleh mengakses kelas jika `kelas.dosen_id === user.id`.

### 3. Dynamic & Temporal Context (Pembatasan Waktu Operasional)
- **Jam Akses Input Nilai & Finalisasi (07:00 - 21:00)**: [gateway/policy.js](file:///d:/KULIAH/KEAMANAN I/ZERO TRUST/gateway/policy.js#L20-L32) dan [gateway/policy.js](file:///d:/KULIAH/KEAMANAN I/ZERO TRUST/gateway/policy.js#L180-L210)
  Dosen dilarang mengubah nilai atau melakukan finalisasi di luar jam operasional yang ditentukan.

### 4. Defense in Depth (Pertahanan Berlapis)
- **Pengecekan Status Final di Service Nilai**: [service-nilai/index.js](file:///d:/KULIAH/KEAMANAN I/ZERO TRUST/service-nilai/index.js#L110-L130)
  Bahkan jika lolos dari gateway, Service Nilai secara independen memeriksa kembali di database apakah nilai sudah berstatus `final = 1`. Jika sudah final, pembaruan tetap ditolak.

### 5. Least Privilege & Machine-to-Machine (M2M) Isolation
- **Proteksi Endpoint Sinkronisasi Transkrip**: [gateway/policy.js](file:///d:/KULIAH/KEAMANAN I/ZERO TRUST/gateway/policy.js#L280-L300) dan [service-transkrip/index.js](file:///d:/KULIAH/KEAMANAN I/ZERO TRUST/service-transkrip/index.js#L120-L140)
  Endpoint `/transkrip/sinkron` secara ketat menolak user biasa (bahkan Admin sekalipun) dan hanya menerima token dengan claim `role === 'service'`.

### 6. Comprehensive Audit Logging (Pencatatan Tanpa Pengecualian)
- **Audit Logger**: [gateway/audit.js](file:///d:/KULIAH/KEAMANAN I/ZERO TRUST/gateway/audit.js#L10-L35)
- **Pencatatan Setiap Keputusan (ALLOW & DENY)**: [gateway/index.js](file:///d:/KULIAH/KEAMANAN I/ZERO TRUST/gateway/index.js#L230-L260)
  Setiap request dicatat ke tabel `audit_log` (mencakup waktu, subject, endpoint, device ID, hasil ALLOW/DENY, dan alasan penolakan).
