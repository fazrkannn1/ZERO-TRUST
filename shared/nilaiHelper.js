// shared/nilaiHelper.js
// Fungsi helper untuk konversi nilai angka → huruf dan bobot
// (Menggantikan generated column SQLite yang tidak didukung libsql)

/**
 * Konversi nilai angka ke huruf (A, A-, B+, dst)
 * @param {number} angka - Nilai 0-100
 * @returns {string}
 */
export function toHuruf(angka) {
  if (angka >= 85) return 'A';
  if (angka >= 80) return 'A-';
  if (angka >= 75) return 'B+';
  if (angka >= 70) return 'B';
  if (angka >= 65) return 'B-';
  if (angka >= 60) return 'C+';
  if (angka >= 55) return 'C';
  if (angka >= 40) return 'D';
  return 'E';
}

/**
 * Konversi nilai angka ke bobot (4.0 scale)
 * @param {number} angka - Nilai 0-100
 * @returns {number}
 */
export function toBobot(angka) {
  if (angka >= 85) return 4.0;
  if (angka >= 80) return 3.7;
  if (angka >= 75) return 3.3;
  if (angka >= 70) return 3.0;
  if (angka >= 65) return 2.7;
  if (angka >= 60) return 2.3;
  if (angka >= 55) return 2.0;
  if (angka >= 40) return 1.0;
  return 0.0;
}

/**
 * Hitung predikat IPK
 * @param {number} ipk
 * @returns {string}
 */
export function toPredikat(ipk) {
  if (ipk >= 3.51) return 'Dengan Pujian (Cum Laude)';
  if (ipk >= 3.01) return 'Sangat Memuaskan';
  if (ipk >= 2.76) return 'Memuaskan';
  if (ipk >= 2.00) return 'Cukup';
  return 'Kurang';
}
