// shared/config.js
// Konfigurasi terpusat - dibaca dari environment variables
// Sesuai prinsip Zero Trust: konfigurasi sensitif tidak di-hardcode

import { readFileSync } from 'fs';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));

// Parse .env manual (tanpa dotenv dependency)
function loadEnv() {
  try {
    const envPath = resolve(__dirname, '../.env');
    const content = readFileSync(envPath, 'utf-8');
    content.split('\n').forEach(line => {
      line = line.trim();
      if (!line || line.startsWith('#')) return;
      const idx = line.indexOf('=');
      if (idx === -1) return;
      const key = line.slice(0, idx).trim();
      const val = line.slice(idx + 1).trim();
      if (!process.env[key]) process.env[key] = val;
    });
  } catch {
    console.warn('[Config] File .env tidak ditemukan, menggunakan environment variables sistem.');
  }
}

loadEnv();

export const config = {
  jwt: {
    secret:     process.env.JWT_SECRET     || 'default_jwt_secret_GANTI_INI',
    expiresIn:  '2h',
  },
  gateway: {
    secret: process.env.GATEWAY_SECRET || 'default_gateway_secret_GANTI_INI',
    port:   parseInt(process.env.GATEWAY_PORT  || '3000', 10),
  },
  services: {
    nilai: {
      url:  process.env.NILAI_SERVICE_URL  || 'http://localhost:3001',
      port: parseInt(process.env.NILAI_PORT || '3001', 10),
    },
    transkrip: {
      url:  process.env.TRANSKRIP_SERVICE_URL || 'http://localhost:3002',
      port: parseInt(process.env.TRANSKRIP_PORT || '3002', 10),
    },
  },
  serviceAuth: {
    clientId: process.env.SERVICE_CLIENT_ID || 'gateway-service-client',
    clientSecret: process.env.SERVICE_CLIENT_SECRET || 'ServiceSecretKey2024!',
  },
  accessHours: {
    start: process.env.ACCESS_HOURS_START || '07:00',
    end:   process.env.ACCESS_HOURS_END   || '21:00',
  },
  db: {
    path: resolve(__dirname, process.env.DB_PATH?.replace('./shared/', '') || 'database.sqlite'),
  },
};
