// gateway/index.js
// ═══════════════════════════════════════════════════════════════════════════
// API GATEWAY - Zero Trust Architecture (PEP - Policy Enforcement Point)
//
// 1. Endpoint /auth/* ditangani langsung (login, refresh, logout, service token)
// 2. Middleware Verifikasi Zero Trust:
//    - Cek header X-Device-ID terdaftar di DB (untuk user)
//    - Cek access token valid via Authorization: Bearer
//    - Panggil Policy Engine untuk allow/deny
//    - Tulis audit log untuk setiap keputusan
// 3. Setup http-proxy-middleware:
//    - /nilai*     → http://localhost:3001
//    - /kelas*     → http://localhost:3001
//    - /transkrip* → http://localhost:3002
//    - Internal call /transkrip/sinkron: generate service token & teruskan
// ═══════════════════════════════════════════════════════════════════════════

import express from 'express';
import bcrypt from 'bcrypt';
import { createProxyMiddleware, fixRequestBody } from 'http-proxy-middleware';
import db from '../db/database.js';
import { config } from '../shared/config.js';
import {
  generateAccessToken,
  generateRefreshToken,
  verifyToken,
  generateServiceToken,
} from './auth.js';
import { logAudit } from './audit.js';
import { evaluatePolicy } from './policy.js';

const app = express();

// Middleware JSON parser untuk endpoint lokal
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Request logger
app.use((req, _res, next) => {
  const ts = new Date().toISOString();
  console.log(`[GATEWAY] ${ts} | ${req.method} ${req.originalUrl || req.path}`);
  next();
});

// ─── Health Check & Informasi ─────────────────────────────────────────────

app.get('/health', (_req, res) => {
  res.json({
    service: 'Zero Trust API Gateway',
    status: 'UP',
    timestamp: new Date().toISOString(),
  });
});

app.get('/', (_req, res) => {
  res.json({
    nama: 'Zero Trust API Gateway (NIST SP 800-207)',
    arsitektur: {
      gateway: `http://localhost:${config.gateway.port} (PEP & Policy Engine)`,
      service_nilai: config.services.nilai.url,
      service_transkrip: config.services.transkrip.url,
    },
    endpoints_publik: {
      'POST /auth/login': 'Login dengan username, password, dan device_id',
      'POST /auth/refresh': 'Refresh access token',
      'POST /auth/logout': 'Revoke refresh token',
      'POST /auth/service': 'Menerbitkan service token (M2M)',
    },
    endpoints_terproteksi: {
      '/nilai*': 'Proxy ke Service Nilai (:3001)',
      '/kelas*': 'Proxy ke Service Nilai/Kelas (:3001)',
      '/transkrip*': 'Proxy ke Service Transkrip (:3002)',
    },
  });
});

// ─── 1. Endpoint /auth/* (Ditangani langsung oleh Gateway) ────────────────

app.post('/auth/login', (req, res) => {
  const { username, password, device_id } = req.body ?? {};

  if (!username || !password || !device_id) {
    logAudit({
      subject: username || 'anonymous',
      endpoint: '/auth/login',
      device: device_id || null,
      hasil: 'DENY',
      alasan: 'Field username, password, atau device_id tidak lengkap',
    });
    return res.status(400).json({ error: 'Username, password, dan device_id wajib diisi.' });
  }

  // 1. Ambil data user
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!user) {
    logAudit({
      subject: username,
      endpoint: '/auth/login',
      device: device_id,
      hasil: 'DENY',
      alasan: 'Username tidak ditemukan',
    });
    return res.status(401).json({ error: 'Kredensial tidak valid.' });
  }

  // 2. Validasi password
  const isMatch = bcrypt.compareSync(password, user.password_hash);
  if (!isMatch) {
    logAudit({
      subject: username,
      endpoint: '/auth/login',
      device: device_id,
      hasil: 'DENY',
      alasan: 'Password salah',
    });
    return res.status(401).json({ error: 'Kredensial tidak valid.' });
  }

  // 3. Verifikasi Device ID (Zero Trust Device Verification)
  if (user.device_id !== device_id) {
    logAudit({
      subject: username,
      endpoint: '/auth/login',
      device: device_id,
      hasil: 'DENY',
      alasan: `Device ID tidak cocok dengan yang terdaftar (${user.device_id})`,
    });
    return res.status(403).json({
      error: 'Akses ditolak: Device ID tidak terdaftar atau tidak cocok dengan akun ini.',
      registered_device_required: true,
    });
  }

  // 4. Terbitkan access & refresh token
  const accessToken = generateAccessToken(user);
  const refreshToken = generateRefreshToken(user);

  logAudit({
    subject: username,
    endpoint: '/auth/login',
    device: device_id,
    hasil: 'ALLOW',
    alasan: 'Autentikasi dan verifikasi device sukses',
  });

  return res.json({
    message: 'Login berhasil.',
    access_token: accessToken,
    refresh_token: refreshToken,
    token_type: 'Bearer',
    expires_in: '10m',
    user: {
      id: user.id,
      username: user.username,
      role: user.role,
      nim: user.nim,
      device_id: user.device_id,
    },
  });
});

app.post('/auth/refresh', (req, res) => {
  const token = req.body?.refresh_token || req.body?.refreshToken;

  if (!token) {
    logAudit({
      endpoint: '/auth/refresh',
      hasil: 'DENY',
      alasan: 'Refresh token tidak disertakan',
    });
    return res.status(400).json({ error: 'Refresh token wajib disertakan.' });
  }

  const payload = verifyToken(token);
  if (!payload || payload.type !== 'refresh') {
    logAudit({
      endpoint: '/auth/refresh',
      hasil: 'DENY',
      alasan: 'Refresh token tidak valid atau expired',
    });
    return res.status(401).json({ error: 'Refresh token tidak valid atau telah kedaluwarsa.' });
  }

  const tokenRecord = db.prepare('SELECT * FROM refresh_tokens WHERE token = ?').get(token);
  if (!tokenRecord) {
    logAudit({
      subject: payload.sub,
      endpoint: '/auth/refresh',
      hasil: 'DENY',
      alasan: 'Refresh token tidak ditemukan di database',
    });
    return res.status(401).json({ error: 'Refresh token tidak dikenali.' });
  }

  if (tokenRecord.revoked === 1) {
    logAudit({
      subject: payload.sub,
      endpoint: '/auth/refresh',
      hasil: 'DENY',
      alasan: 'Refresh token telah dicabut (revoked)',
    });
    return res.status(401).json({ error: 'Refresh token telah dicabut (revoked).' });
  }

  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(tokenRecord.user_id);
  if (!user) {
    return res.status(404).json({ error: 'User tidak ditemukan.' });
  }

  const newAccessToken = generateAccessToken(user);

  logAudit({
    subject: user.username,
    endpoint: '/auth/refresh',
    device: user.device_id,
    hasil: 'ALLOW',
    alasan: 'Penerbitan access token baru dari refresh token',
  });

  return res.json({
    message: 'Access token berhasil diperbarui.',
    access_token: newAccessToken,
    token_type: 'Bearer',
    expires_in: '10m',
  });
});

app.post('/auth/logout', (req, res) => {
  const token = req.body?.refresh_token || req.body?.refreshToken;

  if (!token) {
    return res.status(400).json({ error: 'Refresh token wajib disertakan untuk logout.' });
  }

  const tokenRecord = db.prepare('SELECT * FROM refresh_tokens WHERE token = ?').get(token);
  if (!tokenRecord) {
    logAudit({
      endpoint: '/auth/logout',
      hasil: 'DENY',
      alasan: 'Refresh token tidak ditemukan saat logout',
    });
    return res.status(404).json({ error: 'Refresh token tidak ditemukan.' });
  }

  db.prepare('UPDATE refresh_tokens SET revoked = 1 WHERE token = ?').run(token);

  logAudit({
    subject: tokenRecord.user_id,
    endpoint: '/auth/logout',
    hasil: 'ALLOW',
    alasan: 'Refresh token berhasil dicabut',
  });

  return res.json({
    message: 'Logout berhasil, refresh token telah dicabut.',
    revoked: true,
  });
});

app.post('/auth/service', (req, res) => {
  const { client_id, client_secret, service_name } = req.body ?? {};

  if (!client_id || !client_secret) {
    logAudit({
      endpoint: '/auth/service',
      hasil: 'DENY',
      alasan: 'client_id atau client_secret tidak disertakan',
    });
    return res.status(400).json({ error: 'client_id dan client_secret wajib diisi.' });
  }

  const isValid =
    client_id === config.serviceAuth.clientId &&
    client_secret === config.serviceAuth.clientSecret;

  if (!isValid) {
    logAudit({
      subject: service_name || client_id,
      endpoint: '/auth/service',
      hasil: 'DENY',
      alasan: 'Client ID atau Client Secret tidak valid',
    });
    return res.status(401).json({ error: 'Client ID atau Client Secret tidak valid.' });
  }

  const serviceName = service_name || client_id;
  const serviceToken = generateServiceToken(serviceName);

  logAudit({
    subject: serviceName,
    endpoint: '/auth/service',
    hasil: 'ALLOW',
    alasan: 'Service token berhasil diterbitkan',
  });

  return res.json({
    message: 'Service token berhasil diterbitkan.',
    service_token: serviceToken,
    token_type: 'Bearer',
    expires_in: '5m',
    role: 'service',
  });
});

// ─── 2. Middleware Verifikasi Zero Trust (PEP) ─────────────────────────────

export function verifyZeroTrust(req, res, next) {
  const endpoint = req.originalUrl || req.path;
  const deviceIdHeader = req.headers['x-device-id'] || null;

  // 1. Cek access token valid via Authorization: Bearer
  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    logAudit({
      subject: 'anonymous',
      endpoint,
      device: deviceIdHeader,
      hasil: 'DENY',
      alasan: 'Header Authorization Bearer token tidak disertakan atau format salah',
    });
    return res.status(401).json({
      error: 'Akses ditolak: Token autentikasi diperlukan (Bearer <token>).',
      allow: false,
    });
  }

  const token = authHeader.slice(7).trim();
  const decoded = verifyToken(token);
  if (!decoded) {
    logAudit({
      subject: 'anonymous',
      endpoint,
      device: deviceIdHeader,
      hasil: 'DENY',
      alasan: 'Token JWT tidak valid atau sudah kedaluwarsa',
    });
    return res.status(401).json({
      error: 'Akses ditolak: Token tidak valid atau sudah kedaluwarsa.',
      allow: false,
    });
  }

  // Simpan info user ke req
  req.user = decoded;
  const isService = decoded.role === 'service';

  // 2. Cek header X-Device-ID terdaftar di DB (khusus untuk user)
  if (!isService) {
    if (!deviceIdHeader) {
      logAudit({
        subject: decoded.sub,
        endpoint,
        device: null,
        hasil: 'DENY',
        alasan: 'Header X-Device-ID wajib disertakan untuk user',
      });
      return res.status(403).json({
        error: 'Akses ditolak: Header X-Device-ID wajib disertakan.',
        allow: false,
      });
    }

    const userDb = db.prepare('SELECT * FROM users WHERE id = ?').get(decoded.sub);
    if (!userDb) {
      logAudit({
        subject: decoded.sub,
        endpoint,
        device: deviceIdHeader,
        hasil: 'DENY',
        alasan: 'User tidak ditemukan di database',
      });
      return res.status(401).json({ error: 'User tidak ditemukan.', allow: false });
    }

    if (userDb.device_id !== deviceIdHeader) {
      logAudit({
        subject: userDb.username,
        endpoint,
        device: deviceIdHeader,
        hasil: 'DENY',
        alasan: `Device ID '${deviceIdHeader}' tidak cocok dengan device terdaftar '${userDb.device_id}'`,
      });
      return res.status(403).json({
        error: 'Akses ditolak: Device ID tidak terdaftar atau tidak cocok dengan akun ini.',
        allow: false,
      });
    }

    if (!req.user.nim && userDb.nim) {
      req.user.nim = userDb.nim;
    }
  }

  // 3. Panggil Policy Engine untuk allow/deny
  const decision = evaluatePolicy(req);

  // 4. Tulis audit log untuk setiap keputusan
  logAudit({
    subject: decoded.sub || 'unknown',
    endpoint,
    device: deviceIdHeader,
    hasil: decision.allow ? 'ALLOW' : 'DENY',
    alasan: decision.reason,
  });

  if (!decision.allow) {
    return res.status(403).json({
      error: 'Akses ditolak oleh Policy Engine.',
      reason: decision.reason,
      allow: false,
    });
  }

  // Simpan verified token untuk diteruskan ke proxy
  req.verifiedToken = token;
  next();
}

// ─── 3. Setup http-proxy-middleware ───────────────────────────────────────

/**
 * Proxy untuk Service Nilai: /nilai* → http://localhost:3001
 * Menambahkan header X-Gateway-Secret dan meneruskan Authorization: Bearer <token>
 */
const nilaiProxy = createProxyMiddleware({
  target: config.services.nilai.url,
  changeOrigin: true,
  pathFilter: '/nilai',
  on: {
    proxyReq: (proxyReq, req) => {
      proxyReq.setHeader('x-gateway-secret', config.gateway.secret);
      if (req.verifiedToken) {
        proxyReq.setHeader('authorization', `Bearer ${req.verifiedToken}`);
      }
      fixRequestBody(proxyReq, req);
    },
    error: (err, req, res) => {
      console.error('[PROXY NILAI ERROR]', err.message);
      if (!res.headersSent) {
        res.status(502).json({ error: 'Service Nilai tidak dapat dihubungi.' });
      }
    },
  },
});

/**
 * Proxy untuk Kelas: /kelas* → http://localhost:3001
 */
const kelasProxy = createProxyMiddleware({
  target: config.services.nilai.url,
  changeOrigin: true,
  pathFilter: '/kelas',
  on: {
    proxyReq: (proxyReq, req) => {
      proxyReq.setHeader('x-gateway-secret', config.gateway.secret);
      if (req.verifiedToken) {
        proxyReq.setHeader('authorization', `Bearer ${req.verifiedToken}`);
      }
      fixRequestBody(proxyReq, req);
    },
    error: (err, req, res) => {
      console.error('[PROXY KELAS ERROR]', err.message);
      if (!res.headersSent) {
        res.status(502).json({ error: 'Service Nilai (Kelas) tidak dapat dihubungi.' });
      }
    },
  },
});

/**
 * Proxy untuk Service Transkrip: /transkrip* → http://localhost:3002
 * Untuk internal call ke /transkrip/sinkron: gateway generate service token dan teruskan
 */
const transkripProxy = createProxyMiddleware({
  target: config.services.transkrip.url,
  changeOrigin: true,
  pathFilter: '/transkrip',
  on: {
    proxyReq: (proxyReq, req) => {
      proxyReq.setHeader('x-gateway-secret', config.gateway.secret);

      const isSyncEndpoint =
        req.path === '/sinkron' ||
        req.originalUrl?.includes('/transkrip/sinkron');

      if (isSyncEndpoint) {
        // Gateway generate service token dan teruskan
        const serviceToken = generateServiceToken('gateway-internal');
        proxyReq.setHeader('authorization', `Bearer ${serviceToken}`);
      } else if (req.verifiedToken) {
        proxyReq.setHeader('authorization', `Bearer ${req.verifiedToken}`);
      }

      fixRequestBody(proxyReq, req);
    },
    error: (err, req, res) => {
      console.error('[PROXY TRANSKRIP ERROR]', err.message);
      if (!res.headersSent) {
        res.status(502).json({ error: 'Service Transkrip tidak dapat dihubungi.' });
      }
    },
  },
});

// Pasang middleware verifikasi Zero Trust untuk endpoint terproteksi
app.use(['/nilai', '/kelas', '/transkrip'], verifyZeroTrust);

// Pasang proxy routes
app.use(nilaiProxy);
app.use(kelasProxy);
app.use(transkripProxy);

// ─── 404 & Error Handler ──────────────────────────────────────────────────

app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint tidak ditemukan.', path: req.path });
});

app.use((err, _req, res, _next) => {
  console.error('[GATEWAY ERROR]', err);
  if (!res.headersSent) {
    res.status(500).json({ error: 'Internal server error di gateway.' });
  }
});

// ─── Start Server ─────────────────────────────────────────────────────────

app.listen(config.gateway.port, () => {
  console.log('');
  console.log('╔══════════════════════════════════════════════════════╗');
  console.log('║       ZERO TRUST API GATEWAY - PEP & PROXY           ║');
  console.log('╠══════════════════════════════════════════════════════╣');
  console.log(`║  Port      : ${config.gateway.port}                                 ║`);
  console.log(`║  DB        : better-sqlite3                          ║`);
  console.log(`║  Nilai Svc : ${config.services.nilai.url.padEnd(40)}║`);
  console.log(`║  Trskp Svc : ${config.services.transkrip.url.padEnd(40)}║`);
  console.log('║  Prinsip   : Never Trust, Always Verify              ║');
  console.log('╚══════════════════════════════════════════════════════╝');
  console.log('');
});
