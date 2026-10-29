// shared/db.js
// Modul database terpusat menggunakan @libsql/client (file SQLite lokal)
// API-nya async/await — compatible dengan Node.js v26 tanpa native compilation.

import { createClient } from '@libsql/client';
import { config } from './config.js';
import { pathToFileURL } from 'url';

let _client = null;

/**
 * Mengembalikan instance libsql client singleton.
 * URL menggunakan format file:// untuk database lokal.
 */
export function getDb() {
  if (!_client) {
    const fileUrl = pathToFileURL(config.db.path).href;
    _client = createClient({ url: fileUrl });
  }
  return _client;
}
