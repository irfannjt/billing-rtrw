const db = require('better-sqlite3')('database/billing.db');

try {
  db.exec(`
    CREATE TABLE IF NOT EXISTS vpn_clients (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      vpn_type TEXT DEFAULT 'WireGuard',
      vps_ip TEXT NOT NULL,
      mt_ip TEXT NOT NULL,
      vps_port INTEGER NOT NULL,
      vps_private_key TEXT,
      vps_public_key TEXT,
      mt_private_key TEXT,
      mt_public_key TEXT,
      vps_endpoint_ip TEXT,
      keepalive INTEGER DEFAULT 25,
      status TEXT DEFAULT 'pending',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
  `);
  console.log("Table vpn_clients created successfully");
} catch(e) {
  console.error("Error creating table:", e);
}
