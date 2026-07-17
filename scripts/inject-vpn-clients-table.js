const fs = require('fs');

const sql = `
// Safe migration: table for VPN Clients
try {
  db.exec(\`
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
      created_at DATETIME DEFAULT (NOW_LOCAL())
    );
  \`);
} catch(e) {
  console.error('Failed to create vpn_clients table:', e);
}
`;

let content = fs.readFileSync('config/database.js', 'utf8');
content = content.replace('module.exports = db;', sql + '\nmodule.exports = db;');
fs.writeFileSync('config/database.js', content);
