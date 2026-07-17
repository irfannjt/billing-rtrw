const db = require('better-sqlite3')('database/billing.db');
const { execSync } = require('child_process');
const { logger } = require('../config/logger');

function generateWireGuardKey() {
  try {
    return execSync('wg genkey').toString().trim();
  } catch (err) {
    if (logger && typeof logger.warn === 'function') {
      logger.warn('wg command failed, generating random key instead.');
    }
    const crypto = require('crypto');
    return crypto.randomBytes(32).toString('base64');
  }
}

function generatePublicKey(privateKey) {
  try {
    return execSync(`echo "${privateKey}" | wg pubkey`).toString().trim();
  } catch (err) {
    return '';
  }
}

function getAllClients() {
  return db.prepare("SELECT * FROM vpn_clients ORDER BY id DESC").all();
}

function getClientById(id) {
  return db.prepare("SELECT * FROM vpn_clients WHERE id = ?").get(id);
}

function addClient(data) {
  const vpn_type = data.vpn_type || 'WireGuard';
  let vps_private_key = data.vps_private_key;
  let vps_public_key = data.vps_public_key;
  let mt_private_key = data.mt_private_key;
  let mt_public_key = data.mt_public_key;

  if (vpn_type === 'L2TP') {
    // For L2TP:
    // mt_private_key is L2TP Username (defaults to clean name)
    // vps_private_key is L2TP CHAP Password
    // vps_public_key is IPsec PSK
    // mt_public_key is empty/unused
    mt_private_key = data.l2tp_username || data.mt_private_key || data.name.toLowerCase().replace(/[^a-z0-9]/g, '_');
    vps_private_key = data.l2tp_password || data.vps_private_key || require('crypto').randomBytes(8).toString('hex');
    vps_public_key = data.ipsec_psk || data.vps_public_key || 'salfanet-psk';
    mt_public_key = '';
  } else {
    // WireGuard
    vps_private_key = vps_private_key || generateWireGuardKey();
    vps_public_key = vps_public_key || generatePublicKey(vps_private_key);
    mt_private_key = mt_private_key || generateWireGuardKey();
    mt_public_key = mt_public_key || generatePublicKey(mt_private_key);
  }

  const stmt = db.prepare(`
    INSERT INTO vpn_clients (
      name, vpn_type, vps_ip, mt_ip, vps_port, 
      vps_private_key, vps_public_key, mt_private_key, mt_public_key, 
      vps_endpoint_ip, keepalive, status
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active')
  `);
  
  const info = stmt.run(
    data.name,
    vpn_type,
    data.vps_ip,
    data.mt_ip,
    parseInt(data.vps_port) || (vpn_type === 'L2TP' ? 1701 : 51820),
    vps_private_key,
    vps_public_key,
    mt_private_key,
    mt_public_key,
    data.vps_endpoint_ip || '',
    parseInt(data.keepalive) || (vpn_type === 'L2TP' ? 30 : 25)
  );

  const clientId = info.lastInsertRowid;

  // Execute system integration commands if running as root or on VPS
  if (vpn_type === 'L2TP') {
    try {
      const cleanIp = data.mt_ip.split('/')[0].trim();
      execSync(`/usr/local/bin/salfanet-l2tp-peer add "${mt_private_key}" "${vps_private_key}" "${cleanIp}"`, { stdio: 'ignore' });
      if (logger && typeof logger.info === 'function') {
        logger.info(`Successfully synchronized L2TP client ${mt_private_key} to VPS system.`);
      }
    } catch (err) {
      if (logger && typeof logger.warn === 'function') {
        logger.warn(`Failed to sync L2TP client to VPS system: ${err.message}. This is normal if not running on VPS as root.`);
      }
    }
  } else if (vpn_type === 'WireGuard') {
    try {
      const cleanIp = data.mt_ip.split('/')[0].trim();
      const wgIface = 'wg0'; 
      execSync(`wg set ${wgIface} peer "${mt_public_key}" allowed-ips "${cleanIp}/32"`, { stdio: 'ignore' });
      if (logger && typeof logger.info === 'function') {
        logger.info(`Successfully added WireGuard peer ${mt_public_key} to VPS interface ${wgIface}.`);
      }
    } catch (err) {
      if (logger && typeof logger.warn === 'function') {
        logger.warn(`Failed to sync WireGuard peer to VPS system: ${err.message}. This is normal if wg is not configured.`);
      }
    }
  }
  
  return clientId;
}

function deleteClient(id) {
  const client = getClientById(id);
  if (!client) return false;

  const stmt = db.prepare("DELETE FROM vpn_clients WHERE id = ?");
  const info = stmt.run(id);

  if (info.changes > 0) {
    if (client.vpn_type === 'L2TP') {
      try {
        execSync(`/usr/local/bin/salfanet-l2tp-peer remove "${client.mt_private_key}"`, { stdio: 'ignore' });
        if (logger && typeof logger.info === 'function') {
          logger.info(`Successfully removed L2TP client ${client.mt_private_key} from VPS system.`);
        }
      } catch (err) {
        if (logger && typeof logger.warn === 'function') {
          logger.warn(`Failed to remove L2TP client from VPS system: ${err.message}.`);
        }
      }
    } else if (client.vpn_type === 'WireGuard') {
      try {
        const wgIface = 'wg0';
        execSync(`wg set ${wgIface} peer "${client.mt_public_key}" remove`, { stdio: 'ignore' });
        if (logger && typeof logger.info === 'function') {
          logger.info(`Successfully removed WireGuard peer ${client.mt_public_key} from VPS interface ${wgIface}.`);
        }
      } catch (err) {
        if (logger && typeof logger.warn === 'function') {
          logger.warn(`Failed to remove WireGuard peer from VPS system: ${err.message}.`);
        }
      }
    }
    return true;
  }
  return false;
}

module.exports = {
  generateWireGuardKey,
  generatePublicKey,
  getAllClients,
  getClientById,
  addClient,
  deleteClient
};
