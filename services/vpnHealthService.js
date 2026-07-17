/**
 * Service: VPN & WireGuard Health Check
 * Mengelola konfigurasi WireGuard, pembuatan kunci, ping test, dan riwayat kesehatan tunnel.
 */
const { exec } = require('child_process');
const crypto = require('crypto');
const axios = require('axios');
const db = require('../config/database');
const { getSetting, saveSettings } = require('../config/settingsManager');
const { logger } = require('../config/logger');

// Cache untuk riwayat cek ping (maksimal 50 log)
const pingHistory = [];
const MAX_HISTORY = 50;

// Status terkahir
let latestStatus = {
  online: false,
  latency: null,
  lastChecked: null,
  error: 'Belum pernah dicek'
};

/**
 * Generate string kunci random berformat base64 (mirip Curve25519 WireGuard)
 */
function generateWireGuardKey() {
  return crypto.randomBytes(32).toString('base64');
}

/**
 * Mendapatkan konfigurasi VPN dari settings.json dengan default values
 */
function getVPNSettings() {
  const vps_private_key = getSetting('vpn_vps_private_key', '');
  const vps_public_key = getSetting('vpn_vps_public_key', '');
  const mt_private_key = getSetting('vpn_mt_private_key', '');
  const mt_public_key = getSetting('vpn_mt_public_key', '');

  // Jika kunci kosong, generate otomatis agar user mendapat template yang valid
  const final_vps_private = vps_private_key || generateWireGuardKey();
  const final_vps_public = vps_public_key || generateWireGuardKey();
  const final_mt_private = mt_private_key || generateWireGuardKey();
  const final_mt_public = mt_public_key || generateWireGuardKey();

  // Pastikan kunci yang digenerate otomatis tersimpan jika sebelumnya kosong
  if (!vps_private_key || !vps_public_key || !mt_private_key || !mt_public_key) {
    saveSettings({
      vpn_vps_private_key: final_vps_private,
      vpn_vps_public_key: final_vps_public,
      vpn_mt_private_key: final_mt_private,
      vpn_mt_public_key: final_mt_public
    });
  }

  return {
    enabled: getSetting('vpn_enabled', false),
    vps_iface: getSetting('vpn_vps_iface', 'wg0'),
    vps_port: getSetting('vpn_vps_port', 51820),
    vps_ip: getSetting('vpn_vps_ip', '10.0.0.1/24'),
    vps_private_key: final_vps_private,
    vps_public_key: final_vps_public,
    vps_endpoint_ip: getSetting('vpn_vps_endpoint_ip', ''),
    
    mt_router_id: getSetting('vpn_mt_router_id', null),
    mt_port: getSetting('vpn_mt_port', 51820),
    mt_ip: getSetting('vpn_mt_ip', '10.0.0.2/24'),
    mt_private_key: final_mt_private,
    mt_public_key: final_mt_public,
    keepalive: getSetting('vpn_keepalive', 25),
    cron_interval: getSetting('vpn_cron_interval', 5) // dalam menit
  };
}

/**
 * Menyimpan konfigurasi VPN ke settings.json
 */
function saveVPNSettings(settings) {
  return saveSettings({
    vpn_enabled: settings.enabled === true || settings.enabled === 'true',
    vpn_vps_iface: settings.vps_iface || 'wg0',
    vpn_vps_port: parseInt(settings.vps_port) || 51820,
    vpn_vps_ip: settings.vps_ip || '10.0.0.1/24',
    vpn_vps_private_key: settings.vps_private_key,
    vpn_vps_public_key: settings.vps_public_key,
    vpn_vps_endpoint_ip: settings.vps_endpoint_ip,
    
    vpn_mt_router_id: settings.mt_router_id ? parseInt(settings.mt_router_id) : null,
    vpn_mt_port: parseInt(settings.mt_port) || 51820,
    vpn_mt_ip: settings.mt_ip || '10.0.0.2/24',
    vpn_mt_private_key: settings.mt_private_key,
    vpn_mt_public_key: settings.mt_public_key,
    vpn_keepalive: parseInt(settings.keepalive) || 25,
    vpn_cron_interval: parseInt(settings.cron_interval) || 5
  });
}

/**
 * Mendeteksi IP Publik VPS lewat ipify
 */
async function detectPublicIP() {
  try {
    const res = await axios.get('https://api.ipify.org?format=json', { timeout: 4000 });
    return res.data.ip;
  } catch (err) {
    logger.warn(`[VPN Health] Gagal mendeteksi IP Publik VPS: ${err.message}`);
    return '';
  }
}

/**
 * Mendapatkan daftar router aktif dari database
 */
function getAvailableRouters() {
  try {
    return db.prepare("SELECT id, name, host FROM routers WHERE is_active = 1").all();
  } catch (err) {
    logger.error(`[VPN Health] Gagal mengambil daftar router: ${err.message}`);
    return [];
  }
}

/**
 * Melakukan Ping test riil ke IP WireGuard MikroTik
 */
function checkPing() {
  return new Promise((resolve) => {
    const config = getVPNSettings();
    // Hilangkan subnet CIDR (misal 10.0.0.2/24 -> 10.0.0.2)
    const targetIP = config.mt_ip.split('/')[0].trim();

    if (!targetIP) {
      const errRes = {
        online: false,
        latency: null,
        error: 'IP MikroTik tidak valid',
        timestamp: new Date().toISOString()
      };
      updateLatestStatus(errRes);
      return resolve(errRes);
    }

    // Ping sebanyak 1 kali, timeout 2 detik (lintas platform Unix/Win)
    const isWin = process.platform === 'win32';
    const pingCmd = isWin 
      ? `ping -n 1 -w 2000 ${targetIP}` 
      : `ping -c 1 -W 2 ${targetIP}`;

    exec(pingCmd, (err, stdout, stderr) => {
      let online = false;
      let latency = null;
      let errorMsg = '';

      if (err) {
        online = false;
        errorMsg = 'Request Timeout (RTO) / Host Unreachable';
      } else {
        online = true;
        // Parse latency dari stdout ping
        // Unix format: time=12.4 ms atau time=12 ms
        // Windows format: waktu=12ms atau time=12ms
        const match = stdout.match(/(?:time|waktu)[=<]([\d.]+)\s*ms/i);
        if (match && match[1]) {
          latency = parseFloat(match[1]);
        } else {
          latency = 0; // fallback jika tidak terparse
        }
      }

      const result = {
        online,
        latency,
        error: online ? null : errorMsg,
        timestamp: new Date().toISOString()
      };

      updateLatestStatus(result);
      resolve(result);
    });
  });
}

/**
 * Update status terkahir dan dorong ke riwayat log
 */
function updateLatestStatus(res) {
  const previousOnline = latestStatus.online;
  
  latestStatus = {
    online: res.online,
    latency: res.latency,
    lastChecked: res.timestamp,
    error: res.error
  };

  // Masukkan ke history log
  pingHistory.unshift({
    timestamp: res.timestamp,
    online: res.online,
    latency: res.latency,
    error: res.error
  });

  // Batasi history size
  if (pingHistory.length > MAX_HISTORY) {
    pingHistory.pop();
  }

  // Jika ada perubahan status koneksi (Up -> Down atau sebaliknya), catat ke Audit Trail
  const config = getVPNSettings();
  if (config.enabled && previousOnline !== res.online && res.lastChecked !== null) {
    try {
      const auditTrailService = require('./auditTrailService');
      const action = res.online ? 'VPN_TUNNEL_UP' : 'VPN_TUNNEL_DOWN';
      const detail = res.online 
        ? `Koneksi WireGuard ke MikroTik (${config.mt_ip}) kembali TERHUBUNG (Latency: ${res.latency} ms).`
        : `Koneksi WireGuard ke MikroTik (${config.mt_ip}) TERPUTUS (Error: ${res.error}).`;
      
      auditTrailService.addLog({
        action,
        module: 'VPN_MONITORING',
        detail,
        user_id: 0, // system
        username: 'SYSTEM',
        ip_address: '127.0.0.1'
      });
      logger.info(`[VPN Health] Status VPN berubah: ${action} - ${detail}`);
    } catch (e) {
      logger.error(`[VPN Health] Gagal mencatat log audit VPN: ${e.message}`);
    }
  }
}

/**
 * Mendapatkan status terkahir
 */
function getLatestStatus() {
  const config = getVPNSettings();
  return {
    configured: config.enabled,
    mt_ip: config.mt_ip,
    ...latestStatus
  };
}

/**
 * Mendapatkan riwayat ping test
 */
function getPingHistory() {
  return pingHistory;
}

/**
 * Mendapatkan konfigurasi L2TP/IPSec dari settings.json
 */
function getL2TPSettings() {
  return {
    enabled: getSetting('vpn_l2tp_enabled', false),
    vps_ip: getSetting('vpn_l2tp_vps_ip', '192.168.10.1/24'),
    client_ip: getSetting('vpn_l2tp_client_ip', '192.168.10.2/24'),
    secret: getSetting('vpn_l2tp_secret', 'NusaDigitalL2tpSecretKey'),
    user: getSetting('vpn_l2tp_user', 'nusadigital_vpn'),
    password: getSetting('vpn_l2tp_password', 'nusadigitalpass'),
    mt_router_id: getSetting('vpn_l2tp_mt_router_id', null)
  };
}

/**
 * Menyimpan konfigurasi L2TP/IPSec ke settings.json
 */
function saveL2TPSettings(settings) {
  return saveSettings({
    vpn_l2tp_enabled: settings.enabled === true || settings.enabled === 'true',
    vpn_l2tp_vps_ip: settings.vps_ip || '192.168.10.1/24',
    vpn_l2tp_client_ip: settings.client_ip || '192.168.10.2/24',
    vpn_l2tp_secret: settings.secret || '',
    vpn_l2tp_user: settings.user || '',
    vpn_l2tp_password: settings.password || '',
    vpn_l2tp_mt_router_id: settings.mt_router_id ? parseInt(settings.mt_router_id) : null
  });
}

/**
 * Mendapatkan konfigurasi Autentikasi RADIUS dari settings.json
 */
function getRADIUSSettings() {
  return {
    auth_pap: getSetting('radius_auth_pap', true),
    auth_chap: getSetting('radius_auth_chap', true),
    auth_mschap1: getSetting('radius_auth_mschap1', true),
    auth_mschap2: getSetting('radius_auth_mschap2', true),
    single_session: getSetting('radius_single_session', true)
  };
}

/**
 * Menyimpan konfigurasi Autentikasi RADIUS ke settings.json
 */
function saveRADIUSSettings(settings) {
  return saveSettings({
    radius_auth_pap: settings.auth_pap === true || settings.auth_pap === 'true',
    radius_auth_chap: settings.auth_chap === true || settings.auth_chap === 'true',
    radius_auth_mschap1: settings.auth_mschap1 === true || settings.auth_mschap1 === 'true',
    radius_auth_mschap2: settings.auth_mschap2 === true || settings.auth_mschap2 === 'true',
    radius_single_session: settings.single_session === true || settings.single_session === 'true'
  });
}

/**
 * Mendapatkan daftar NAS RADIUS dari database
 */
function getNASList() {
  try {
    return db.prepare("SELECT * FROM radius_nas ORDER BY id DESC").all();
  } catch (err) {
    logger.error(`[VPN Health] Gagal mengambil daftar NAS: ${err.message}`);
    return [];
  }
}

/**
 * Menambahkan NAS RADIUS baru ke database
 */
function addNAS(nas) {
  try {
    const stmt = db.prepare(`
      INSERT INTO radius_nas (name, ip_nas, type, secret, status, active_sessions)
      VALUES (?, ?, ?, ?, 'offline', 0)
    `);
    const info = stmt.run(nas.name, nas.ip_nas, nas.type || 'PPPoE/Hotspot', nas.secret);
    return info.changes > 0;
  } catch (err) {
    logger.error(`[VPN Health] Gagal menambahkan NAS: ${err.message}`);
    throw err;
  }
}

/**
 * Menghapus NAS RADIUS dari database
 */
function deleteNAS(id) {
  try {
    const stmt = db.prepare("DELETE FROM radius_nas WHERE id = ?");
    const info = stmt.run(id);
    return info.changes > 0;
  } catch (err) {
    logger.error(`[VPN Health] Gagal menghapus NAS: ${err.message}`);
    throw err;
  }
}

module.exports = {
  generateWireGuardKey,
  getVPNSettings,
  saveVPNSettings,
  detectPublicIP,
  getAvailableRouters,
  checkPing,
  getLatestStatus,
  getPingHistory,
  getL2TPSettings,
  saveL2TPSettings,
  getRADIUSSettings,
  saveRADIUSSettings,
  getNASList,
  addNAS,
  deleteNAS
};
