const fs = require('fs');

let content = fs.readFileSync('services/sidebarMenuService.js', 'utf8');

const menuDef = `  { key: 'vpn_clients', section: 'system', href: '/admin/vpn-clients', icon: 'bi bi-shield-check', labelDefault: 'VPN Clients', roles: ['admin'], activePages: ['vpn_clients'] },\n`;
content = content.replace(/({\s*key:\s*'vpn_health'[^}]+},)/, `$1\n${menuDef}`);

const stateDef = `  vpn_clients: STATE_VISIBLE,\n`;
content = content.replace(/(vpn_health:\s*STATE_VISIBLE,)/, `$1\n${stateDef}`);

fs.writeFileSync('services/sidebarMenuService.js', content);
