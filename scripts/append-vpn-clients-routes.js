const fs = require('fs');

const routeCode = `
// ==========================================
// VPN Clients
// ==========================================
const vpnClientSvc = require('../services/vpnClientService');

router.get('/vpn-clients', requireAdminSession, restrictToAdmin, async (req, res) => {
  try {
    const clients = vpnClientSvc.getAllClients();
    res.render('admin/vpn_clients', {
      title: 'VPN Clients',
      activePage: 'vpn_clients',
      user: req.session.user,
      sidebarSections: require('../services/sidebarMenuService').getSidebarSections(req.session),
      clients: clients,
      vpsEndpointIp: require('../services/vpnHealthService').getVPNSettings().vps_endpoint_ip || ''
    });
  } catch (error) {
    console.error(error);
    res.status(500).send('Server Error');
  }
});

router.post('/vpn-clients/create', requireAdminSession, restrictToAdmin, async (req, res) => {
  try {
    vpnClientSvc.addClient(req.body);
    res.redirect('/admin/vpn-clients');
  } catch (error) {
    console.error(error);
    res.status(500).send('Server Error');
  }
});

router.post('/vpn-clients/delete/:id', requireAdminSession, restrictToAdmin, async (req, res) => {
  try {
    vpnClientSvc.deleteClient(req.params.id);
    res.redirect('/admin/vpn-clients');
  } catch (error) {
    console.error(error);
    res.status(500).send('Server Error');
  }
});
`;

let content = fs.readFileSync('routes/adminPortal.js', 'utf8');
content = content.replace('module.exports = router;', routeCode + '\nmodule.exports = router;');
fs.writeFileSync('routes/adminPortal.js', content);
