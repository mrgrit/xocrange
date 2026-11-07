// Start native Dashboard jobs only after the Manager API is ready. TLS and
// credentials use the same installation identity as its native plugin.
const fs = require('fs');
const https = require('https');
const credentials = JSON.parse(fs.readFileSync('/run/xoc-secrets/manager-api.json'));
const ca = fs.readFileSync('/run/xoc-secrets/manager-ca.pem');
const deadline = Date.now() + 120000;
async function ready() {
  return new Promise(resolve => {
    const request = https.request({hostname:'siem', port:55000,
      path:'/security/user/authenticate', method:'POST', ca,
      auth:credentials.username + ':' + credentials.password}, response => {
      response.resume(); resolve(response.statusCode === 200);
    });
    request.on('error', () => resolve(false));
    request.setTimeout(10000, () => request.destroy());
    request.end();
  });
}
(async () => {
  do {
    if (await ready()) process.exit(0);
    await new Promise(resolve => setTimeout(resolve, 2000));
  } while (Date.now() < deadline);
  console.error('Verified Manager API did not become ready; Dashboard startup stopped.');
  process.exit(1);
})();
