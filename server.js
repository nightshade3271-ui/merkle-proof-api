// server.js
// Standalone HTTP Server and Local Testing Harness for MerkleProof API
// Port: 3017

const http = require('http');
const fs = require('fs');
const path = require('path');

const treeHandler = require('./api/tree');
const proofHandler = require('./api/proof');
const verifyHandler = require('./api/verify');
const consistencyHandler = require('./api/consistency');
const indexHandler = require('./api/index');

const PORT = process.env.PORT || 3017;

const server = http.createServer((req, res) => {
  const parsedUrl = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  let pathname = parsedUrl.pathname.replace(/\/$/, '') || '/';

  // Handle static landing page
  if (pathname === '/' || pathname === '/index.html') {
    const htmlPath = path.join(__dirname, 'public', 'index.html');
    if (fs.existsSync(htmlPath)) {
      res.statusCode = 200;
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      fs.createReadStream(htmlPath).pipe(res);
      return;
    }
  }

  // Handle logo asset
  if (pathname === '/logo.png') {
    const pubPath = path.join(__dirname, 'public', 'logo.png');
    const rootPath = path.join(__dirname, 'logo.png');
    const targetFile = fs.existsSync(pubPath) ? pubPath : (fs.existsSync(rootPath) ? rootPath : null);
    if (targetFile) {
      res.statusCode = 200;
      res.setHeader('Content-Type', 'image/png');
      fs.createReadStream(targetFile).pipe(res);
      return;
    }
  }

  // Dual routing for external endpoints and Vercel internal /api/ rewrites
  if (pathname === '' || pathname === '/health' || pathname === '/api/index' || pathname === '/api/health') {
    return indexHandler(req, res);
  }
  if (pathname === '/v1/merkle/tree' || pathname === '/api/tree') {
    return treeHandler(req, res);
  }
  if (pathname === '/v1/merkle/proof' || pathname === '/api/proof') {
    return proofHandler(req, res);
  }
  if (pathname === '/v1/merkle/verify' || pathname === '/api/verify') {
    return verifyHandler(req, res);
  }
  if (pathname === '/v1/merkle/consistency' || pathname === '/api/consistency') {
    return consistencyHandler(req, res);
  }

  // 404 Fallback
  res.statusCode = 404;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.end(JSON.stringify({
    success: false,
    error: `Route not found: ${pathname}`,
    available_endpoints: [
      'POST /v1/merkle/tree',
      'POST /v1/merkle/proof',
      'POST /v1/merkle/verify',
      'POST /v1/merkle/consistency',
      'GET /health'
    ]
  }, null, 2));
});

if (require.main === module) {
  server.listen(PORT, () => {
    console.log(`[MerkleProof API] Listening on http://localhost:${PORT}`);
    console.log(`[MerkleProof API] Health Check: http://localhost:${PORT}/health`);
    console.log(`[MerkleProof API] Interactive Portal: http://localhost:${PORT}/index.html`);
  });
}

module.exports = server;
