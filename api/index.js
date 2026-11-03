// api/index.js
// GET /health, /api/health, /api/index
// Cryptographic Merkle tree engine health, RFC compliance specifications, and system metadata

const { getEngineMetadata } = require('../lib/merkle');
const { sendJson, setCors } = require('../lib/http-utils');

module.exports = async function handler(req, res) {
  setCors(res);

  if (req.method === 'OPTIONS') {
    res.statusCode = 204;
    res.end();
    return;
  }

  const metadata = getEngineMetadata();

  return sendJson(res, 200, {
    status: 'healthy',
    service: 'MerkleProof Cryptographic Binary Tree & Proof Engine API',
    version: '1.0.0',
    timestamp: new Date().toISOString(),
    uptime_seconds: process.uptime(),
    cryptography: {
      standard: 'RFC 9162 / RFC 6962 Binary Merkle Trees',
      hash_functions: ['SHA-256', 'SHA-512', 'SHA-384'],
      domain_separation: {
        leaf_prefix: '0x00',
        internal_prefix: '0x01'
      },
      proof_types: ['Inclusion Proof (Audit Path)', 'Consistency Proof (Append-Only)'],
      comparison: 'Constant-Time timingSafeEqual'
    },
    metadata,
    endpoints: [
      { method: 'POST', path: '/v1/merkle/tree', description: 'Builds binary Merkle tree and returns root hash' },
      { method: 'POST', path: '/v1/merkle/proof', description: 'Generates inclusion proof (audit path) for specific item or index' },
      { method: 'POST', path: '/v1/merkle/verify', description: 'Verifies an inclusion proof against an expected root hash in constant time' },
      { method: 'POST', path: '/v1/merkle/consistency', description: 'Generates RFC 9162 consistency proof between two log snapshots' },
      { method: 'GET',  path: '/health', description: 'System health, cryptographic specifications, and engine status' }
    ]
  });
};

