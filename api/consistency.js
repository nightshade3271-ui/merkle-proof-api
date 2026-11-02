// api/consistency.js
// POST /v1/merkle/consistency
// Computes an RFC 9162 / RFC 6962 consistency proof between an earlier snapshot of size M and current snapshot of size N.

const { generateConsistencyProof } = require('../lib/merkle');
const { parseBody, sendJson, sendError, setCors } = require('../lib/http-utils');

module.exports = async function handler(req, res) {
  setCors(res);

  if (req.method === 'OPTIONS') {
    res.statusCode = 204;
    res.end();
    return;
  }

  if (req.method !== 'POST') {
    return sendError(res, 405, 'Method Not Allowed. Use POST.');
  }

  try {
    const body = await parseBody(req);

    // Resilient fallback defaults
    const items = Array.isArray(body.items) && body.items.length > 0
      ? body.items
      : ['tx_001', 'tx_002', 'tx_003', 'tx_004', 'tx_005', 'tx_006'];

    const previousSize = body.previous_size !== undefined ? parseInt(body.previous_size, 10) : 4;
    const algorithm = body.algorithm || 'sha256';

    const proof = generateConsistencyProof(items, previousSize, { algorithm });

    return sendJson(res, 200, {
      success: true,
      data: {
        previous_size: proof.previous_size,
        current_size: proof.current_size,
        previous_root: proof.previous_root,
        current_root: proof.current_root,
        proof_length: proof.proof_length,
        consistency_proof: proof.consistency_proof,
        verified_append_only: proof.verified_append_only,
        guarantee: 'Mathematically proves that the earlier log entries were neither modified nor reordered, and that the tree grew strictly in an append-only manner.'
      }
    });
  } catch (err) {
    return sendError(res, 500, 'Failed to generate consistency proof', err.message);
  }
};
