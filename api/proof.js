// api/proof.js
// POST /v1/merkle/proof
// Generates an RFC 9162 binary inclusion proof (audit path) for a target item or index.

const { generateInclusionProof, buildMerkleTree } = require('../lib/merkle');
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
      : ['event_log_alpha', 'event_log_beta', 'event_log_gamma', 'event_log_delta'];

    const target = body.target !== undefined ? body.target : 0;
    const algorithm = body.algorithm || 'sha256';
    const isAlreadyHashed = Boolean(body.is_already_hashed);
    const duplicateOdd = Boolean(body.duplicate_odd);

    const proof = generateInclusionProof(items, target, {
      algorithm,
      isAlreadyHashed,
      duplicateOdd
    });

    return sendJson(res, 200, {
      success: true,
      data: {
        target_index: proof.target_index,
        leaf_hash: proof.leaf_hash,
        root_hash: proof.root_hash,
        algorithm: proof.algorithm,
        proof_length: proof.proof_length,
        audit_path: proof.audit_path,
        verification_guidance: 'Submit this audit_path along with the leaf_hash or item to /v1/merkle/verify to mathematically prove inclusion against the root_hash in O(log N) time.'
      }
    });
  } catch (err) {
    return sendError(res, 500, 'Failed to generate inclusion proof', err.message);
  }
};

