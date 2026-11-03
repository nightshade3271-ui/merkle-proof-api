// api/tree.js
// POST /v1/merkle/tree
// Ingests an array of items or hashes, constructs a binary Merkle tree with RFC 9162 domain separation, and returns the root hash.

const { buildMerkleTree } = require('../lib/merkle');
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

    // Resilient fallback defaults for RapidAPI Studio run button
    const items = Array.isArray(body.items) && body.items.length > 0
      ? body.items
      : ['event_log_alpha', 'event_log_beta', 'event_log_gamma', 'event_log_delta'];

    const algorithm = body.algorithm || 'sha256';
    const isAlreadyHashed = Boolean(body.is_already_hashed);
    const duplicateOdd = Boolean(body.duplicate_odd);
    const includeLevels = Boolean(body.include_levels);

    const tree = buildMerkleTree(items, {
      algorithm,
      isAlreadyHashed,
      duplicateOdd
    });

    return sendJson(res, 200, {
      success: true,
      data: {
        root_hash: tree.root,
        leaf_count: tree.leaf_count,
        tree_depth: tree.depth,
        algorithm: tree.algorithm,
        rfc_standard: 'RFC 9162 / RFC 6962 Domain Separation',
        levels: includeLevels ? tree.levels : undefined,
        note: 'The root hash serves as a tamper-evident cryptographic fingerprint representing the entire dataset.'
      }
    });
  } catch (err) {
    return sendError(res, 500, 'Failed to construct Merkle tree', err.message);
  }
};

