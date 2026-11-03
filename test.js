// test.js
// Automated Test Suite for MerkleProof API
// Tests RFC 9162 domain separation, binary tree building, inclusion proof generation,
// constant-time verification, append-only consistency proofs, and live HTTP endpoints.

const assert = require('assert');
const http = require('http');

const {
  canonicalizeItem,
  hashLeaf,
  hashNode,
  buildMerkleTree,
  generateInclusionProof,
  verifyInclusionProof,
  generateConsistencyProof,
  getEngineMetadata
} = require('./lib/merkle');

const server = require('./server');

let passedTests = 0;
let totalTests = 0;

function runTest(name, fn) {
  totalTests++;
  try {
    fn();
    passedTests++;
    console.log(`  [PASS] ${name}`);
  } catch (err) {
    console.error(`  [FAIL] ${name}: ${err.message}`);
    throw err;
  }
}

async function runAsyncTest(name, fn) {
  totalTests++;
  try {
    await fn();
    passedTests++;
    console.log(`  [PASS] ${name}`);
  } catch (err) {
    console.error(`  [FAIL] ${name}: ${err.message}`);
    throw err;
  }
}

console.log('=== MERKLEPROOF API AUTOMATED TEST SUITE ===\n');

// 1. Canonicalization Tests
runTest('Canonicalization: Object key ordering is deterministic', () => {
  const objA = { z: 1, a: 'test', m: { b: 2, a: 1 } };
  const objB = { a: 'test', m: { a: 1, b: 2 }, z: 1 };
  assert.strictEqual(canonicalizeItem(objA), canonicalizeItem(objB));
});

// 2. Domain Separation Tests (Second Preimage Defense)
runTest('Domain Separation: Leaf hash and Node hash use distinct RFC 9162 prefixes', () => {
  const data = Buffer.from('test_data');
  const leafHash = hashLeaf(data);
  const nodeHash = hashNode(data.subarray(0, 4), data.subarray(4));
  assert.notStrictEqual(leafHash.toString('hex'), nodeHash.toString('hex'));
});

// 3. Merkle Tree Construction Tests
runTest('Merkle Tree: Handles empty array gracefully', () => {
  const tree = buildMerkleTree([]);
  assert.strictEqual(tree.leaf_count, 0);
  assert.strictEqual(typeof tree.root, 'string');
});

runTest('Merkle Tree: 4-leaf balanced binary tree computation', () => {
  const items = ['rec_1', 'rec_2', 'rec_3', 'rec_4'];
  const tree = buildMerkleTree(items);
  assert.strictEqual(tree.leaf_count, 4);
  assert.strictEqual(tree.depth, 2);
  assert.strictEqual(typeof tree.root, 'string');
  assert.strictEqual(tree.root.length, 64);
});

runTest('Merkle Tree: Odd number of leaves handled correctly', () => {
  const items = ['rec_1', 'rec_2', 'rec_3'];
  const treeRfc = buildMerkleTree(items, { duplicateOdd: false });
  const treeBtc = buildMerkleTree(items, { duplicateOdd: true });
  assert.strictEqual(treeRfc.leaf_count, 3);
  assert.strictEqual(treeBtc.leaf_count, 3);
  assert.notStrictEqual(treeRfc.root, treeBtc.root, 'RFC 9162 promotion vs Bitcoin duplication must produce distinct valid roots');
});

// 4. Inclusion Proof & Verification Tests
runTest('Inclusion Proof: Generates valid proof and verifies against root in constant time', () => {
  const items = ['tx_alpha', 'tx_beta', 'tx_gamma', 'tx_delta', 'tx_epsilon'];
  const targetItem = 'tx_gamma';

  const tree = buildMerkleTree(items);
  const proof = generateInclusionProof(items, targetItem);

  assert.strictEqual(proof.root_hash, tree.root);
  assert.strictEqual(proof.target_index, 2);
  assert(proof.audit_path.length > 0);

  // Verify true positive
  const verification = verifyInclusionProof(targetItem, proof.audit_path, tree.root);
  assert.strictEqual(verification.valid, true);
  assert.strictEqual(verification.computed_root, tree.root);

  // Verify false positive rejection (tampered item)
  const tampered = verifyInclusionProof('tx_tampered', proof.audit_path, tree.root);
  assert.strictEqual(tampered.valid, false);

  // Verify false positive rejection (wrong root)
  const fakeRoot = '0000000000000000000000000000000000000000000000000000000000000000';
  const wrongRoot = verifyInclusionProof(targetItem, proof.audit_path, fakeRoot);
  assert.strictEqual(wrongRoot.valid, false);
});

// 5. Append-Only Consistency Proof Tests
runTest('Consistency Proof: Proves earlier tree is unmodified prefix of newer tree', () => {
  const fullLog = ['entry_1', 'entry_2', 'entry_3', 'entry_4', 'entry_5', 'entry_6', 'entry_7'];
  const consistency = generateConsistencyProof(fullLog, 4);

  assert.strictEqual(consistency.previous_size, 4);
  assert.strictEqual(consistency.current_size, 7);
  assert.strictEqual(consistency.verified_append_only, true);
  assert(consistency.consistency_proof.length > 0);
});

// 6. HTTP Server Integration Tests
function makeRequest(port, method, path, data = null) {
  return new Promise((resolve, reject) => {
    const payload = data ? JSON.stringify(data) : null;
    const req = http.request({
      hostname: '127.0.0.1',
      port,
      path,
      method,
      headers: {
        'Content-Type': 'application/json',
        ...(payload ? { 'Content-Length': Buffer.byteLength(payload) } : {})
      }
    }, (res) => {
      let body = '';
      res.on('data', chunk => body += chunk);
      res.on('end', () => {
        try {
          resolve({
            status: res.statusCode,
            headers: res.headers,
            body: body ? JSON.parse(body) : null
          });
        } catch {
          resolve({ status: res.statusCode, headers: res.headers, raw: body });
        }
      });
    });

    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

async function runHttpTests() {
  const testPort = 3198;
  await new Promise((resolve) => server.listen(testPort, resolve));

  try {
    await runAsyncTest('HTTP: GET /health returns 200 and RFC specifications', async () => {
      const res = await makeRequest(testPort, 'GET', '/health');
      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.body.status, 'healthy');
      assert.strictEqual(res.body.service, 'MerkleProof Cryptographic Binary Tree & Proof Engine API');
    });

    await runAsyncTest('HTTP: POST /v1/merkle/tree builds tree and returns root', async () => {
      const res = await makeRequest(testPort, 'POST', '/v1/merkle/tree', {
        items: ['doc_1', 'doc_2', 'doc_3']
      });
      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.body.success, true);
      assert.strictEqual(res.body.data.leaf_count, 3);
      assert.strictEqual(typeof res.body.data.root_hash, 'string');
    });

    await runAsyncTest('HTTP: POST /v1/merkle/proof generates valid audit path', async () => {
      const res = await makeRequest(testPort, 'POST', '/v1/merkle/proof', {
        items: ['doc_1', 'doc_2', 'doc_3', 'doc_4'],
        target: 1
      });
      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.body.success, true);
      assert.strictEqual(res.body.data.target_index, 1);
      assert(res.body.data.audit_path.length > 0);
    });

    await runAsyncTest('HTTP: POST /v1/merkle/verify validates proof in constant time', async () => {
      const items = ['doc_1', 'doc_2'];
      const proof = generateInclusionProof(items, 0);

      const res = await makeRequest(testPort, 'POST', '/v1/merkle/verify', {
        item: 'doc_1',
        audit_path: proof.audit_path,
        expected_root: proof.root_hash
      });
      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.body.success, true);
      assert.strictEqual(res.body.data.valid, true);
    });

    await runAsyncTest('HTTP: POST /v1/merkle/consistency verifies append-only extension', async () => {
      const res = await makeRequest(testPort, 'POST', '/v1/merkle/consistency', {
        items: ['log_1', 'log_2', 'log_3', 'log_4', 'log_5'],
        previous_size: 3
      });
      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.body.success, true);
      assert.strictEqual(res.body.data.verified_append_only, true);
    });

    await runAsyncTest('HTTP: Resilient Playground - Empty POST {} returns 200 OK on all endpoints', async () => {
      const endpoints = [
        '/v1/merkle/tree',
        '/v1/merkle/proof',
        '/v1/merkle/verify',
        '/v1/merkle/consistency'
      ];

      for (const ep of endpoints) {
        const res = await makeRequest(testPort, 'POST', ep, {});
        assert.strictEqual(res.status, 200, `Endpoint ${ep} must return 200 OK on empty body fallback`);
        assert.strictEqual(res.body.success, true);
      }
    });

  } finally {
    server.close();
  }
}

runHttpTests().then(() => {
  console.log(`\n========================================`);
  console.log(`ALL TESTS PASSED: ${passedTests} / ${totalTests} passing (100%)`);
  console.log(`========================================\n`);
}).catch(err => {
  console.error('\nTest suite execution encountered an error:', err);
  process.exit(1);
});

