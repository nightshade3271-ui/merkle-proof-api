# MerkleProof API — RapidAPI Marketplace Listing Dossier

## 1. Basic Metadata
- **API Name:** MerkleProof API
- **Short Tagline:** Binary Merkle Tree & RFC 9162 Cryptographic Inclusion Proof Engine
- **Category:** Cryptography (or Security / Developer Tools)
- **Target Audience:** Backend engineers, blockchain developers, audit logging architects, and compliance engineering teams implementing verifiable data structures.
- **Website URL:** `https://merkle-proof-api.vercel.app`
- **Terms of Service URL:** `https://merkle-proof-api.vercel.app#terms`

---

## 2. Short Description (For Search Results)
> High-performance binary Merkle tree engine implementing RFC 9162 and RFC 6962 domain separation (0x00 leaf / 0x01 node prefixes). Ingests arrays of records or hashes, computes root fingerprints, generates O(log N) inclusion audit proofs, and verifies append-only log consistency in constant time. Developer utility provided strictly "AS IS".

---

## 3. Long Description / Marketplace Overview (Markdown)

```markdown
# MerkleProof API — Binary Merkle Tree & Verifiable Audit Proof Engine

MerkleProof API delivers high-performance verifiable data structure utilities for modern backend architectures: **Construct binary Merkle trees, generate compact $O(\log N)$ inclusion proofs, and mathematically prove that records have not been altered, omitted, or deleted.**

---

### Key Capabilities

#### 1. Binary Merkle Tree Construction (`POST /v1/merkle/tree`)
- **RFC 9162 Domain Separation:** Pre-appends `0x00` to leaves and `0x01` to internal nodes, providing second preimage resistance.
- **Multiple Hash Algorithms:** Supports SHA-256, SHA-512, and SHA-384.
- **Arbitrary Data Ingestion:** Accepts string arrays, canonicalized JSON objects, or pre-computed 32-byte hex digests.

#### 2. Inclusion Proofs / Audit Paths (`POST /v1/merkle/proof`)
- **Logarithmic Proof Size:** Produces an audit path of $O(\log_2 N)$ sibling hashes. A dataset of 1,000,000 records requires only $\approx 20$ hashes ($\approx 640$ bytes).
- **Zero Confidentiality Leakage:** Prove that a specific transaction, log entry, or document exists in the dataset without revealing any other entries.

#### 3. Constant-Time Proof Verification (`POST /v1/merkle/verify`)
- **Side-Channel Defense:** Evaluates the proof chain from leaf to root and validates equality against expected roots using `crypto.timingSafeEqual`.

#### 4. Append-Only Consistency Proofs (`POST /v1/merkle/consistency`)
- **Historical Tamper-Evidence:** Proves that an updated tree of size $N$ contains an earlier tree of size $M$ as an exact prefix, guaranteeing past records were never retroactively modified or reordered.

---

### Instant Quickstart (Node.js)

```javascript
// 1. Build Tree & Get Root Hash
const treeRes = await fetch("https://merkle-proof-api.vercel.app/v1/merkle/tree", {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    "X-RapidAPI-Key": "YOUR_RAPIDAPI_KEY",
    "X-RapidAPI-Host": "merkle-proof-api.p.rapidapi.com"
  },
  body: JSON.stringify({
    items: ["record_1", "record_2", "record_3", "record_4"]
  })
});
const tree = await treeRes.json();
console.log("Merkle Root:", tree.data.root_hash);

// 2. Generate Inclusion Proof for record_1
const proofRes = await fetch("https://merkle-proof-api.vercel.app/v1/merkle/proof", {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    "X-RapidAPI-Key": "YOUR_RAPIDAPI_KEY",
    "X-RapidAPI-Host": "merkle-proof-api.p.rapidapi.com"
  },
  body: JSON.stringify({
    items: ["record_1", "record_2", "record_3", "record_4"],
    target: 0
  })
});
const proof = await proofRes.json();
console.log("Audit Path Length:", proof.data.proof_length);
```

---

### ⚖️ Disclaimer & Terms
This API provides mathematical and cryptographic hashing primitives as a general developer utility. Subscribing developers and integrating systems are solely responsible for their own key custody, database architecture, and implementation. Provided strictly "AS IS", without warranties of any kind.
```

---

## 4. Suggested Pricing Tiers (RapidAPI Marketplace)

| Plan | Price | Monthly Quota | Overage Rate | Features / Rate Limits |
| :--- | :--- | :--- | :--- | :--- |
| **Basic (Free)** | **$0.00 / mo** | 100 requests / mo | $0.05 / req | Full playground access, 2 req/sec rate limit. |
| **Pro** | **$29.00 / mo** | 15,000 requests / mo | $0.005 / req | Tree construction, inclusion proofs, verification, 20 req/sec limit. |
| **Ultra** | **$99.00 / mo** | 100,000 requests / mo | $0.002 / req | Large-batch trees, consistency proofs, 60 req/sec limit. |
| **Mega** | **$299.00 / mo** | 500,000 requests / mo | $0.001 / req | High-throughput enterprise burst capacity, 150 req/sec limit. |

---

## 5. Search Keywords & Tags
`merkle-tree`, `merkle-proof`, `cryptography`, `rfc9162`, `rfc6962`, `audit-trail`, `tamper-evident`, `inclusion-proof`, `consistency-proof`, `sha256`, `verifiable-data-structures`, `certificate-transparency`

