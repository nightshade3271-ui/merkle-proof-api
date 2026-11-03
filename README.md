# MerkleProof API 🌳

> **Cryptographic Binary Merkle Tree & Audit Proof Engine**  
> *Generate RFC 9162 domain-separated Merkle trees, $O(\log N)$ inclusion proofs, and append-only consistency proofs for tamper-evident data verification.*

[![Tests](https://img.shields.io/badge/tests-13%20passed-brightgreen.svg)](test.js)
[![OpenAPI](https://img.shields.io/badge/OpenAPI-3.0.3-blue.svg)](rapidapi-openapi.json)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Vercel](https://img.shields.io/badge/deployment-Vercel%20Edge-black.svg)](https://vercel.com)

---

## ⚡ Technical Overview

Merkle trees allow cryptographic verification of large datasets with minimal bandwidth and zero exposure of confidential records:
* **Second Preimage Defense:** Implements RFC 9162 domain separation (`0x00` leaf prefix / `0x01` internal node prefix).
* **Compact Inclusion Proofs:** Verifies any single record against a published Merkle root using only $O(\log_2 N)$ sibling hashes.
* **Append-Only Consistency:** Proves historical logs have not been modified, reordered, or deleted across snapshot updates.
* **Constant-Time Verification:** Validates computed roots using `crypto.timingSafeEqual` to eliminate timing side-channels.

---

## 🚀 Key Features

* **Tree Construction (`POST /v1/merkle/tree`):** Ingests strings, JSON objects, or hex digests and computes the root hash.
* **Inclusion Proofs (`POST /v1/merkle/proof`):** Generates binary audit paths (sibling hashes + direction flags).
* **Constant-Time Verification (`POST /v1/merkle/verify`):** Recomputes and validates proof chains against root hashes.
* **Consistency Proofs (`POST /v1/merkle/consistency`):** Mathematically verifies append-only log extension.

---

## 📦 RapidAPI Quickstart

```bash
curl -X POST https://merkle-proof-api.p.rapidapi.com/v1/merkle/tree \
  -H "Content-Type: application/json" \
  -H "X-RapidAPI-Key: YOUR_RAPIDAPI_KEY" \
  -H "X-RapidAPI-Host: merkle-proof-api.p.rapidapi.com" \
  -d '{
    "items": ["audit_record_1", "audit_record_2", "audit_record_3", "audit_record_4"],
    "algorithm": "sha256"
  }'
```

---

## 🧪 Local Testing & Verification

Run the automated test suite:
```bash
npm test
```

Start the standalone HTTP daemon on port 3017:
```bash
npm start
```
Visit `http://localhost:3017` in your browser for the interactive cryptographic playground.

---

## ⚖️ Disclaimer & Limitation of Liability

This API is provided strictly as a general developer utility offering mathematical hashing algorithms. Integrating applications and subscribing developers maintain full and exclusive responsibility for their own system design, key management, and database integrity. Provided "AS IS" without warranties of any kind.

---

## 📄 License
MIT License. Cryptographic engineering by MerkleProof.

