# MerkleProof API — Technical Documentation & Architecture Reference

Welcome to the **MerkleProof API** developer documentation. MerkleProof delivers high-performance, cryptographic **Binary Merkle Trees & Verifiable Audit Proofs** for databases, document management platforms, distributed ledgers, and tamper-evident event streaming architectures.

MerkleProof solves the core verification challenge: **How to cryptographically prove that a specific data record or log entry exists within a dataset of millions of records—and has not been altered or deleted—without sharing or exposing the entire dataset.**

---

## 1. Quickstart & RapidAPI Gateway Authentication

All requests proxied through the RapidAPI Marketplace use standard gateway authentication headers:

```http
POST /v1/merkle/tree HTTP/1.1
Host: merkle-proof-api.p.rapidapi.com
Content-Type: application/json
X-RapidAPI-Key: YOUR_RAPIDAPI_KEY
X-RapidAPI-Host: merkle-proof-api.p.rapidapi.com

{
  "items": ["log_record_001", "log_record_002", "log_record_003", "log_record_004"],
  "algorithm": "sha256"
}
```

---

## 2. Core Cryptographic Architecture

### A. RFC 9162 & RFC 6962 Domain Separation
To prevent second preimage attacks (where an attacker submits an internal node hash claiming it is a leaf hash), MerkleProof strictly enforces domain separation prefixes:
* **Leaf Hash:** $H(0\text{x}00 \parallel \text{data})$
* **Internal Node Hash:** $H(0\text{x}01 \parallel \text{left} \parallel \text{right})$

This guarantees that a leaf can never collide with an interior branch node, regardless of dataset contents.

### B. Inclusion Proofs (Audit Paths)
An inclusion proof consists of the cryptographic sibling hashes required to reconstruct the Merkle root from a single leaf up to the root:
* **Proof Complexity:** $O(\log_2 N)$ hashes.
* For a dataset of **1,000,000 records**, the proof requires only **$\approx 20$ hashes** ($\approx 640$ bytes).
* The verifier only needs the single record and the audit path—**the remaining 999,999 records remain completely confidential**.

### C. Append-Only Consistency Proofs
The `/v1/merkle/consistency` endpoint implements RFC 9162 Section 2.1.4 to prove that an earlier log snapshot of size $M$ is an exact prefix of an updated log of size $N$ ($M \le N$). This guarantees historical records were neither retroactively modified, reordered, nor deleted.

---

## 3. Database Implementation Pattern

### Storing Merkle Roots for Immutable Change Audits (PostgreSQL)

```sql
-- Schema for tamper-evident event log
CREATE TABLE audit_snapshots (
  id SERIAL PRIMARY KEY,
  snapshot_timestamp TIMESTAMPTZ NOT NULL,
  record_count INT NOT NULL,
  merkle_root_hash CHAR(64) NOT NULL
);

-- Periodically (e.g. hourly or daily), publish the Merkle root hash
-- to an external timestamping authority, transparency log, or public witness.
```

When an auditor or user requests verification of record `event_log_482`:
1. Call `/v1/merkle/proof` to generate the audit path.
2. Provide the user with the record and the audit path.
3. The user independently calls `/v1/merkle/verify` to confirm that the hash chain equals the published root hash in constant time.

---

## 4. API Endpoints Reference

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/v1/merkle/tree` | Ingests array of items/hashes, builds tree, returns root hash |
| `POST` | `/v1/merkle/proof` | Generates $O(\log N)$ inclusion proof for specified target |
| `POST` | `/v1/merkle/verify` | Constant-time `crypto.timingSafeEqual` proof validator |
| `POST` | `/v1/merkle/consistency` | Generates append-only log consistency proof |
| `GET` | `/health` | Engine diagnostics and RFC specifications |

---

## 5. Disclaimer & Limitation of Liability

This API is a developer utility providing mathematical and cryptographic hashing functions. Subscribing developers and integrating systems are solely responsible for their own application architecture, cryptographic key custody, access controls, and data management. The software and services are provided "AS IS", without warranty of any kind, express or implied.

