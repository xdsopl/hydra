### Hash-Yoked Dispersed Regeneration Algorithm (HYDRA)

# HYDRA Protocol Specification

## 1. Overview & Objectives
**HYDRA** is a decentralized, self-healing data storage and transmission protocol. It combines high-performance Mersenne Prime field arithmetic ($M31$), Cauchy-based erasure coding, and cryptographic Merkle proofs to ensure high availability and data integrity with minimal wire overhead.

---

## 2. Parameter Constraints ($K$ and $N$)
* **Data Chunks ($K$):** $K \in [1, 128]$
* **Total Shards ($N$):** 
  $$\text{If } K = 1 \text{ then } N = 1, \text{ else } N = 2^{\lceil \log_2(K) \rceil + 1}$$
* **Redundancy:** Provides a robust 2x redundancy tier for all $K > 1$, scaling up to a maximum of $N = 256$ shards.

---

## 3. Block & Wire Format Layout

The protocol uses two distinct paths depending on whether erasure coding is active:

### Fast-Path ($K = 1$, No Erasure Coding / No Splits)
When $K = 1$, no M31 encoding is performed. The message is stored as-is with zero chunk indexing overhead.
* **Layout Structure:**
  ```
  [ Byte 0: digest_flag + (K - 1) ] [ Message Payload ] [ Hash (16 or 32 bytes) ]
  ```
* **Byte 0 Breakdown:**
  * **Bit 0 (`digest_flag`):** `0` = 16-byte Blake2s digest, `1` = 32-byte Blake2s digest.
  * **Bits 1–7 (`K - 1`):** Encoded as `0` (since $K - 1 = 0$).
* *Omissions:* `chunk_index` and Merkle proof paths are skipped entirely ($N = 1$).

### Full-Path ($K > 1$, Cauchy Erasure Coding Enabled)
When $K > 1$, the message is split into $K$ chunks, expanded to $N$ total shards via Cauchy matrix multiplication over $M31$, and bundled with full cryptographic proof materials.
* **Layout Structure:**
  ```
  [ Byte 0: digest_flag + (K - 1) ] [ Byte 1: chunk_index (0..255) ] [ Shard Payload ] [ Merkle Proof Path ]
  ```
* **Byte Breakdown:**
  * **Byte 0:** Bit 0 = `digest_flag`, Bits 1–7 = $K - 1$ (values $1$ to $127$ for $K \in [2, 128]$).
  * **Byte 1 (`chunk_index`):** 8-bit unsigned integer ($0$ to $255$) identifying the specific shard position.
  * **Merkle Proof Path:** Consists of $\log_2(N)$ sibling hashes (16 or 32 bytes each), enabling zero-trust verification against the canonical root.
