### Hash-Yoked Dispersed Regeneration Algorithm (HYDRA)

# HYDRA Protocol Specification

## 1. Overview & Objectives
**HYDRA** is a decentralized, self-healing data storage and transmission protocol. It combines high-performance Mersenne Prime field arithmetic ($M31$), Cauchy-based erasure coding, and cryptographic Merkle proofs to ensure high availability and data integrity with minimal wire overhead.

---

## 2. Parameter Constraints ($K$ and $N$)
* **Needed Blocks ($K$):** $K \in [1, 128]$
* **Total Blocks ($N$):** 
  $$\text{If } K = 1 \text{ then } N = 1, \text{ else } N = 2^{\lceil \log_2(K) \rceil + 1}$$
* **Redundancy:** Provides a robust 2x redundancy tier for all $K > 1$, scaling up to a maximum of $N = 256$ blocks.

---

## 3. Block & Wire Format Layout

The protocol uses two distinct paths depending on whether erasure coding is active:

### Fast-Path ($K = 1$, No Erasure Coding / No Splits)
When $K = 1$, no M31 encoding is performed. The message is stored as-is without an index byte.
* **Layout Structure:**
  ```
  [ Byte 0: digest_flag + (K - 1) ] [ Message Payload ] [ Hash (4 or 8 bytes) ]
  ```
* **Byte 0 Breakdown:**
  * **Bits 0–6 (`K - 1`):** Encoded as `0` (since $K - 1 = 0$).
  * **Bit 7 (`digest_flag`):** `0` = 4-byte, `1` = 8-byte Blake2s hash over Byte 0 and the payload.
* **Error Protection:** The hash only guards against accidental corruption that slipped past the overlying system. The 4-byte hash is the default, the 8-byte hash adds extra protection.
* **Capacity:** Up to $blen - 5$ bytes of message with the 4-byte hash, or $blen - 9$ bytes with the 8-byte hash.
* *Omissions:* The index byte and the Merkle proof are skipped entirely ($N = 1$).

### Full-Path ($K > 1$, Cauchy Erasure Coding Enabled)
When $K > 1$, the message is split into $K$ blocks, expanded to $N$ total blocks via Cauchy matrix multiplication over $M31$, and bundled with full cryptographic proof materials.
* **Layout Structure:**
  ```
  [ Byte 0: digest_flag + (K - 1) ] [ Byte 1: index (0..255) ] [ Payload ] [ Merkle Proof Path ]
  ```
* **Byte Breakdown:**
  * **Byte 0:** Bits 0–6 = $K - 1$ (values $1$ to $127$ for $K \in [2, 128]$), Bit 7 = `digest_flag` (`0` = 16-byte, `1` = 32-byte Blake2s hashes).
  * **Byte 1 (index):** 8-bit unsigned integer ($0$ to $255$) identifying the position of the block.
  * **Merkle Proof Path:** Consists of $\log_2(N)$ sibling hashes, ordered from the leaf upwards, followed by the root (16 or 32 bytes each), enabling zero-trust verification against the canonical root. The leaf hash covers Bytes 0 and 1 and the payload. The root identifies the message, so blocks of many unrelated messages can be told apart and cached until their siblings arrive.
* **Identifying Blocks:** Once a block's proof passes, its last 16 or 32 bytes (per `digest_flag`) are the root identifying the message, and Byte 1 is its index. Callers cache blocks by root and index and hand $K$ distinct blocks of the same root to the decoder, which rejects a duplicate index instead of filtering it.

---

## 4. Module API

The WebAssembly module exports a few fixed buffers and six functions. All functions return `-1` on bad arguments or failure.

### Buffers
* **`message`** ($2^{20}$ bytes): the message to encode, and the decoded message after `decode_message`.
* **`blocks`** ($256 \times 8192$ bytes): the $N$ encoded blocks after `encode_message`, block $i$ at offset $i \cdot blen$. Before `decode_message`, the caller puts $K$ blocks here one after another.
* **`block`** ($8192$ bytes): a single received block for `verify_block`.
* **`digest`** ($32$ bytes): the result of `digest_message`.

### Functions
* **`needed_blocks(mlen, blen, dflag)`:** returns $K$ for a message of `mlen` bytes in blocks of `blen` bytes.
* **`total_blocks(K)`:** returns $N$.
* **`encode_message(mlen, blen, dflag)`:** encodes the first `mlen` bytes of `message` into `blocks` and returns $N$.
* **`verify_block(blen)`:** checks the block in `block`. Returns `0` to keep it and `-1` to drop it.
* **`decode_message(blen)`:** decodes the $K$ blocks in `blocks` into `message` and returns the number of bytes written. Returns `-1` if a block fails its proof, the blocks belong to different messages, or an index repeats.
* **`digest_message(mlen)`:** writes the plain 32-byte Blake2s hash of the first `mlen` bytes of `message` into `digest`. Truncate it for shorter identifiers instead of asking for a shorter hash.

### Sending
Write the message into `message`, call `encode_message(mlen, blen, dflag)` and send the $N$ blocks of `blen` bytes from `blocks`. Any $K$ of them are enough to get the message back.

### Receiving
Copy each received block into `block` and drop it if `verify_block(blen)` fails. Cache the rest by root and index as described above. A block with $K = 1$ holds the whole message on its own. Once $K$ distinct blocks of a root are there, copy them one after another into `blocks` and call `decode_message(blen)`.

The decoder delivers at least `mlen` bytes, followed by zero padding. HYDRA does not know the exact length, so the application has to carry it inside the message, for example in a length field. Call `digest_message(mlen)` with that exact length to get an identifier of the message itself.

```js
const wasm = (await WebAssembly.instantiateStreaming(fetch("hydra.wasm"))).instance.exports;
const memory = wasm.memory.buffer;
const message = new Uint8Array(memory, wasm.message.value, 1 << 20);
const blocks = new Uint8Array(memory, wasm.blocks.value, 8192 * 256);
const block = new Uint8Array(memory, wasm.block.value, 8192);

const blen = 256;
message.set(new TextEncoder().encode("Hello World!"));
const N = wasm.encode_message(12, blen, 0);

block.set(blocks.subarray(0, blen));
if (wasm.verify_block(blen) == 0) {
	blocks.set(block.subarray(0, blen), 0);
	const len = wasm.decode_message(blen);
	console.log(new TextDecoder().decode(message.subarray(0, 12)), N, len);
}
```

### Limits
* **Block length:** $blen \le 8192$ bytes.
* **Message length:** $1 \le mlen \le 2^{20}$ bytes, but $K \le 128$ caps it further. The largest message for some block lengths:

  | blen | dflag = 0 | dflag = 1 |
  |-----:|----------:|----------:|
  | 64 | 59 | 55 |
  | 128 | 430 | 119 |
  | 256 | 13884 | 988 |
  | 512 | 46620 | 28268 |
  | 1024 | 112092 | 93740 |
  | 2048 | 243036 | 224684 |
  | 4096 | 505420 | 487068 |
  | 8192 | 1029692 | 1011340 |

---

## 5. Building & Testing
* **`make`:** builds `temp/hydra.wasm` with clang for `wasm32`.
* **`make assets`:** compresses it to `assets/hydra.wasm.gz` for the web page.
* **`make webserver`:** serves `assets/` on port 8080. Open `index.html` to run the tests and examples in the browser.
* **`make check`:** runs the native tests in `tests/` and round trips through the command line tool:
  ```
  temp/hydra encode BLEN DFLAG MESSAGE PREFIX
  temp/hydra decode MESSAGE BLOCK...
  ```
  `encode` writes the $N$ blocks to `PREFIX000`, `PREFIX001` and so on. `decode` skips damaged, foreign and duplicate blocks and writes the decoded message, padding included.
