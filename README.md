### Hash-Yoked Dispersed Regeneration Algorithm (HYDRA)

# HYDRA Protocol Specification

## 1. Overview & Objectives
**HYDRA** is a decentralized, self-healing data storage and transmission protocol. It combines high-performance Mersenne Prime field arithmetic ($M31$), Cauchy-based erasure coding, and cryptographic Merkle proofs to ensure high availability and data integrity with minimal wire overhead.

**Try it:** https://xdsopl.github.io/hydra/ runs the tests and examples in your browser.

---

## 2. Parameters ($K$, $N$ and the Hash Length)
* **Needed Blocks ($K$):** $K \in [1, 1024]$. The sender picks $K$: the message is split into $K$ parts, and any $K$ blocks are enough to get it back.
* **Total Blocks ($N$):** $N = 2^{height}$ with $height \in [1, 16]$, so $N \in [2, 65536]$, and always $N \ge K$. The sender picks $N$ as well. $K = 1$ is no special case: the message then fits into one block, and each of the $N \ge 2$ blocks holds all of it.
* **Recommended $N$:** at least 16 times the next power of two of $K$, so independent senders that pick random indices rarely send the same block. `useful_height` gives that height, capped at 16. It is only a recommendation; in small blocks with 32-byte hashes, the longer proof of a larger tree may leave too little room.
* **Hash Length ($hlen$):** 16 bytes by default, or 32 bytes for the paranoid. The whole tree uses it: leaves, nodes, proof and root.
* **Payload Length ($plen$):** $plen = blen - 4 - hlen \cdot (height + 1)$ for a block of $blen$ bytes. The payload holds $v = \lfloor 8 \cdot plen / 31 \rfloor$ values of 31 bits each. For a message of $mlen$ bytes, the sender needs $K \cdot v \cdot 31 \ge 31 + 8 \cdot mlen$; the extra 31 bits hold the value the M31 packing substitutes for $2^{31} - 1$.

---

## 3. Block Format

All multi-byte fields are little-endian.

```
[ header (4 bytes) ] [ payload (plen bytes) ] [ proof (height × hlen bytes) ] [ root (hlen bytes) ]
```

* **Header:** one little-endian 32-bit word.

  | Bits | Field |
  |-----:|-------|
  | 31 | hash flag: `0` = 16-byte hashes, `1` = 32-byte hashes |
  | 30 | reserved, must be `0`, otherwise the block is dropped |
  | 29–26 | $height - 1$ |
  | 25–16 | $K - 1$ |
  | 15–0 | index of the block, $0 \le index < N$ |

  On the wire, bytes 0–1 hold the index (low byte first), byte 2 holds the low 8 bits of $K - 1$, and byte 3 holds the top 2 bits of $K - 1$ in bits 0–1, $height - 1$ in bits 2–5, the reserved bit in bit 6 and the hash flag in bit 7.
* **Payload:** the $v$ values of the block, 31 bits each, packed from the lowest bit up. The bits after the last value, and any whole bytes after them, are padding and must be zero.
* **Proof:** the $height$ sibling hashes on the way from the leaf up to the root, lowest first.
* **Root:** the root of the Merkle tree over all $N$ blocks.
* **Merkle Tree:** BLAKE2s with the output length $hlen$. A leaf is the hash keyed with the byte `0` over the header and the payload, so the parameters and flags cannot change without breaking the proof. A node is the hash keyed with the byte `1` over its two children.
* **Valid Blocks:** a block is only valid if the reserved bit is `0`, $K \le N$, $index < N$, the padding is zero and the proof leads to the root.
* **Block Length:** blocks carry no length field. The transport knows how long each block is and passes that on.

---

## 4. Encoding, Decoding & Relaying
* **Deterministic:** the blocks depend only on the message, $K$, $plen$, $N$ and the hash length, so anyone with the message regenerates identical blocks. The message is packed into $K \cdot v$ values over M31 and expanded into $N$ blocks with a Cauchy matrix, block $index$ using row $K + index$.
* **Streaming Encoder:** the encoder generates one block at a time, hashes its leaf and throws the block away. The $N$ blocks are never all in memory; only the tree is kept, at most $2 \cdot 65536 \cdot 32$ bytes. Afterwards any block can be generated again on demand, with its proof.
* **Decoding:** any $K$ valid blocks with the same header fields (apart from the index), the same length, the same root and distinct indices are the complete state: they give back the message, and from it every block.
* **Relaying:** a relay must decode, regenerate the tree and check that the rebuilt root equals the received root before it sends any block on. Otherwise a malicious sender could build a tree over blocks that are not one codeword, and different choices of $K$ blocks would then decode differently.
* **Identity:** the root identifies one encoding, not the message. The message itself is identified by its plain hash, `digest_message`.
* **Cost:** encoding has to generate all $N$ blocks for the tree, about $N \cdot mlen \cdot 8 / 31$ multiplications in M31, so a larger $N$ costs encoders and relays alike. Decoding grows with $K^3$ for the coefficients, plus $K \cdot mlen \cdot 8 / 31$ multiplications for the data.

---

## 5. Module API

The WebAssembly module exports a few fixed buffers and nine functions. All functions return `-1` on bad arguments or failure.

### Buffers
* **`message`** ($2^{20} + 8192$ bytes): the message to encode, and the decoded message after `decode_message`. Messages are at most $2^{20}$ bytes; the decoder may fill up to one more block of padding.
* **`blocks`**: before `decode_message`, the caller puts $K$ blocks here, one after another.
* **`block`** ($8192$ bytes): a single block, written by `encode_block` and read by `verify_block`.
* **`digest`** ($32$ bytes): the result of `digest_message`.

### Functions
* **`needed_blocks(mlen, blen, height, dflag)`:** returns the smallest $K$ that holds a message of `mlen` bytes in blocks of `blen` bytes with a tree of the given height.
* **`block_length(mlen, K, height, dflag)`:** returns the smallest block length that still holds the message in $K$ blocks. It is often shorter than the budget, and the caller can use the rest for other things.
* **`useful_height(K)`:** returns the recommended height for $K$, so that $N \ge 16 \cdot 2^{\lceil \log_2 K \rceil}$, at most 16.
* **`encode_message(mlen, blen, height, dflag)`:** builds the tree over all $N$ blocks for the first `mlen` bytes of `message` and returns $K$. Longer blocks than `block_length` suggests are fine; the extra bytes become zero padding.
* **`encode_block(index)`:** writes block `index` with its proof into `block` and returns its length. Only after `encode_message`, or after `decode_message` and a successful `regenerate_tree`.
* **`verify_block(blen)`:** checks the block in `block`. Returns `0` to keep it and `-1` to drop it.
* **`decode_message(blen)`:** decodes the $K$ blocks in `blocks` into `message` and returns the number of bytes written. Returns `-1` if a block is invalid, the blocks disagree on the header or root, or an index repeats.
* **`regenerate_tree()`:** after `decode_message`, rebuilds the tree from the decoded message and returns `0` if the root matches the received one. Only then may a relay send blocks on.
* **`digest_message(mlen)`:** writes the plain 32-byte BLAKE2s hash of the first `mlen` bytes of `message` into `digest`. Truncate it for shorter identifiers instead of asking for a shorter hash.

### Planning
The sender knows the message length and a budget for the block length. $K$ depends on the height through the length of the proof, and the recommended height depends on $K$, so try heights from 1 upwards: `needed_blocks(mlen, budget, height, dflag)` gives $K$, and stop at the first height with `useful_height(K) <= height`. If no height gets there, take the one with the largest $N / K$. Then `block_length(mlen, K, height, dflag)` tells how much of the budget the blocks really need.

### Sending
Write the message into `message`, call `encode_message(mlen, blen, height, dflag)`, then `encode_block(index)` for each block to send and send the `blen` bytes from `block`. Any $K$ of the $N$ blocks are enough to get the message back. The sender does not have to send all $N$: $K$ plus a margin for the expected losses is enough, and more blocks can follow later for receivers that are still missing some.

### Receiving
Copy each received block into `block` and drop it if `verify_block(blen)` fails. Cache the rest by root and index. Once $K$ distinct blocks of a root are there, copy them one after another into `blocks` and call `decode_message(blen)`.

The decoder delivers at least `mlen` bytes, followed by zero padding. HYDRA does not know the exact length, so the application has to carry it inside the message, for example in a length field. Call `digest_message(mlen)` with that exact length to get an identifier of the message itself.

### Relaying
After `decode_message`, call `regenerate_tree()`. If it returns `0`, `encode_block(index)` gives any of the $N$ blocks, identical to the ones the sender made. If it returns `-1`, the blocks did not come from one honest encoding: keep nothing and send nothing on.

```js
const wasm = (await WebAssembly.instantiateStreaming(fetch("hydra.wasm"))).instance.exports;
const memory = wasm.memory.buffer;
const message = new Uint8Array(memory, wasm.message.value, (1 << 20) + 8192);
const block = new Uint8Array(memory, wasm.block.value, 8192);
const blocks = new Uint8Array(memory, wasm.blocks.value, 8192 * 2);

const text = new TextEncoder().encode("Hello World!");
message.set(text);
const height = 4, dflag = 0;
const K = wasm.needed_blocks(text.length, 200, height, dflag);
const blen = wasm.block_length(text.length, K, height, dflag);
wasm.encode_message(text.length, blen, height, dflag);

wasm.encode_block(5);
if (wasm.verify_block(blen) == 0) {
	blocks.set(block.subarray(0, blen), 0);
	const len = wasm.decode_message(blen);
	console.log(new TextDecoder().decode(message.subarray(0, text.length)), K, blen, len);
}
```

### Limits
* **Block length:** $blen \le 8192$ bytes.
* **Message length:** $1 \le mlen \le 2^{20}$ bytes, but $K \le 1024$ caps it further for short blocks. The largest message for some budgets, with the recommended $N$:

  | budget | dflag = 0 | dflag = 1 |
  |-------:|----------:|----------:|
  | 128 | 50 ($K = 2$, $N = 32$) | — |
  | 256 | 13884 ($K = 512$, $N = 8192$) | 112 ($K = 2$, $N = 32$) |
  | 512 | 273788 ($K = 1024$, $N = 16384$) | 29756 ($K = 512$, $N = 8192$) |
  | 1024 | 797564 ($K = 1024$, $N = 16384$) | 551548 ($K = 1024$, $N = 16384$) |
  | 2048 | 1048576 ($K = 582$, $N = 16384$) | 1048576 ($K = 672$, $N = 16384$) |
  | 4096 | 1048576 ($K = 272$, $N = 8192$) | 1048576 ($K = 288$, $N = 8192$) |
  | 8192 | 1048576 ($K = 132$, $N = 4096$) | 1048576 ($K = 135$, $N = 4096$) |

  With a smaller $N$ than recommended, larger messages fit; `needed_blocks` tells for any height.

---

## 6. Building & Testing
* **`make`:** builds `temp/hydra.wasm` with clang for `wasm32` and copies it to `docs/hydra.wasm` for the web page.
* **`make webserver`:** serves `docs/` on http://127.0.0.1:8080/ with Python's `http.server`. Open it to run the tests and examples in the browser.
* **`make check`:** runs the native tests in `tests/` and round trips through the command line tool:
  ```
  temp/hydra encode BLEN DFLAG MESSAGE PREFIX [HEIGHT]
  temp/hydra decode MESSAGE BLOCK...
  ```
  `encode` plans as described above, unless `HEIGHT` is given, and writes the $N$ blocks to `PREFIX00000`, `PREFIX00001` and so on, each only as long as `block_length` says. `decode` skips damaged, foreign and duplicate blocks and writes the decoded message, padding included.
