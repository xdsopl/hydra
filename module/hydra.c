/*
WebAssembly HYDRA module for self-healing erasure coding

Copyright 2026 Ahmet Inan <xdsopl@gmail.com>
*/

#include "blake2.h"
#include "string.h"

#define DLEN_MAX 32
#define MLEN_MAX (1 << 20)
#define BLEN_MAX 8192
#define HLEN_MAX 16
#define HEIGHT_MAX 8
#define BCNT_MAX (1 << HEIGHT_MAX)

// prevent second preimage attack
static const unsigned char leaf_key = 0;
static const unsigned char node_key = 1;

__attribute__((visibility("default")))
unsigned char digest[DLEN_MAX];
__attribute__((visibility("default")))
unsigned char message[MLEN_MAX];
__attribute__((visibility("default")))
unsigned char blocks[BLEN_MAX*BCNT_MAX];
__attribute__((visibility("default")))
unsigned char hashes[HLEN_MAX*2*BCNT_MAX];
__attribute__((visibility("default")))
unsigned char block[BLEN_MAX];
__attribute__((visibility("default")))
unsigned char proof[HLEN_MAX*(HEIGHT_MAX+1)];

__attribute__((visibility("default")))
int digest_message(int mlen, int dlen)
{
	if (mlen < 1 || mlen > MLEN_MAX)
		return 1;
	if (dlen < 1 || dlen > DLEN_MAX)
		return 1;
	blake2s_state state;
	blake2s_init(&state, dlen);
	blake2s_update(&state, message, mlen);
	blake2s_final(&state, digest, dlen);
	return 0;
}

__attribute__((visibility("default")))
int digest_blocks(int height, int blen, int hlen)
{
	if (height < 2 || height > HEIGHT_MAX)
		return 1;
	if (blen < 1 || blen > BLEN_MAX)
		return 1;
	if (hlen < 1 || hlen > HLEN_MAX)
		return 1;
	blake2s_state init, state;
	blake2s_init_key(&init, hlen, &leaf_key, 1);
	int leaves = 1 << height;
	int woff = leaves - 1;
	for (int i = 0; i < leaves; i++) {
		state = init;
		blake2s_update(&state, blocks+blen*i, blen);
		blake2s_final(&state, hashes+hlen*(woff+i), hlen);
	}
	blake2s_init_key(&init, hlen, &node_key, 1);
	for (int nodes = leaves / 2; nodes; nodes /= 2) {
		int roff = woff;
		woff -= nodes;
		for (int i = 0; i < nodes; i++) {
			state = init;
			blake2s_update(&state, hashes+hlen*(roff+2*i), 2*hlen);
			blake2s_final(&state, hashes+hlen*(woff+i), hlen);
		}
	}
	return 0;
}

__attribute__((visibility("default")))
int extract_proof(int height, int blen, int hlen, int index)
{
	if (height < 2 || height > HEIGHT_MAX)
		return 1;
	if (blen < 1 || blen > BLEN_MAX)
		return 1;
	if (hlen < 1 || hlen > HLEN_MAX)
		return 1;
	int leaves = 1 << height;
	if (index < 0 || index >= leaves)
		return 1;
	memcpy(block, blocks+blen*index, blen);
	int roff = leaves - 1;
	for (int j = height; j > 0; j--) {
		int sibling = index ^ 1;
		index /= 2;
		memcpy(proof+hlen*j, hashes+hlen*(roff+sibling), hlen);
		roff -= 1 << (j - 1);
	}
	memcpy(proof, hashes, hlen);
	return 0;
}

__attribute__((visibility("default")))
int verify_proof(int height, int blen, int hlen, int index)
{
	if (height < 2 || height > HEIGHT_MAX)
		return 1;
	if (blen < 1 || blen > BLEN_MAX)
		return 1;
	if (hlen < 1 || hlen > HLEN_MAX)
		return 1;
	int leaves = 1 << height;
	if (index < 0 || index >= leaves)
		return 1;
	blake2s_state init, state;
	blake2s_init_key(&init, hlen, &leaf_key, 1);
	state = init;
	blake2s_update(&state, block, blen);
	unsigned char hash[HLEN_MAX];
	blake2s_final(&state, hash, hlen);
	blake2s_init_key(&init, hlen, &node_key, 1);
	for (int j = height; j > 0; j--) {
		state = init;
		unsigned char *left = hash, *right = proof+hlen*j;
		if (index & 1) {
			unsigned char *tmp = left;
			left = right;
			right = tmp;
		}
		index /= 2;
		blake2s_update(&state, left, hlen);
		blake2s_update(&state, right, hlen);
		blake2s_final(&state, hash, hlen);
	}
	return !!memcmp(hash, proof, hlen);
}

