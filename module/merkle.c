/*
WebAssembly HYDRA module for self-healing erasure coding

Copyright 2026 Ahmet Inan <xdsopl@gmail.com>
*/

#include "blake2.h"
#include "string.h"

/* prevent second preimage attack */
static const unsigned char leaf_key = 0;
static const unsigned char node_key = 1;

int merkle_digest_message(unsigned char *digest, unsigned char *message, int mlen, int dlen)
{
	blake2s_state state;
	if (dlen < 1 || dlen > 32)
		return 1;
	blake2s_init(&state, dlen);
	blake2s_update(&state, message, mlen);
	blake2s_final(&state, digest, dlen);
	return 0;
}

int merkle_digest_blocks(unsigned char *hashes, unsigned char *blocks, int height, int blen, int stride, int dlen)
{
	blake2s_state init, state;
	int leaves = 1 << height;
	int woff = leaves - 1;
	if (stride < blen)
		return 1;
	if (dlen < 1 || dlen > 32)
		return 1;
	blake2s_init_key(&init, dlen, &leaf_key, 1);
	while (leaves--) {
		state = init;
		blake2s_update(&state, blocks+stride*leaves, blen);
		blake2s_final(&state, hashes+dlen*(woff+leaves), dlen);
	}
	blake2s_init_key(&init, dlen, &node_key, 1);
	while (height--) {
		int nodes = 1 << height;
		int roff = woff;
		woff -= nodes;
		while (nodes--) {
			state = init;
			blake2s_update(&state, hashes+dlen*(roff+2*nodes), 2*dlen);
			blake2s_final(&state, hashes+dlen*(woff+nodes), dlen);
		}
	}
	return 0;
}

int merkle_extract_proof(unsigned char *block, unsigned char *proof, unsigned char *blocks, unsigned char *hashes, int height, int blen, int stride, int dlen, int index)
{
	int leaves = 1 << height;
	int roff = leaves - 1;
	if (stride < blen)
		return 1;
	if (dlen < 1 || dlen > 32)
		return 1;
	if (index < 0 || index >= leaves)
		return 1;
	memcpy(block, blocks+stride*index, blen);
	while (height) {
		int sibling = index ^ 1;
		index /= 2;
		memcpy(proof+dlen*height, hashes+dlen*(roff+sibling), dlen);
		height--;
		roff -= 1 << height;
	}
	memcpy(proof, hashes, dlen);
	return 0;
}

int merkle_verify_proof(unsigned char *block, unsigned char *proof, int height, int blen, int dlen, int index)
{
	blake2s_state init, state;
	unsigned char hash[32];
	int leaves = 1 << height;
	if (dlen < 1 || dlen > 32)
		return 1;
	if (index < 0 || index >= leaves)
		return 1;
	blake2s_init_key(&init, dlen, &leaf_key, 1);
	state = init;
	blake2s_update(&state, block, blen);
	blake2s_final(&state, hash, dlen);
	blake2s_init_key(&init, dlen, &node_key, 1);
	while (height) {
		unsigned char *left = hash;
		unsigned char *right = proof+dlen*height;
		height--;
		if (index & 1) {
			unsigned char *tmp = left;
			left = right;
			right = tmp;
		}
		index /= 2;
		state = init;
		blake2s_update(&state, left, dlen);
		blake2s_update(&state, right, dlen);
		blake2s_final(&state, hash, dlen);
	}
	return !!memcmp(hash, proof, dlen);
}

