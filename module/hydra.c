/*
WebAssembly HYDRA module for self-healing erasure coding

Copyright 2026 Ahmet Inan <xdsopl@gmail.com>
*/

#include "blake2.h"

#define MLEN_MAX (1 << 20)
#define HLEN_MAX (16 << 9)

__attribute__((visibility("default")))
unsigned char digest[32];
__attribute__((visibility("default")))
unsigned char message[MLEN_MAX];
__attribute__((visibility("default")))
unsigned char blocks[MLEN_MAX];
__attribute__((visibility("default")))
unsigned char hashes[HLEN_MAX];

__attribute__((visibility("default")))
int digest_message(int mlen, int dlen)
{
	if (mlen < 0 || mlen > MLEN_MAX)
		return 1;
	if (dlen < 1 || dlen > 32)
		return 1;
	blake2s_state state;
	blake2s_init(&state, dlen);
	blake2s_update(&state, message, mlen);
	blake2s_final(&state, digest, dlen);
	return 0;
}

__attribute__((visibility("default")))
int digest_blocks(int height, int blen)
{
	if (height < 2 || height > 8)
		return 1;
	int leaves = 1 << height;
	if (blen < 0 || blen * leaves > MLEN_MAX)
		return 1;
	blake2s_state init, state;
	unsigned char key = 0; // prevent second preimage attack
	blake2s_init_key(&init, 16, &key, 1);
	int woff = leaves - 1;
	for (int i = 0; i < leaves; i++) {
		state = init;
		blake2s_update(&state, blocks+blen*i, blen);
		blake2s_final(&state, hashes+16*(woff+i), 16);
	}
	key = 1; // put internal nodes into a different domain
	blake2s_init_key(&init, 16, &key, 1);
	for (int nodes = leaves / 2; nodes; nodes /= 2) {
		int roff = woff;
		woff -= nodes;
		for (int i = 0; i < nodes; i++) {
			state = init;
			blake2s_update(&state, hashes+16*(roff+2*i), 32);
			blake2s_final(&state, hashes+16*(woff+i), 16);
		}
	}
	return 0;
}

