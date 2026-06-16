/*
WebAssembly HYDRA module for self-healing erasure coding

Copyright 2026 Ahmet Inan <xdsopl@gmail.com>
*/

#include "blake2.h"

#define DLEN_MAX 32
#define MLEN_MAX (1 << 20)
#define BLEN_MAX 8192
#define HLEN_MAX 16
#define HEIGHT_MAX 8
#define BCNT_MAX (1 << HEIGHT_MAX)

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
	unsigned char key = 0; // prevent second preimage attack
	blake2s_init_key(&init, hlen, &key, 1);
	int leaves = 1 << height;
	int woff = leaves - 1;
	for (int i = 0; i < leaves; i++) {
		state = init;
		blake2s_update(&state, blocks+blen*i, blen);
		blake2s_final(&state, hashes+hlen*(woff+i), hlen);
	}
	key = 1; // put internal nodes into a different domain
	blake2s_init_key(&init, hlen, &key, 1);
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

