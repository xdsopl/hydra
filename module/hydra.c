/*
WebAssembly HYDRA module for self-healing erasure coding

Copyright 2026 Ahmet Inan <xdsopl@gmail.com>
*/

#include "blake2.h"

#define MLEN_MAX (1 << 24)

__attribute__((visibility("default")))
unsigned char digest[64];
__attribute__((visibility("default")))
unsigned char message[MLEN_MAX];

__attribute__((visibility("default")))
int digest_message(int mlen, int dlen)
{
	if (mlen < 0 || mlen > MLEN_MAX)
		return 1;
	if (dlen < 1 || dlen > 64)
		return 1;
	blake2b_state state;
	blake2b_init(&state, dlen);
	blake2b_update(&state, message, mlen);
	blake2b_final(&state, digest, dlen);
	return 0;
}

