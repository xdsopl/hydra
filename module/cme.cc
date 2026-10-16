/*
WebAssembly HYDRA module for self-healing erasure coding

Copyright 2026 Ahmet Inan <xdsopl@gmail.com>
*/

#define assert(expr) do {} while (0)
#include "stdint.h"
#include "prime_field.hh"
#include "cauchy_prime_field_erasure_coding.hh"
#include "mersenne_packing.hh"

#define MLEN_MAX (1 << 20)
#define BLEN_MAX 8192

typedef CODE::PrimeField<uint32_t, 0x7FFFFFFF> M31;
static CODE::MersenneRemapping<MLEN_MAX> remap;
static CODE::CauchyPrimeFieldErasureCoding<M31> cme;
static M31 message_values[(31 + MLEN_MAX * 8 + 30) / 31];
static M31 chunk_values[(BLEN_MAX * 8) / 31];

extern "C" {

int cme_encode_message(unsigned char *blocks, unsigned char *message, int K, int N, int mlen, int blen)
{
	if (mlen < 1 || mlen > MLEN_MAX)
		return -1;
	if (blen < 1 || blen > BLEN_MAX)
		return -1;
	if (mlen <= blen)
		return -1;
	if (K < 1 || N < K)
		return -1;
	message_values[0] = remap.encode(message_values+1, message, mlen);
	int block_values = (31 + mlen * 8 + K * 31 - 1) / (K * 31);
	int block_bits = block_values * 31;
	int block_bytes = (block_bits + 7) / 8;
	if (blen < block_bytes)
		return -1;
	int total_values = block_values * K;
	for (int i = (31 + mlen * 8 + 30) / 31; i < total_values; ++i)
		message_values[i] = M31(0);
	for (int i = 0; i < N; ++i) {
		int chunk_ident = K + i;
		cme.encode(message_values, chunk_values, chunk_ident, block_values, K);
		CODE::MersennePacking::unpack(blocks+i*blen, chunk_values, block_values, blen);
		for (int j = (block_values * 31 + 7) / 8; j < blen; ++j)
			blocks[i*blen+j] = 0;
	}
	return 0;
}

}

