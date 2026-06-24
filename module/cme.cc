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
#define HEIGHT_MAX 8
#define BCNT_MAX (1 << HEIGHT_MAX)

typedef CODE::PrimeField<uint32_t, 0x7FFFFFFF> M31;
static CODE::MersenneRemapping<MLEN_MAX> remap;
static CODE::CauchyPrimeFieldErasureCoding<M31> cme;
static M31 message_values[(31 + MLEN_MAX * 8 + 30) / 31];
static M31 chunk_values[(BLEN_MAX * 8) / 31];

extern "C" {

__attribute__((visibility("default")))
extern unsigned char message[MLEN_MAX];
__attribute__((visibility("default")))
extern unsigned char blocks[BLEN_MAX*BCNT_MAX];

__attribute__((visibility("default")))
int ilog2_floor(int x)
{
	int l = -1;
	for (; x > 0; x /= 2)
		++l;
	return l;
}

__attribute__((visibility("default")))
int ilog2_ceil(int x)
{
	return ilog2_floor(x - 1) + 1;
}

__attribute__((visibility("default")))
int encode_message(int mlen, int blen)
{
	if (mlen < 1 || mlen > MLEN_MAX)
		return -1;
	if (blen < 1 || blen > BLEN_MAX)
		return -1;
	if (mlen <= blen)
		return -1;
	int avail_values = (blen * 8) / 31;
	int avail_bits = avail_values * 31;
	int block_count = (31 + mlen * 8 + avail_bits - 1) / avail_bits;
	int height = 1 + ilog2_ceil(block_count);
	if (height < 2 || height > HEIGHT_MAX)
		return -1;
	message_values[0] = remap.encode(message_values+1, message, mlen);
	int block_values = (31 + mlen * 8 + block_count * 31 - 1) / (block_count * 31);
	int total_values = block_values * block_count;
	for (int i = (31 + mlen * 8 + 30) / 31; i < total_values; ++i)
		message_values[i] = M31(0);
	int chunk_count = 1 << height;
	for (int i = 0; i < chunk_count; ++i) {
		int chunk_ident = block_count + i;
		cme.encode(message_values, chunk_values, chunk_ident, block_values, block_count);
		CODE::MersennePacking::unpack(blocks+i*blen, chunk_values, block_values, blen);
		for (int j = (block_values * 31 + 7) / 8; j < blen; ++j)
			blocks[i*blen+j] = 0;
	}
	return block_count;
}

}

