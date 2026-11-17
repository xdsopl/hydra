/*
Native test for module/cme.cc

Copyright 2026 Ahmet Inan <xdsopl@gmail.com>
*/

#include "../module/cme.cc"
#include <stdio.h>
#include <string.h>

#define NMAX 256
#define VALUES_MAX ((31 + CAPACITY_MAX * 8 + 30) / 31)

static unsigned char message[CAPACITY_MAX];
static unsigned char output[CAPACITY_MAX];
static unsigned char blocks[BLEN_MAX*NMAX];
static unsigned char unpacked[BLEN_MAX];
static unsigned char chosen[BLEN_MAX*NMAX];
static int indices[NMAX];
static M31 received[VALUES_MAX];
static M31 data[VALUES_MAX];
static int idents[K_MAX];
static int picked[K_MAX];
static bool taken[N_MAX];
static int order[NMAX];
static int failures;
static unsigned int seed = 1;

static unsigned int rnd()
{
	seed = seed * 1664525 + 1013904223;
	return seed >> 8;
}

static void check(bool ok, const char *what, int K, int N, int mlen, int blen)
{
	if (ok)
		return;
	printf("FAILED: %s (K %d, N %d, mlen %d, blen %d)\n", what, K, N, mlen, blen);
	++failures;
}

static void fill_message(int mlen, int pattern)
{
	for (int i = 0; i < mlen; ++i)
		message[i] = pattern == 0 ? rnd() : pattern == 1 ? 255 : 0;
}

static void choose_blocks(int K, int N, int variant)
{
	for (int i = 0; i < N; ++i)
		order[i] = i;
	if (variant == 1)
		for (int i = 0; i < K; ++i)
			order[i] = N - K + i;
	if (variant == 2)
		for (int i = 0; i < K; ++i)
			order[i] = N - 1 - i;
	if (variant >= 3)
		for (int i = 0; i < K; ++i) {
			int j = i + rnd() % (N - i);
			int tmp = order[i];
			order[i] = order[j];
			order[j] = tmp;
		}
}

static void roundtrip(int K, int N, int mlen, int blen, int pattern)
{
	int block_values = (blen * 8) / 31;
	int block_bytes = (block_values * 31 + 7) / 8;
	fill_message(mlen, pattern);
	memset(blocks, 0xA5, blen * N);
	check(!cme_encode_message(blocks, message, K, N, mlen, blen, blen), "encode_message", K, N, mlen, blen);
	for (int i = 0; i < N; ++i)
		for (int j = block_bytes; j < blen; ++j)
			check(!blocks[i*blen+j], "block padding is zero", K, N, mlen, blen);
	for (int variant = 0; variant < 4; ++variant) {
		if (N == K && variant)
			break;
		choose_blocks(K, N, variant);
		if (!variant) {
			for (int j = 0; j < K; ++j) {
				idents[j] = K + order[j];
				CODE::MersennePacking::pack(received+block_values*j, blocks+blen*order[j], block_values, block_bytes);
				CODE::MersennePacking::unpack(unpacked, received+block_values*j, block_values, block_bytes);
				check(!memcmp(unpacked, blocks+blen*order[j], block_bytes), "block packing roundtrip", K, N, mlen, blen);
			}
			for (int i = 0; i < K; ++i)
				cme.decode(data+block_values*i, received, idents, i, block_values, K);
			for (int i = 1 + (mlen * 8 + 30) / 31; i < block_values * K; ++i)
				check(data[i] == M31(0), "padding values decode to zero", K, N, mlen, blen);
			CODE::MersennePacking::decode(output, data+1, mlen, data[0]);
			check(!memcmp(output, message, mlen), "decoded message matches", K, N, mlen, blen);
		}
		for (int j = 0; j < K; ++j) {
			indices[j] = order[j];
			memcpy(chosen+blen*j, blocks+blen*order[j], blen);
		}
		memset(output, 0xA5, mlen);
		check(!cme_decode_message(output, chosen, indices, K, blen, blen), "decode_message", K, N, mlen, blen);
		check(!memcmp(output, message, mlen), "decode_message output matches", K, N, mlen, blen);
	}
}

static void rejections()
{
	int K = 4, N = 8, blen = 100;
	int capacity = (K * (blen * 8 / 31) * 31 - 31) / 8;
	check(cme_encode_message(blocks, message, K, N, capacity + 1, blen, blen) == -1, "message larger than K blocks is rejected", K, N, capacity + 1, blen);
	check(cme_encode_message(blocks, message, K, N, 0, blen, blen) == -1, "mlen 0 is rejected", K, N, 0, blen);
	check(cme_prepare_message(message, K_MAX + 1, 1, blen) == -1, "K above K_MAX is rejected", K_MAX + 1, N, 1, blen);
	check(cme_prepare_message(message, K_MAX, 1, BLEN_MAX) == -1, "capacity above CAPACITY_MAX is rejected", K_MAX, N, 1, BLEN_MAX);
	check(cme_prepare_message(message, 1, 1, 4) == -1, "message larger than capacity 0 is rejected", 1, N, 1, 4);
	check(cme_encode_block(blocks, 0, 0, blen) == -1, "encode_block with K 0 is rejected", 0, N, 0, blen);
	check(cme_encode_block(blocks, K_MAX + 1, 0, blen) == -1, "encode_block with K above K_MAX is rejected", K_MAX + 1, N, 0, blen);
	check(cme_encode_block(blocks, K, -1, blen) == -1, "encode_block with index -1 is rejected", K, N, 0, blen);
	check(cme_encode_block(blocks, K, N_MAX, blen) == -1, "encode_block with index N_MAX is rejected", K, N_MAX, 0, blen);
	check(cme_encode_block(blocks, K, 0, 3) == -1, "encode_block with blen below 4 is rejected", K, N, 0, 3);
	check(cme_encode_message(blocks, message, 0, N, capacity, blen, blen) == -1, "K 0 is rejected", 0, N, capacity, blen);
	check(cme_encode_message(blocks, message, K, K - 1, capacity, blen, blen) == -1, "N below K is rejected", K, K - 1, capacity, blen);
	check(cme_encode_message(blocks, message, K, N, 4, 3, 3) == -1, "blen below 4 is rejected", K, N, 4, 3);
	check(cme_decode_message(output, blocks, indices, 0, blen, blen) == -1, "decode with K 0 is rejected", 0, N, 0, blen);
	check(cme_decode_message(output, blocks, indices, 1, 4, 4) == -1, "decode with capacity 0 is rejected", 1, N, 0, 4);
	check(cme_decode_message(output, blocks, indices, K_MAX + 1, blen, blen) == -1, "decode with K above K_MAX is rejected", K_MAX + 1, N, 0, blen);
	check(cme_decode_message(output, blocks, indices, K_MAX, BLEN_MAX, BLEN_MAX) == -1, "decode with capacity above CAPACITY_MAX is rejected", K_MAX, N, 0, BLEN_MAX);
	check(cme_decode_message(output, blocks, indices, K, 3, 3) == -1, "decode with blen below 4 is rejected", K, N, 0, 3);
	check(cme_encode_message(blocks, message, K, N, capacity, blen, blen - 1) == -1, "stride below blen is rejected", K, N, capacity, blen);
	check(cme_decode_message(output, blocks, indices, K, blen, blen - 1) == -1, "decode with stride below blen is rejected", K, N, 0, blen);
}

static void strided()
{
	int K = 5, N = 16, mlen = 1000, blen = 300, stride = blen + 3;
	fill_message(mlen, 0);
	memset(blocks, 0xA5, stride * N);
	check(!cme_encode_message(blocks, message, K, N, mlen, blen, stride), "strided encode_message", K, N, mlen, blen);
	check(!cme_encode_message(chosen, message, K, N, mlen, blen, blen), "packed encode_message", K, N, mlen, blen);
	for (int i = 0; i < N; ++i) {
		for (int j = blen; j < stride; ++j)
			check(blocks[i*stride+j] == 0xA5, "stride gap is untouched", K, N, mlen, blen);
		check(!memcmp(blocks+i*stride, chosen+i*blen, blen), "strided block matches packed block", K, N, mlen, blen);
	}
	for (int j = 0; j < K; ++j)
		indices[j] = N - K + j;
	memset(output, 0xA5, mlen);
	check(!cme_decode_message(output, blocks+(N-K)*stride, indices, K, blen, stride), "strided decode_message", K, N, mlen, blen);
	check(!memcmp(output, message, mlen), "strided decode_message output matches", K, N, mlen, blen);
}

static void decode_picked(int K, int mlen, int blen)
{
	memset(output, 0xA5, mlen);
	check(!cme_decode_message(output, chosen, picked, K, blen, blen), "decode_message from picked indices", K, N_MAX, mlen, blen);
}

static void blocks_by_index()
{
	static const int wide[] = { 256, 30000, N_MAX - 1 };
	int K = 3, N = 256, blen = 100;
	int capacity = message_capacity(K, blen);
	int mlen = capacity - 5;
	fill_message(mlen, 0);
	memset(message+mlen, 0xA5, capacity - mlen);
	check(!cme_encode_message(blocks, message, K, N, mlen, blen, blen), "encode_message", K, N, mlen, blen);
	check(!cme_prepare_message(message, K, mlen, blen), "prepare_message", K, N, mlen, blen);
	for (int i = 0; i < N; ++i) {
		memset(unpacked, 0xA5, blen);
		check(!cme_encode_block(unpacked, K, i, blen), "encode_block", K, N, mlen, blen);
		check(!memcmp(unpacked, blocks+blen*i, blen), "encode_block matches encode_message", K, N, mlen, blen);
	}
	for (int j = 0; j < K; ++j) {
		picked[j] = wide[j];
		check(!cme_encode_block(chosen+blen*j, K, picked[j], blen), "encode_block with a wide index", K, N_MAX, mlen, blen);
	}
	decode_picked(K, capacity, blen);
	check(!memcmp(output, message, mlen), "decoded from indices up to N_MAX - 1", K, N_MAX, mlen, blen);
	for (int i = mlen; i < capacity; ++i)
		check(!output[i], "message tail encodes as zero", K, N_MAX, mlen, blen);
}

static void largest_K()
{
	int K = K_MAX, blen = 4;
	int mlen = message_capacity(K, blen);
	fill_message(mlen, 0);
	check(!cme_prepare_message(message, K, mlen, blen), "prepare_message with K_MAX", K, N_MAX, mlen, blen);
	memset(taken, 0, sizeof(taken));
	for (int j = 0; j < K; ++j) {
		int index = rnd() % N_MAX;
		while (taken[index])
			index = rnd() % N_MAX;
		taken[index] = true;
		picked[j] = index;
		check(!cme_encode_block(chosen+blen*j, K, index, blen), "encode_block with K_MAX", K, N_MAX, mlen, blen);
	}
	decode_picked(K, mlen, blen);
	check(!memcmp(output, message, mlen), "decoded with K_MAX from random indices", K, N_MAX, mlen, blen);
}

static bool wanted(int K, int capacity, int mlen, int pattern)
{
	if (mlen < 1 || mlen > capacity)
		return false;
	if (capacity >= 100000 && (mlen != capacity || pattern > 1))
		return false;
	if (capacity > 300000 && K < 128)
		return false;
	return true;
}

int main()
{
	static const int Ks[] = { 1, 2, 3, 4, 5, 7, 8, 16, 31, 32, 33, 64, 100, 128 };
	static const int blens[] = { 4, 5, 8, 31, 32, 63, 64, 100, 1000, 4097, BLEN_MAX };
	for (int K : Ks) {
		int Ns[] = { 2, K };
		while (Ns[0] < 2 * K)
			Ns[0] *= 2;
		for (int N : Ns)
			for (int blen : blens) {
				if (K >= 64 && (N == K || (blen != 4 && blen != 63 && blen != 4097 && blen != BLEN_MAX)))
					continue;
				int capacity = (K * (blen * 8 / 31) * 31 - 31) / 8;
				int mlens[] = { capacity, capacity - 1, blen + 1, (blen + 1 + capacity) / 2, 1 };
				check(cme_encode_message(blocks, message, K, N, capacity + 1, blen, blen) == -1, "message larger than K blocks is rejected", K, N, capacity + 1, blen);
				for (int mlen : mlens)
					for (int pattern = 0; pattern < 3; ++pattern)
						if (wanted(K, capacity, mlen, pattern))
							roundtrip(K, N, mlen, blen, pattern);
			}
	}
	strided();
	rejections();
	blocks_by_index();
	largest_K();
	if (failures) {
		printf("cme_test: %d failures\n", failures);
		return 1;
	}
	printf("cme_test: ok\n");
	return 0;
}

