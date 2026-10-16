/*
Native test for module/cme.cc

Copyright 2026 Ahmet Inan <xdsopl@gmail.com>
*/

#include "../module/cme.cc"
#include <stdio.h>
#include <string.h>

#define NMAX 256
#define VALUES_MAX ((31 + MLEN_MAX * 8 + 30) / 31)

static unsigned char message[MLEN_MAX];
static unsigned char output[MLEN_MAX];
static unsigned char blocks[BLEN_MAX*NMAX];
static unsigned char unpacked[BLEN_MAX];
static M31 received[VALUES_MAX];
static M31 data[VALUES_MAX];
static int idents[NMAX];
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

static void roundtrip(int K, int N, int mlen, int extra, int pattern)
{
	int block_values = (31 + mlen * 8 + K * 31 - 1) / (K * 31);
	int block_bytes = (block_values * 31 + 7) / 8;
	int blen = block_bytes + extra;
	if (blen > BLEN_MAX || mlen <= blen)
		return;
	fill_message(mlen, pattern);
	memset(blocks, 0xA5, blen * N);
	check(!cme_encode_message(blocks, message, K, N, mlen, blen), "encode_message", K, N, mlen, blen);
	for (int i = 0; i < N; ++i)
		for (int j = block_bytes; j < blen; ++j)
			check(!blocks[i*blen+j], "block padding is zero", K, N, mlen, blen);
	for (int variant = 0; variant < 4; ++variant) {
		if (N == K && variant)
			break;
		choose_blocks(K, N, variant);
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
}

static void rejections()
{
	int K = 4, N = 8, mlen = 1000;
	int block_values = (31 + mlen * 8 + K * 31 - 1) / (K * 31);
	int block_bytes = (block_values * 31 + 7) / 8;
	check(cme_encode_message(blocks, message, K, N, mlen, block_bytes - 1) == -1, "blen below block size is rejected", K, N, mlen, block_bytes - 1);
	check(cme_encode_message(blocks, message, K, N, mlen, mlen) == -1, "mlen equal blen is rejected", K, N, mlen, mlen);
	check(cme_encode_message(blocks, message, K, N, mlen, mlen + 1) == -1, "mlen below blen is rejected", K, N, mlen, mlen + 1);
	check(cme_encode_message(blocks, message, 0, N, mlen, block_bytes) == -1, "K 0 is rejected", 0, N, mlen, block_bytes);
	check(cme_encode_message(blocks, message, K, K - 1, mlen, block_bytes) == -1, "N below K is rejected", K, K - 1, mlen, block_bytes);
}

static bool wanted(int K, int mlen, int extra, int pattern)
{
	if (extra && pattern)
		return false;
	if ((K >= 64 || mlen >= 100000) && (extra || pattern > 1))
		return false;
	return true;
}

int main()
{
	static const int Ks[] = { 2, 3, 4, 5, 7, 8, 16, 31, 32, 33, 64, 100, 128 };
	static const int mlens[] = { 100, 1000, 4097, 50000, 1000000 };
	static const int extras[] = { 0, 1, 5 };
	for (int K : Ks) {
		int Ns[] = { 2, K };
		while (Ns[0] < 2 * K)
			Ns[0] *= 2;
		for (int N : Ns)
			for (int mlen : mlens)
				for (int extra : extras)
					for (int pattern = 0; pattern < 3; ++pattern)
						if (wanted(K, mlen, extra, pattern))
							roundtrip(K, N, mlen, extra, pattern);
	}
	rejections();
	if (failures) {
		printf("cme_test: %d failures\n", failures);
		return 1;
	}
	printf("cme_test: ok\n");
	return 0;
}

