/*
Native test for module/hydra.c

Copyright 2026 Ahmet Inan <xdsopl@gmail.com>
*/

#include <stdio.h>
#include <string.h>
#include "blake2.h"
#include "../module/hydra.h"

#define ENCODED_LEN (16 << 20)

extern unsigned char digest[32];
extern unsigned char message[CAPACITY_MAX];
extern unsigned char blocks[];
extern unsigned char block[BLEN_MAX];

int needed_blocks(int mlen, int blen, int height, int dflag);
int block_length(int mlen, int K, int height, int dflag);
int useful_height(int K);
int encode_message(int mlen, int blen, int height, int dflag);
int encode_block(int index);
int verify_block(int blen);
int decode_message(int blen);
int regenerate_tree(void);
int digest_message(int mlen);
int merkle_digest_leaf(unsigned char *hashes, unsigned char *leaf, int height, int llen, int dlen, int index);
int merkle_build_tree(unsigned char *hashes, int height, int dlen);
int merkle_copy_proof(unsigned char *proof, unsigned char *hashes, int height, int dlen, int index);

static unsigned char expect[32];
static unsigned char before[32];
static unsigned char encoded[ENCODED_LEN];
static unsigned char original[CAPACITY_MAX];
static unsigned char hashes[32*2*BCNT_MAX];
static unsigned char level[2][32*BCNT_MAX];
static unsigned char taken[BCNT_MAX];
static int chosen[K_MAX];
static int failures;
static unsigned int seed = 1;

static void fill(unsigned char *buf, int len)
{
	while (len--) {
		seed = seed * 1664525 + 1013904223;
		*buf++ = seed >> 24;
	}
}

static int rnd(int n)
{
	seed = seed * 1664525 + 1013904223;
	return (seed >> 8) % n;
}

static void to_hex(char *str, unsigned char *buf, int len)
{
	while (len--) {
		sprintf(str, "%02x", *buf++);
		str += 2;
	}
}

static void check(int ok, const char *what, int mlen, int blen, int height, int dflag)
{
	if (ok)
		return;
	printf("FAILED: %s (mlen %d, blen %d, height %d, dflag %d)\n", what, mlen, blen, height, dflag);
	++failures;
}

static void reference(unsigned char *out, int dlen, unsigned char *in, int len)
{
	blake2s_state state;
	blake2s_init(&state, dlen);
	blake2s_update(&state, in, len);
	blake2s_final(&state, out, dlen);
}

static void keyed(unsigned char *out, int dlen, unsigned char key, unsigned char *in, int len)
{
	blake2s_state state;
	blake2s_init_key(&state, dlen, &key, 1);
	blake2s_update(&state, in, len);
	blake2s_final(&state, out, dlen);
}

static int overhead(int height, int dflag)
{
	return 4 + (dflag ? 32 : 16) * (height + 1);
}

static unsigned header(const unsigned char *buf)
{
	return buf[0] | buf[1] << 8 | buf[2] << 16 | (unsigned)buf[3] << 24;
}

static void set_header(unsigned char *buf, unsigned head)
{
	buf[0] = head;
	buf[1] = head >> 8;
	buf[2] = head >> 16;
	buf[3] = head >> 24;
}

static int encode_all(int mlen, int blen, int height, int dflag)
{
	int K = encode_message(mlen, blen, height, dflag);
	if (K < 0)
		return K;
	for (int i = 0; i < 1 << height; ++i) {
		if (encode_block(i) != blen)
			return -1;
		memcpy(encoded+blen*i, block, blen);
	}
	return K;
}

static void choose(int K, int N)
{
	memset(taken, 0, N);
	for (int i = 0; i < K; ++i) {
		int index = rnd(N);
		while (taken[index])
			index = rnd(N);
		taken[index] = 1;
		chosen[i] = index;
	}
}

static int decode_chosen(int K, int blen)
{
	for (int i = 0; i < K; ++i)
		memcpy(blocks+blen*i, encoded+blen*chosen[i], blen);
	return decode_message(blen);
}

static void known_answers(void)
{
	char str[65];
	memcpy(message, "abc", 3);
	check(!digest_message(3), "digest_message", 3, 0, 0, 0);
	to_hex(str, digest, 32);
	check(!strcmp(str, "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982"), "known digest of abc", 3, 0, 0, 0);
	reference(expect, 16, message, 3);
	check(memcmp(digest, expect, 16) != 0, "truncated digest differs from 16 byte blake2s", 3, 0, 0, 0);
}

static void test_lengths(void)
{
	static const int mlens[] = { 1, 31, 32, 33, 64, 65, 1000, MLEN_MAX };
	for (int i = 0; i < (int)(sizeof(mlens) / sizeof(mlens[0])); ++i) {
		fill(message, mlens[i]);
		reference(expect, 32, message, mlens[i]);
		check(!digest_message(mlens[i]), "digest_message", mlens[i], 0, 0, 0);
		check(!memcmp(digest, expect, 32), "digest_message matches blake2s", mlens[i], 0, 0, 0);
	}
	memcpy(before, digest, 32);
	check(digest_message(0) == -1, "digest_message rejects mlen 0", 0, 0, 0, 0);
	check(digest_message(-1) == -1, "digest_message rejects mlen -1", -1, 0, 0, 0);
	check(digest_message(MLEN_MAX + 1) == -1, "digest_message rejects mlen too long", MLEN_MAX + 1, 0, 0, 0);
	check(!memcmp(digest, before, 32), "rejected calls leave digest alone", 0, 0, 0, 0);
}

static void test_state(void)
{
	check(encode_block(0) == -1, "encode_block before any tree", 0, 0, 0, 0);
	check(regenerate_tree() == -1, "regenerate_tree before decoding", 0, 0, 0, 0);
	fill(message, 100);
	check(encode_message(100, 256, 4, 0) > 0, "encode_message", 100, 256, 4, 0);
	check(encode_block(16) == -1, "encode_block rejects index N", 100, 256, 4, 0);
	check(encode_block(-1) == -1, "encode_block rejects index -1", 100, 256, 4, 0);
	check(encode_message(0, 256, 4, 0) == -1, "encode_message rejects mlen 0", 0, 256, 4, 0);
	check(encode_block(0) == -1, "a failed encode_message drops the tree", 0, 256, 4, 0);
	check(encode_message(100, 256, 4, 0) > 0, "encode_message", 100, 256, 4, 0);
	memset(blocks, 0, 256);
	check(decode_message(256) == -1, "decode_message rejects zeros", 100, 256, 4, 0);
	check(encode_block(0) == -1, "a failed decode_message drops the tree", 100, 256, 4, 0);
}

static void test_header(int K, int height, int dflag, int index)
{
	int mlen = K == 1 ? 12 : (31 * K - 31) / 8;
	int blen = block_length(mlen, K, height, dflag);
	check(blen > 0, "block_length", mlen, blen, height, dflag);
	fill(message, mlen);
	check(encode_message(mlen, blen, height, dflag) == K, "encode_message gives K", mlen, blen, height, dflag);
	check(encode_block(index) == blen, "encode_block", mlen, blen, height, dflag);
	check(block[0] == (index & 255), "byte 0 holds the low byte of the index", mlen, blen, height, dflag);
	check(block[1] == index >> 8, "byte 1 holds the high byte of the index", mlen, blen, height, dflag);
	check(block[2] == ((K - 1) & 255), "byte 2 holds the low byte of K - 1", mlen, blen, height, dflag);
	check(block[3] == ((K - 1) >> 8 | (height - 1) << 2 | dflag << 7), "byte 3 holds K - 1, height - 1 and the flag", mlen, blen, height, dflag);
}

static void test_tree(int mlen, int blen, int height, int dflag)
{
	int dlen = dflag ? 32 : 16;
	int N = 1 << height;
	int plen = blen - overhead(height, dflag);
	int cur = 0;
	fill(message, mlen);
	int K = encode_all(mlen, blen, height, dflag);
	check(K > 0, "encode_all", mlen, blen, height, dflag);
	if (K < 0)
		return;
	for (int i = 0; i < N; ++i)
		keyed(level[cur]+dlen*i, dlen, 0, encoded+blen*i, 4 + plen);
	for (int nodes = N / 2; nodes; nodes /= 2) {
		for (int i = 0; i < nodes; ++i)
			keyed(level[!cur]+dlen*i, dlen, 1, level[cur]+2*dlen*i, 2*dlen);
		cur = !cur;
	}
	for (int i = 0; i < N; ++i)
		check(!memcmp(encoded+blen*i+blen-dlen, level[cur], dlen), "root matches a tree over header and payload", mlen, blen, height, dflag);
}

static void test_planning(void)
{
	static const int mlens[] = { 1, 12, 100, 1000, 10000, 100000, MLEN_MAX };
	static const int blens[] = { 64, 256, 1024, 8192 };
	for (int a = 0; a < (int)(sizeof(mlens) / sizeof(mlens[0])); ++a)
	for (int b = 0; b < (int)(sizeof(blens) / sizeof(blens[0])); ++b)
	for (int height = 1; height <= HEIGHT_MAX; ++height)
	for (int dflag = 0; dflag < 2; ++dflag) {
		int mlen = mlens[a], budget = blens[b];
		int K = needed_blocks(mlen, budget, height, dflag);
		if (K < 0)
			continue;
		int blen = block_length(mlen, K, height, dflag);
		int plen = blen - overhead(height, dflag);
		check(blen > 0 && blen <= budget, "block_length fits the budget", mlen, budget, height, dflag);
		check(needed_blocks(mlen, blen, height, dflag) == K, "the shorter block keeps K", mlen, blen, height, dflag);
		check(message_capacity(K, plen) >= mlen, "K blocks hold the message", mlen, blen, height, dflag);
		check(plen == ((plen * 8) / 31 * 31 + 7) / 8, "no padding bytes", mlen, blen, height, dflag);
		int shorter = needed_blocks(mlen, blen - 1, height, dflag);
		check(shorter < 0 || shorter > K, "one byte less needs more blocks", mlen, blen - 1, height, dflag);
		check(K == 1 || message_capacity(K - 1, budget - overhead(height, dflag)) < mlen, "K is the smallest for the budget", mlen, budget, height, dflag);
	}
	check(block_length(3, 10, 4, 0) == -1, "block_length rejects a K that leaves whole blocks of padding", 3, 0, 4, 0);
	check(block_length(3, 1, 4, 0) > 0, "block_length with K = 1", 3, 0, 4, 0);
	check(useful_height(1) == 4, "useful_height(1)", 0, 0, 4, 0);
	check(useful_height(2) == 5, "useful_height(2)", 0, 0, 5, 0);
	check(useful_height(16) == 8, "useful_height(16)", 0, 0, 8, 0);
	check(useful_height(17) == 9, "useful_height(17)", 0, 0, 9, 0);
	check(useful_height(K_MAX) == 14, "useful_height(K_MAX)", 0, 0, 14, 0);
	check(useful_height(0) == -1, "useful_height rejects 0", 0, 0, 0, 0);
	check(useful_height(K_MAX + 1) == -1, "useful_height rejects K_MAX + 1", 0, 0, 0, 0);
}

static void test_bad_arguments(void)
{
	check(needed_blocks(0, 256, 4, 0) == -1, "needed_blocks rejects mlen 0", 0, 256, 4, 0);
	check(needed_blocks(MLEN_MAX + 1, 8192, 12, 0) == -1, "needed_blocks rejects mlen too long", MLEN_MAX + 1, 8192, 12, 0);
	check(needed_blocks(100, 0, 4, 0) == -1, "needed_blocks rejects blen 0", 100, 0, 4, 0);
	check(needed_blocks(100, BLEN_MAX + 1, 4, 0) == -1, "needed_blocks rejects blen too long", 100, BLEN_MAX + 1, 4, 0);
	check(needed_blocks(100, 256, 0, 0) == -1, "needed_blocks rejects height 0", 100, 256, 0, 0);
	check(needed_blocks(100, 256, HEIGHT_MAX + 1, 0) == -1, "needed_blocks rejects height too large", 100, 256, HEIGHT_MAX + 1, 0);
	check(needed_blocks(100, 256, 4, 2) == -1, "needed_blocks rejects dflag 2", 100, 256, 4, 2);
	check(needed_blocks(100, 103, 5, 0) == -1, "needed_blocks rejects a block without room for a value", 100, 103, 5, 0);
	check(needed_blocks(100, 104, 5, 0) == 27, "needed_blocks accepts room for one value", 100, 104, 5, 0);
	check(needed_blocks(1000, 140, 4, 0) == -1, "needed_blocks rejects more than N blocks", 1000, 140, 4, 0);
	check(needed_blocks(1000, 140, 5, 0) == 26, "needed_blocks accepts the same with a larger N", 1000, 140, 5, 0);
	check(needed_blocks(MLEN_MAX, 1024, 16, 0) == -1, "needed_blocks rejects more than K_MAX blocks", MLEN_MAX, 1024, 16, 0);
	check(needed_blocks(8201852, 8192, 10, 0) == K_MAX, "the largest message fills K_MAX blocks of BLEN_MAX", 8201852, 8192, 10, 0);
	check(needed_blocks(8201853, 8192, 10, 0) == -1, "one byte more needs more than K_MAX blocks", 8201853, 8192, 10, 0);
	check(block_length(0, 1, 4, 0) == -1, "block_length rejects mlen 0", 0, 0, 4, 0);
	check(block_length(100, 0, 4, 0) == -1, "block_length rejects K 0", 100, 0, 4, 0);
	check(block_length(100, K_MAX + 1, 16, 0) == -1, "block_length rejects K_MAX + 1", 100, 0, 16, 0);
	check(block_length(100, 17, 4, 0) == -1, "block_length rejects K above N", 100, 0, 4, 0);
	check(block_length(100, 1, 0, 0) == -1, "block_length rejects height 0", 100, 0, 0, 0);
	check(block_length(100, 1, 4, -1) == -1, "block_length rejects dflag -1", 100, 0, 4, -1);
	check(block_length(100000, 2, 4, 0) == -1, "block_length rejects blocks above BLEN_MAX", 100000, 0, 4, 0);
	check(encode_message(100, 256, 4, 2) == -1, "encode_message rejects dflag 2", 100, 256, 4, 2);
	check(decode_message(3) == -1, "decode_message rejects blen 3", 0, 3, 0, 0);
	check(decode_message(BLEN_MAX + 1) == -1, "decode_message rejects blen too long", 0, BLEN_MAX + 1, 0, 0);
	check(verify_block(3) == -1, "verify_block rejects blen 3", 0, 3, 0, 0);
	check(verify_block(BLEN_MAX + 1) == -1, "verify_block rejects blen too long", 0, BLEN_MAX + 1, 0, 0);
}

static void test_round_trip(int mlen, int blen, int height, int dflag)
{
	int N = 1 << height;
	fill(message, mlen);
	memcpy(original, message, mlen);
	check(!digest_message(mlen), "digest_message before encoding", mlen, blen, height, dflag);
	memcpy(before, digest, 32);
	int K = encode_message(mlen, blen, height, dflag);
	check(K == needed_blocks(mlen, blen, height, dflag), "encode_message gives needed_blocks", mlen, blen, height, dflag);
	if (K < 1)
		return;
	choose(K, N);
	for (int i = 0; i < K; ++i) {
		check(encode_block(chosen[i]) == blen, "encode_block", mlen, blen, height, dflag);
		check(!verify_block(blen), "verify_block", mlen, blen, height, dflag);
		memcpy(blocks+blen*i, block, blen);
	}
	memset(message, 255, mlen);
	int len = decode_message(blen);
	int plen = blen - overhead(height, dflag);
	check(len == message_capacity(K, plen), "decode_message gives the capacity", mlen, blen, height, dflag);
	if (len < mlen)
		return;
	check(!memcmp(message, original, mlen), "decoded message matches", mlen, blen, height, dflag);
	for (int i = mlen; i < len; ++i)
		check(!message[i], "decoded padding is zero", mlen, blen, height, dflag);
	check(!digest_message(mlen), "digest_message after decoding", mlen, blen, height, dflag);
	check(!memcmp(digest, before, 32), "digest after decoding matches digest before encoding", mlen, blen, height, dflag);
}

static void test_padding_bytes(int mlen, int height, int dflag)
{
	int K = needed_blocks(mlen, 1024, height, dflag);
	int minimal = block_length(mlen, K, height, dflag);
	for (int extra = 1; extra <= 5; ++extra) {
		int blen = minimal + extra;
		int plen = blen - overhead(height, dflag);
		int used = ((plen * 8) / 31 * 31 + 7) / 8;
		int longer = needed_blocks(mlen, blen, height, dflag);
		fill(message, mlen);
		check(longer > 0 && longer <= K, "a longer block needs no more blocks", mlen, blen, height, dflag);
		check(encode_all(mlen, blen, height, dflag) == longer, "encode_message with a longer block", mlen, blen, height, dflag);
		for (int i = 0; i < 1 << height; ++i)
			for (int j = used; j < plen; ++j)
				check(!encoded[blen*i+4+j], "padding bytes are zero", mlen, blen, height, dflag);
		choose(longer, 1 << height);
		check(decode_chosen(longer, blen) >= mlen, "decode_message with a longer block", mlen, blen, height, dflag);
	}
}

static void forge_tree(int N, int blen, int dflag, int height)
{
	int dlen = dflag ? 32 : 16;
	int plen = blen - overhead(height, dflag);
	for (int i = 0; i < N; ++i)
		merkle_digest_leaf(hashes, encoded+blen*i, height, 4 + plen, dlen, i);
	merkle_build_tree(hashes, height, dlen);
	for (int i = 0; i < N; ++i)
		merkle_copy_proof(encoded+blen*i+4+plen, hashes, height, dlen, i);
}

static int verify_encoded(int index, int blen)
{
	memcpy(block, encoded+blen*index, blen);
	return verify_block(blen);
}

static void test_forged(void)
{
	int mlen = 1000, budget = 256, height = 5, dflag = 0;
	int N = 1 << height;
	int K = needed_blocks(mlen, budget, height, dflag);
	int blen = block_length(mlen, K, height, dflag);
	int plen = blen - overhead(height, dflag);
	int bits = (plen * 8) / 31 * 31;
	fill(message, mlen);
	check(encode_all(mlen, blen, height, dflag) == K, "encode_all", mlen, blen, height, dflag);
	check(bits % 8 != 0, "the payload has padding bits", mlen, blen, height, dflag);
	forge_tree(N, blen, dflag, height);
	check(!verify_encoded(3, blen), "rebuilt tree verifies", mlen, blen, height, dflag);
	encoded[blen*3+4+bits/8] |= 128;
	forge_tree(N, blen, dflag, height);
	check(verify_encoded(3, blen) == -1, "verify_block rejects a padding bit with a valid proof", mlen, blen, height, dflag);
	check(!verify_encoded(4, blen), "the other blocks still verify", mlen, blen, height, dflag);
	encoded[blen*3+4+bits/8] &= 127;
	set_header(encoded+blen*5, header(encoded+blen*5) | 1u << 30);
	forge_tree(N, blen, dflag, height);
	check(verify_encoded(5, blen) == -1, "verify_block rejects the reserved bit with a valid proof", mlen, blen, height, dflag);
	set_header(encoded+blen*5, header(encoded+blen*5) & ~(1u << 30));
	set_header(encoded+blen*6, (header(encoded+blen*6) & 0xFC00FFFF) | (unsigned)(N) << 16);
	forge_tree(N, blen, dflag, height);
	check(verify_encoded(6, blen) == -1, "verify_block rejects K above N with a valid proof", mlen, blen, height, dflag);
	check(encode_all(mlen, blen, height, dflag) == K, "encode_all", mlen, blen, height, dflag);
	set_header(encoded+blen*1, header(encoded+blen*1) + (1u << 16));
	forge_tree(N, blen, dflag, height);
	check(!verify_encoded(1, blen), "a block claiming K + 1 verifies in a forged tree", mlen, blen, height, dflag);
	for (int i = 0; i < K; ++i)
		chosen[i] = i;
	check(decode_chosen(K, blen) == -1, "decode_message rejects blocks that disagree on K", mlen, blen, height, dflag);
	check(encode_all(mlen, blen, height, dflag) == K, "encode_all", mlen, blen, height, dflag);
	fill(encoded+4, bits / 8);
	forge_tree(N, blen, dflag, height);
	for (int i = 0; i < N; ++i)
		check(!verify_encoded(i, blen), "a tree over blocks that are no codeword still verifies", mlen, blen, height, dflag);
	for (int i = 0; i < K; ++i)
		chosen[i] = i;
	check(decode_chosen(K, blen) > 0, "decode_message cannot tell", mlen, blen, height, dflag);
	check(regenerate_tree() == -1, "regenerate_tree catches it", mlen, blen, height, dflag);
	check(encode_block(0) == -1, "no blocks to relay after a failed regenerate_tree", mlen, blen, height, dflag);
}

static void test_mixed(void)
{
	int mlen = 5000, budget = 512, height = 6, dflag = 1;
	int K = needed_blocks(mlen, budget, height, dflag);
	int blen = block_length(mlen, K, height, dflag);
	int N = 1 << height;
	fill(message, mlen);
	check(encode_all(mlen, blen, height, dflag) == K, "encode_all", mlen, blen, height, dflag);
	memcpy(encoded+blen*N, encoded, blen * N);
	fill(message, mlen);
	check(encode_all(mlen, blen, height, dflag) == K, "encode_all another message", mlen, blen, height, dflag);
	for (int i = 0; i < K; ++i)
		chosen[i] = i;
	check(decode_chosen(K, blen) > 0, "decode_message with K distinct blocks", mlen, blen, height, dflag);
	chosen[K-1] = chosen[0];
	check(decode_chosen(K, blen) == -1, "decode_message rejects a duplicate", mlen, blen, height, dflag);
	chosen[K-1] = N + K - 1;
	check(decode_chosen(K, blen) == -1, "decode_message rejects a block of another message", mlen, blen, height, dflag);
	chosen[K-1] = K - 1;
	check(decode_chosen(K, blen) > 0, "decode_message works again", mlen, blen, height, dflag);
	check(decode_message(blen - 1) == -1, "decode_message rejects the wrong length", mlen, blen - 1, height, dflag);
	check(verify_encoded(0, blen - 1) == -1, "verify_block rejects one byte less", mlen, blen - 1, height, dflag);
	check(verify_encoded(0, blen + 1) == -1, "verify_block rejects one byte more", mlen, blen + 1, height, dflag);
	fill(message, mlen);
	check(encode_all(mlen, blen, height - 1, dflag) > 0, "encode_all with a smaller tree", mlen, blen, height - 1, dflag);
	memcpy(blocks+blen*(K-1), encoded+blen*(K-1), blen);
	for (int i = 0; i < K - 1; ++i)
		memcpy(blocks+blen*i, encoded+blen*(N+i), blen);
	check(decode_message(blen) == -1, "decode_message rejects blocks with another height", mlen, blen, height, dflag);
}

static void test_relay(int mlen, int blen, int height, int dflag)
{
	int N = 1 << height;
	fill(message, mlen);
	int K = encode_all(mlen, blen, height, dflag);
	check(K > 0, "encode_all", mlen, blen, height, dflag);
	if (K < 1)
		return;
	choose(K, N);
	memset(message, 255, CAPACITY_MAX);
	check(decode_chosen(K, blen) >= mlen, "decode_message", mlen, blen, height, dflag);
	check(encode_block(0) == -1, "no blocks to relay before regenerate_tree", mlen, blen, height, dflag);
	check(!regenerate_tree(), "regenerate_tree", mlen, blen, height, dflag);
	int same = 1;
	for (int i = 0; i < N; ++i)
		same &= encode_block(i) == blen && !memcmp(block, encoded+blen*i, blen);
	check(same, "a relay regenerates every block", mlen, blen, height, dflag);
	check(regenerate_tree() == -1, "regenerate_tree only once per decode", mlen, blen, height, dflag);
}

static void test_wide(int mlen, int dflag)
{
	int height = HEIGHT_MAX;
	int N = 1 << height;
	int K = needed_blocks(mlen, 1024, height, dflag);
	int blen = block_length(mlen, K, height, dflag);
	fill(message, mlen);
	memcpy(original, message, mlen);
	check(encode_message(mlen, blen, height, dflag) == K, "encode_message with N = 65536", mlen, blen, height, dflag);
	for (int i = 0; i < K; ++i) {
		check(encode_block(N - 1 - 997 * i) == blen, "encode_block with a high index", mlen, blen, height, dflag);
		memcpy(blocks+blen*i, block, blen);
	}
	check(decode_message(blen) >= mlen, "decode_message from high indices", mlen, blen, height, dflag);
	check(!memcmp(message, original, mlen), "decoded message matches", mlen, blen, height, dflag);
}

int main(void)
{
	known_answers();
	test_lengths();
	test_state();
	test_header(1, 4, 0, 5);
	test_header(3, 16, 1, 0xABCD);
	test_header(K_MAX, 11, 0, 2047);
	test_tree(12, 72, 2, 0);
	test_tree(1000, 300, 5, 1);
	test_planning();
	test_bad_arguments();
	test_round_trip(12, 72, 2, 0);
	test_round_trip(12, 120, 2, 1);
	test_round_trip(12, 200, 4, 0);
	test_round_trip(1000, 256, 8, 0);
	test_round_trip(900, 300, 8, 1);
	test_round_trip(5000, 512, 9, 1);
	test_round_trip(100000, 1024, 12, 0);
	test_round_trip(8201852, 8192, 10, 0);
	test_round_trip(7932, 252, 14, 0);
	test_padding_bytes(3000, 6, 0);
	test_padding_bytes(3000, 6, 1);
	test_forged();
	test_mixed();
	test_relay(12, 72, 2, 0);
	test_relay(1000, 256, 8, 0);
	test_relay(100000, 2048, 10, 1);
	test_wide(100, 0);
	test_wide(20000, 1);
	if (failures) {
		printf("hydra_test: %d failures\n", failures);
		return 1;
	}
	printf("hydra_test: ok\n");
	return 0;
}

