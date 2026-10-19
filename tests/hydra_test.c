/*
Native test for module/hydra.c

Copyright 2026 Ahmet Inan <xdsopl@gmail.com>
*/

#include <stdio.h>
#include <string.h>
#include "blake2.h"
#include "../module/hydra.h"

extern unsigned char digest[32];
extern unsigned char message[MLEN_MAX];
extern unsigned char blocks[BLEN_MAX*BCNT_MAX];

int encode_message(int mlen, int blen, int dflag);
int decode_message(int blen);
int digest_message(int mlen);

static unsigned char expect[32];
static unsigned char before[32];
static unsigned char encoded[BLEN_MAX*BCNT_MAX];
static unsigned char original[MLEN_MAX];
static int failures;
static unsigned int seed = 1;

static void fill(unsigned char *buf, int len)
{
	while (len--) {
		seed = seed * 1664525 + 1013904223;
		*buf++ = seed >> 24;
	}
}

static void to_hex(char *str, unsigned char *buf, int len)
{
	while (len--) {
		sprintf(str, "%02x", *buf++);
		str += 2;
	}
}

static void check(int ok, const char *what, int mlen, int blen, int dflag)
{
	if (ok)
		return;
	printf("FAILED: %s (mlen %d, blen %d, dflag %d)\n", what, mlen, blen, dflag);
	++failures;
}

static void reference(unsigned char *out, int dlen, unsigned char *in, int len)
{
	blake2s_state state;
	blake2s_init(&state, dlen);
	blake2s_update(&state, in, len);
	blake2s_final(&state, out, dlen);
}

static void known_answers(void)
{
	char str[65];
	memcpy(message, "abc", 3);
	check(!digest_message(3), "digest_message", 3, 0, 0);
	to_hex(str, digest, 32);
	check(!strcmp(str, "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982"), "known digest of abc", 3, 0, 0);
	reference(expect, 16, message, 3);
	check(memcmp(digest, expect, 16) != 0, "truncated digest differs from 16 byte blake2s", 3, 0, 0);
}

static void test_lengths(void)
{
	static const int mlens[] = { 1, 31, 32, 33, 64, 65, 1000, MLEN_MAX };
	for (int i = 0; i < (int)(sizeof(mlens) / sizeof(mlens[0])); ++i) {
		fill(message, mlens[i]);
		reference(expect, 32, message, mlens[i]);
		check(!digest_message(mlens[i]), "digest_message", mlens[i], 0, 0);
		check(!memcmp(digest, expect, 32), "digest_message matches blake2s", mlens[i], 0, 0);
	}
	memcpy(before, digest, 32);
	check(digest_message(0) == -1, "digest_message rejects mlen 0", 0, 0, 0);
	check(digest_message(-1) == -1, "digest_message rejects mlen -1", -1, 0, 0);
	check(digest_message(MLEN_MAX + 1) == -1, "digest_message rejects mlen too long", MLEN_MAX + 1, 0, 0);
	check(!memcmp(digest, before, 32), "rejected calls leave digest alone", 0, 0, 0);
}

static void test_round_trip(int mlen, int blen, int dflag)
{
	fill(message, mlen);
	check(!digest_message(mlen), "digest_message before encoding", mlen, blen, dflag);
	memcpy(before, digest, 32);
	int N = encode_message(mlen, blen, dflag);
	check(N > 0, "encode_message", mlen, blen, dflag);
	if (N < 1)
		return;
	int K = (blocks[0] & 127) + 1;
	memmove(blocks, blocks+blen*(N-K), blen * K);
	memset(message, 255, mlen);
	int len = decode_message(blen);
	check(len >= mlen, "decode_message", mlen, blen, dflag);
	if (len < mlen)
		return;
	check(!digest_message(mlen), "digest_message after decoding", mlen, blen, dflag);
	check(!memcmp(digest, before, 32), "digest after decoding matches digest before encoding", mlen, blen, dflag);
	if (len == mlen)
		return;
	check(!digest_message(len), "digest_message over the padding", len, blen, dflag);
	check(memcmp(digest, before, 32) != 0, "digest over the padding differs", len, blen, dflag);
}

static int decode_chosen(const int *chosen, int K, int mlen, int blen)
{
	for (int i = 0; i < K; ++i)
		memcpy(blocks+blen*i, encoded+blen*chosen[i], blen);
	memset(message, 255, mlen);
	return decode_message(blen);
}

static int decoded_original(const int *chosen, int K, int mlen, int blen)
{
	if (decode_chosen(chosen, K, mlen, blen) < mlen)
		return 0;
	return !memcmp(message, original, mlen);
}

static void test_duplicates(int mlen, int blen, int dflag)
{
	int chosen[BCNT_MAX];
	fill(message, mlen);
	memcpy(original, message, mlen);
	int N = encode_message(mlen, blen, dflag);
	check(N > 0, "encode_message", mlen, blen, dflag);
	if (N < 1)
		return;
	int K = (blocks[0] & 127) + 1;
	check(K > 1, "message needs more than one block", mlen, blen, dflag);
	if (K < 2)
		return;
	memcpy(encoded, blocks, blen * N);
	for (int i = 0; i < K; ++i)
		chosen[i] = N - 1 - i;
	check(decoded_original(chosen, K, mlen, blen), "decode_message with K distinct blocks", mlen, blen, dflag);
	chosen[K-1] = chosen[0];
	check(decode_chosen(chosen, K, mlen, blen) == -1, "decode_message rejects last block repeating the first", mlen, blen, dflag);
	chosen[K-1] = N - K;
	chosen[1] = chosen[K-2];
	check(decode_chosen(chosen, K, mlen, blen) == -1, "decode_message rejects a duplicate in the middle", mlen, blen, dflag);
	for (int i = 0; i < K; ++i)
		chosen[i] = 0;
	check(decode_chosen(chosen, K, mlen, blen) == -1, "decode_message rejects K copies of one block", mlen, blen, dflag);
	for (int i = 0; i < K; ++i)
		chosen[i] = i;
	check(decoded_original(chosen, K, mlen, blen), "decode_message works again after rejecting duplicates", mlen, blen, dflag);
}

int main(void)
{
	known_answers();
	test_lengths();
	test_round_trip(12, 32, 0);
	test_round_trip(12, 32, 1);
	test_round_trip(1000, 256, 0);
	test_round_trip(900, 256, 1);
	test_round_trip(5000, 512, 1);
	test_round_trip(100000, 1024, 0);
	test_round_trip(1029692, 8192, 0);
	test_duplicates(1000, 256, 0);
	test_duplicates(900, 256, 1);
	test_duplicates(100000, 1024, 0);
	if (failures) {
		printf("hydra_test: %d failures\n", failures);
		return 1;
	}
	printf("hydra_test: ok\n");
	return 0;
}

