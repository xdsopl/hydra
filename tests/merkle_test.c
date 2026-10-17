/*
Native test for module/merkle.c

Copyright 2026 Ahmet Inan <xdsopl@gmail.com>
*/

#include <stdio.h>
#include <string.h>
#include "blake2.h"

#define MLEN_MAX 8192
#define BLEN_MAX 8192
#define HEIGHT_MAX 8
#define BCNT_MAX (1 << HEIGHT_MAX)

int merkle_digest_message(unsigned char *digest, unsigned char *message, int mlen, int dlen);
int merkle_digest_blocks(unsigned char *hashes, unsigned char *blocks, int height, int blen, int stride, int dlen);
int merkle_extract_proof(unsigned char *block, unsigned char *proof, unsigned char *blocks, unsigned char *hashes, int height, int blen, int stride, int dlen, int index);
int merkle_verify_proof(unsigned char *block, unsigned char *proof, int height, int blen, int dlen, int index);

static unsigned char digest[32];
static unsigned char message[MLEN_MAX];
static unsigned char blocks[BLEN_MAX*BCNT_MAX];
static unsigned char hashes[32*2*BCNT_MAX];
static unsigned char block[BLEN_MAX];
static unsigned char proof[32*(HEIGHT_MAX+1)];
static unsigned char level[2][32*BCNT_MAX];
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

static void check(int ok, const char *what, int height, int blen, int dlen, int index)
{
	if (ok)
		return;
	printf("FAILED: %s (height %d, blen %d, dlen %d, index %d)\n", what, height, blen, dlen, index);
	++failures;
}

static void hash(unsigned char *out, int dlen, unsigned char key, unsigned char *in, int len)
{
	blake2s_state state;
	blake2s_init_key(&state, dlen, &key, 1);
	blake2s_update(&state, in, len);
	blake2s_final(&state, out, dlen);
}

static void reference_root(unsigned char *root, int height, int blen, int dlen)
{
	int cur = 0;
	int nodes = 1 << height;
	int i;
	for (i = 0; i < nodes; ++i)
		hash(level[cur]+dlen*i, dlen, 0, blocks+blen*i, blen);
	while (nodes > 1) {
		nodes /= 2;
		for (i = 0; i < nodes; ++i)
			hash(level[!cur]+dlen*i, dlen, 1, level[cur]+2*dlen*i, 2*dlen);
		cur = !cur;
	}
	memcpy(root, level[cur], dlen);
}

static void known_answers(void)
{
	char str[65];
	int i;
	for (i = 0; i < 16; ++i)
		blocks[i] = i;
	memcpy(message, "abc", 3);
	check(!merkle_digest_message(digest, message, 3, 32), "digest_message", 0, 0, 32, 0);
	to_hex(str, digest, 32);
	check(!strcmp(str, "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982"), "known digest of abc", 0, 3, 32, 0);
	check(!merkle_digest_message(digest, message, 3, 16), "digest_message", 0, 0, 16, 0);
	to_hex(str, digest, 16);
	check(!strcmp(str, "aa4938119b1dc7b87cbad0ffd200d0ae"), "known digest of abc", 0, 3, 16, 0);
	check(!merkle_digest_blocks(hashes, blocks, 2, 4, 4, 32), "digest_blocks", 2, 4, 32, 0);
	to_hex(str, hashes, 32);
	check(!strcmp(str, "694db3ceb3276ec7e774521402a8ecdb1321d18b03907942a997f1c56fe6f6c2"), "known root", 2, 4, 32, 0);
	check(!merkle_digest_blocks(hashes, blocks, 2, 4, 4, 16), "digest_blocks", 2, 4, 16, 0);
	to_hex(str, hashes, 16);
	check(!strcmp(str, "0a9b5e981248f84051173de6ded79be7"), "known root", 2, 4, 16, 0);
}

static void test_digest_message(void)
{
	static const int mlens[] = { 1, 31, 32, 33, 64, 65, 1000, MLEN_MAX };
	static const int dlens[] = { 1, 16, 32 };
	unsigned char expect[32];
	blake2s_state state;
	int i, j;
	for (i = 0; i < (int)(sizeof(mlens) / sizeof(mlens[0])); ++i) {
		fill(message, mlens[i]);
		for (j = 0; j < (int)(sizeof(dlens) / sizeof(dlens[0])); ++j) {
			blake2s_init(&state, dlens[j]);
			blake2s_update(&state, message, mlens[i]);
			blake2s_final(&state, expect, dlens[j]);
			check(!merkle_digest_message(digest, message, mlens[i], dlens[j]), "digest_message", 0, mlens[i], dlens[j], 0);
			check(!memcmp(digest, expect, dlens[j]), "digest_message matches blake2s", 0, mlens[i], dlens[j], 0);
		}
		check(merkle_digest_message(digest, message, mlens[i], 0) == 1, "digest_message rejects dlen 0", 0, mlens[i], 0, 0);
		check(merkle_digest_message(digest, message, mlens[i], 33) == 1, "digest_message rejects dlen 33", 0, mlens[i], 33, 0);
	}
}

static void flip(unsigned char *buf, int len, int index)
{
	buf[(index * 7) % len] ^= 1 << (index % 8);
}

static void test_tree(int height, int blen, int dlen)
{
	unsigned char root[32];
	int leaves = 1 << height;
	int index;
	fill(blocks, blen * leaves);
	check(!merkle_digest_blocks(hashes, blocks, height, blen, blen, dlen), "digest_blocks", height, blen, dlen, 0);
	reference_root(root, height, blen, dlen);
	check(!memcmp(hashes, root, dlen), "root matches reference", height, blen, dlen, 0);
	for (index = 0; index < leaves; ++index) {
		check(!merkle_extract_proof(block, proof, blocks, hashes, height, blen, blen, dlen, index), "extract_proof", height, blen, dlen, index);
		check(!memcmp(block, blocks+blen*index, blen), "extracted block", height, blen, dlen, index);
		check(!memcmp(proof, hashes+dlen*(leaves-1+(index^1)), dlen), "proof starts with sibling", height, blen, dlen, index);
		check(!memcmp(proof+dlen*height, root, dlen), "proof ends with root", height, blen, dlen, index);
		check(!merkle_verify_proof(block, proof, height, blen, dlen, index), "verify_proof", height, blen, dlen, index);
		if (dlen < 16)
			continue;
		flip(block, blen, index);
		check(merkle_verify_proof(block, proof, height, blen, dlen, index) == 1, "verify_proof rejects corrupted block", height, blen, dlen, index);
		flip(block, blen, index);
		flip(proof, dlen * (height + 1), index);
		check(merkle_verify_proof(block, proof, height, blen, dlen, index) == 1, "verify_proof rejects corrupted proof", height, blen, dlen, index);
		flip(proof, dlen * (height + 1), index);
		check(merkle_verify_proof(block, proof, height, blen, dlen, index ^ 1) == 1, "verify_proof rejects wrong index", height, blen, dlen, index);
		check(!merkle_verify_proof(block, proof, height, blen, dlen, index), "verify_proof after restoring", height, blen, dlen, index);
	}
	check(merkle_extract_proof(block, proof, blocks, hashes, height, blen, blen, dlen, -1) == 1, "extract_proof rejects index -1", height, blen, dlen, -1);
	check(merkle_extract_proof(block, proof, blocks, hashes, height, blen, blen, dlen, leaves) == 1, "extract_proof rejects index leaves", height, blen, dlen, leaves);
	check(merkle_verify_proof(block, proof, height, blen, dlen, -1) == 1, "verify_proof rejects index -1", height, blen, dlen, -1);
	check(merkle_verify_proof(block, proof, height, blen, dlen, leaves) == 1, "verify_proof rejects index leaves", height, blen, dlen, leaves);
}

static void test_bad_dlen(void)
{
	check(merkle_digest_blocks(hashes, blocks, 2, 4, 4, 0) == 1, "digest_blocks rejects dlen 0", 2, 4, 0, 0);
	check(merkle_digest_blocks(hashes, blocks, 2, 4, 4, 33) == 1, "digest_blocks rejects dlen 33", 2, 4, 33, 0);
	check(merkle_extract_proof(block, proof, blocks, hashes, 2, 4, 4, 0, 0) == 1, "extract_proof rejects dlen 0", 2, 4, 0, 0);
	check(merkle_extract_proof(block, proof, blocks, hashes, 2, 4, 4, 33, 0) == 1, "extract_proof rejects dlen 33", 2, 4, 33, 0);
	check(merkle_verify_proof(block, proof, 2, 4, 0, 0) == 1, "verify_proof rejects dlen 0", 2, 4, 0, 0);
	check(merkle_verify_proof(block, proof, 2, 4, 33, 0) == 1, "verify_proof rejects dlen 33", 2, 4, 33, 0);
}

int main(void)
{
	static const int heights[] = { 2, 3, 8 };
	static const int blens[] = { 1, 64, 1000, BLEN_MAX };
	static const int dlens[] = { 1, 16, 32 };
	int i, j, k;
	known_answers();
	test_digest_message();
	for (i = 0; i < (int)(sizeof(heights) / sizeof(heights[0])); ++i)
		for (j = 0; j < (int)(sizeof(blens) / sizeof(blens[0])); ++j)
			for (k = 0; k < (int)(sizeof(dlens) / sizeof(dlens[0])); ++k)
				test_tree(heights[i], blens[j], dlens[k]);
	test_bad_dlen();
	if (failures) {
		printf("merkle_test: %d failures\n", failures);
		return 1;
	}
	printf("merkle_test: ok\n");
	return 0;
}

