/*
Native test for module/merkle.c

Copyright 2026 Ahmet Inan <xdsopl@gmail.com>
*/

#include <stdio.h>
#include <string.h>
#include "blake2.h"

#define MLEN_MAX 8192
#define BLEN_MAX 8192
#define HEIGHT_MAX 16
#define BCNT_MAX (1 << HEIGHT_MAX)

int merkle_digest_message(unsigned char *digest, unsigned char *message, int mlen, int dlen);
int merkle_digest_leaf(unsigned char *hashes, unsigned char *leaf, int height, int llen, int dlen, int index);
int merkle_build_tree(unsigned char *hashes, int height, int dlen);
int merkle_copy_proof(unsigned char *proof, unsigned char *hashes, int height, int dlen, int index);
int merkle_verify_leaf(unsigned char *proof, unsigned char *leaf, int height, int llen, int dlen, int index);

static unsigned char digest[32];
static unsigned char message[MLEN_MAX];
static unsigned char leaf[BLEN_MAX];
static unsigned char other[BLEN_MAX];
static unsigned char proof[32*(HEIGHT_MAX+1)];
static unsigned char hashes[32*2*BCNT_MAX];
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

static void check(int ok, const char *what, int height, int llen, int dlen, int index)
{
	if (ok)
		return;
	printf("FAILED: %s (height %d, llen %d, dlen %d, index %d)\n", what, height, llen, dlen, index);
	++failures;
}

static void make_leaf(unsigned char *buf, int llen, int index)
{
	seed = 2654435761u * (index + 1) + llen;
	fill(buf, llen);
}

static void hash(unsigned char *out, int dlen, unsigned char key, unsigned char *in, int len)
{
	blake2s_state state;
	blake2s_init_key(&state, dlen, &key, 1);
	blake2s_update(&state, in, len);
	blake2s_final(&state, out, dlen);
}

static void known_answers(void)
{
	char str[65];
	int i;
	for (i = 0; i < 16; ++i)
		leaf[i] = i;
	memcpy(message, "abc", 3);
	check(!merkle_digest_message(digest, message, 3, 32), "digest_message", 0, 0, 32, 0);
	to_hex(str, digest, 32);
	check(!strcmp(str, "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982"), "known digest of abc", 0, 3, 32, 0);
	check(!merkle_digest_message(digest, message, 3, 16), "digest_message", 0, 0, 16, 0);
	to_hex(str, digest, 16);
	check(!strcmp(str, "aa4938119b1dc7b87cbad0ffd200d0ae"), "known digest of abc", 0, 3, 16, 0);
	for (i = 0; i < 4; ++i)
		check(!merkle_digest_leaf(hashes, leaf+4*i, 2, 4, 32, i), "digest_leaf", 2, 4, 32, i);
	check(!merkle_build_tree(hashes, 2, 32), "build_tree", 2, 4, 32, 0);
	to_hex(str, hashes, 32);
	check(!strcmp(str, "694db3ceb3276ec7e774521402a8ecdb1321d18b03907942a997f1c56fe6f6c2"), "known root", 2, 4, 32, 0);
	for (i = 0; i < 4; ++i)
		check(!merkle_digest_leaf(hashes, leaf+4*i, 2, 4, 16, i), "digest_leaf", 2, 4, 16, i);
	check(!merkle_build_tree(hashes, 2, 16), "build_tree", 2, 4, 16, 0);
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

static void test_tree(int height, int llen, int dlen, int step)
{
	unsigned char root[32];
	int leaves = 1 << height;
	int cur = 0;
	int nodes = leaves;
	int index, i;
	for (index = 0; index < leaves; ++index) {
		make_leaf(leaf, llen, index);
		check(!merkle_digest_leaf(hashes, leaf, height, llen, dlen, index), "digest_leaf", height, llen, dlen, index);
		hash(level[cur]+dlen*index, dlen, 0, leaf, llen);
	}
	check(!merkle_build_tree(hashes, height, dlen), "build_tree", height, llen, dlen, 0);
	while (nodes > 1) {
		nodes /= 2;
		for (i = 0; i < nodes; ++i)
			hash(level[!cur]+dlen*i, dlen, 1, level[cur]+2*dlen*i, 2*dlen);
		cur = !cur;
	}
	memcpy(root, level[cur], dlen);
	check(!memcmp(hashes, root, dlen), "root matches reference", height, llen, dlen, 0);
	for (index = 0; index < leaves; index += step) {
		make_leaf(leaf, llen, index);
		check(!merkle_copy_proof(proof, hashes, height, dlen, index), "copy_proof", height, llen, dlen, index);
		if (height)
			check(!memcmp(proof, hashes+dlen*(leaves-1+(index^1)), dlen), "proof starts with sibling", height, llen, dlen, index);
		check(!memcmp(proof+dlen*height, root, dlen), "proof ends with root", height, llen, dlen, index);
		check(!merkle_verify_leaf(proof, leaf, height, llen, dlen, index), "verify_leaf", height, llen, dlen, index);
		if (dlen < 16)
			continue;
		flip(leaf, llen, index);
		check(merkle_verify_leaf(proof, leaf, height, llen, dlen, index) == 1, "verify_leaf rejects corrupted leaf", height, llen, dlen, index);
		flip(leaf, llen, index);
		flip(proof, dlen * (height + 1), index);
		check(merkle_verify_leaf(proof, leaf, height, llen, dlen, index) == 1, "verify_leaf rejects corrupted proof", height, llen, dlen, index);
		flip(proof, dlen * (height + 1), index);
		make_leaf(other, llen, index ^ 1);
		if (height && memcmp(leaf, other, llen))
			check(merkle_verify_leaf(proof, leaf, height, llen, dlen, index ^ 1) == 1, "verify_leaf rejects wrong index", height, llen, dlen, index);
		check(!merkle_verify_leaf(proof, leaf, height, llen, dlen, index), "verify_leaf after restoring", height, llen, dlen, index);
	}
	check(merkle_digest_leaf(hashes, leaf, height, llen, dlen, -1) == 1, "digest_leaf rejects index -1", height, llen, dlen, -1);
	check(merkle_digest_leaf(hashes, leaf, height, llen, dlen, leaves) == 1, "digest_leaf rejects index leaves", height, llen, dlen, leaves);
	check(merkle_copy_proof(proof, hashes, height, dlen, -1) == 1, "copy_proof rejects index -1", height, llen, dlen, -1);
	check(merkle_copy_proof(proof, hashes, height, dlen, leaves) == 1, "copy_proof rejects index leaves", height, llen, dlen, leaves);
	check(merkle_verify_leaf(proof, leaf, height, llen, dlen, -1) == 1, "verify_leaf rejects index -1", height, llen, dlen, -1);
	check(merkle_verify_leaf(proof, leaf, height, llen, dlen, leaves) == 1, "verify_leaf rejects index leaves", height, llen, dlen, leaves);
}

static void test_bad_dlen(void)
{
	check(merkle_digest_leaf(hashes, leaf, 2, 4, 0, 0) == 1, "digest_leaf rejects dlen 0", 2, 4, 0, 0);
	check(merkle_digest_leaf(hashes, leaf, 2, 4, 33, 0) == 1, "digest_leaf rejects dlen 33", 2, 4, 33, 0);
	check(merkle_build_tree(hashes, 2, 0) == 1, "build_tree rejects dlen 0", 2, 4, 0, 0);
	check(merkle_build_tree(hashes, 2, 33) == 1, "build_tree rejects dlen 33", 2, 4, 33, 0);
	check(merkle_copy_proof(proof, hashes, 2, 0, 0) == 1, "copy_proof rejects dlen 0", 2, 4, 0, 0);
	check(merkle_copy_proof(proof, hashes, 2, 33, 0) == 1, "copy_proof rejects dlen 33", 2, 4, 33, 0);
	check(merkle_verify_leaf(proof, leaf, 2, 4, 0, 0) == 1, "verify_leaf rejects dlen 0", 2, 4, 0, 0);
	check(merkle_verify_leaf(proof, leaf, 2, 4, 33, 0) == 1, "verify_leaf rejects dlen 33", 2, 4, 33, 0);
}

int main(void)
{
	static const int heights[] = { 0, 1, 2, 3, 8 };
	static const int llens[] = { 1, 64, 1000, BLEN_MAX };
	static const int dlens[] = { 1, 16, 32 };
	int i, j, k;
	known_answers();
	test_digest_message();
	for (i = 0; i < (int)(sizeof(heights) / sizeof(heights[0])); ++i)
		for (j = 0; j < (int)(sizeof(llens) / sizeof(llens[0])); ++j)
			for (k = 0; k < (int)(sizeof(dlens) / sizeof(dlens[0])); ++k)
				test_tree(heights[i], llens[j], dlens[k], 1);
	for (j = 0; j < 2; ++j)
		for (k = 0; k < (int)(sizeof(dlens) / sizeof(dlens[0])); ++k)
			test_tree(HEIGHT_MAX, llens[j], dlens[k], 257);
	test_bad_dlen();
	if (failures) {
		printf("merkle_test: %d failures\n", failures);
		return 1;
	}
	printf("merkle_test: ok\n");
	return 0;
}

