/*
WebAssembly HYDRA module for self-healing erasure coding

Copyright 2026 Ahmet Inan <xdsopl@gmail.com>
*/

#include "string.h"
#include "hydra.h"

#define BLOCKS_LEN (CAPACITY_MAX+8+K_MAX*(8+32*(HEIGHT_MAX+1)))

__attribute__((visibility("default")))
unsigned char digest[32];
__attribute__((visibility("default")))
unsigned char message[CAPACITY_MAX];
__attribute__((visibility("default")))
unsigned char blocks[BLOCKS_LEN];
__attribute__((visibility("default")))
unsigned char block[BLEN_MAX];
static unsigned char hashes[32*2*BCNT_MAX];
static unsigned char root[32];
static int indices[K_MAX];
static unsigned char seen[BCNT_MAX];
static int tree_state, tree_K, tree_height, tree_dflag, tree_blen;

static int ilog2_floor(int x)
{
	int l = -1;
	for (; x > 0; x /= 2)
		++l;
	return l;
}

static int ilog2_ceil(int x)
{
	return ilog2_floor(x - 1) + 1;
}

static int hash_length(int dflag)
{
	return dflag ? 32 : 16;
}

static int payload_length(int blen, int height, int dflag)
{
	if (blen < 1 || blen > BLEN_MAX)
		return -1;
	if (height < 1 || height > HEIGHT_MAX)
		return -1;
	if (dflag != 0 && dflag != 1)
		return -1;
	int plen = blen - 4 - hash_length(dflag) * (height + 1);
	if (plen * 8 < 31)
		return -1;
	return plen;
}

static unsigned read_header(const unsigned char *buf)
{
	return buf[0] | buf[1] << 8 | buf[2] << 16 | (unsigned)buf[3] << 24;
}

static void write_header(unsigned char *buf, int K, int height, int dflag, int index)
{
	unsigned head = (unsigned)dflag << 31 | (unsigned)(height - 1) << 26 | (unsigned)(K - 1) << 16 | index;
	buf[0] = head;
	buf[1] = head >> 8;
	buf[2] = head >> 16;
	buf[3] = head >> 24;
}

static int parse_header(const unsigned char *buf, int *K, int *height, int *dflag, int *index)
{
	unsigned head = read_header(buf);
	if (head >> 30 & 1)
		return -1;
	*dflag = head >> 31;
	*height = (head >> 26 & 15) + 1;
	*K = (head >> 16 & 1023) + 1;
	*index = head & 65535;
	if (*K > 1 << *height)
		return -1;
	if (*index >= 1 << *height)
		return -1;
	return 0;
}

static int padding_is_zero(const unsigned char *data, int plen)
{
	int bits = (plen * 8) / 31 * 31;
	if (bits % 8 && data[bits/8] >> bits % 8)
		return 0;
	for (int i = (bits + 7) / 8; i < plen; ++i)
		if (data[i])
			return 0;
	return 1;
}

int merkle_digest_message(unsigned char *digest, unsigned char *message, int mlen, int dlen);
int merkle_digest_leaf(unsigned char *hashes, unsigned char *leaf, int height, int llen, int dlen, int index);
int merkle_build_tree(unsigned char *hashes, int height, int dlen);
int merkle_copy_proof(unsigned char *proof, unsigned char *hashes, int height, int dlen, int index);
int merkle_verify_leaf(unsigned char *proof, unsigned char *leaf, int height, int llen, int dlen, int index);
int cme_prepare_message(unsigned char *message, int K, int mlen, int blen);
int cme_encode_block(unsigned char *block, int K, int index, int blen);
int cme_decode_message(unsigned char *message, unsigned char *blocks, int *indices, int K, int blen, int stride);

__attribute__((visibility("default")))
int needed_blocks(int mlen, int blen, int height, int dflag)
{
	if (mlen < 1 || mlen > MLEN_MAX)
		return -1;
	int plen = payload_length(blen, height, dflag);
	if (plen < 0)
		return -1;
	int values = (plen * 8) / 31;
	int K = (31 + mlen * 8 + 31 * values - 1) / (31 * values);
	if (K > K_MAX || K > 1 << height)
		return -1;
	if (message_capacity(K, plen) > CAPACITY_MAX)
		return -1;
	return K;
}

__attribute__((visibility("default")))
int block_length(int mlen, int K, int height, int dflag)
{
	if (mlen < 1 || mlen > MLEN_MAX)
		return -1;
	if (K < 1 || K > K_MAX)
		return -1;
	if (height < 1 || height > HEIGHT_MAX)
		return -1;
	if (K > 1 << height)
		return -1;
	if (dflag != 0 && dflag != 1)
		return -1;
	int values = (31 + mlen * 8 + 31 * K - 1) / (31 * K);
	if (31 * values * (K - 1) >= 31 + mlen * 8)
		return -1;
	int plen = (values * 31 + 7) / 8;
	int blen = 4 + hash_length(dflag) * (height + 1) + plen;
	if (blen > BLEN_MAX)
		return -1;
	if (message_capacity(K, plen) > CAPACITY_MAX)
		return -1;
	return blen;
}

__attribute__((visibility("default")))
int useful_height(int K)
{
	if (K < 1 || K > K_MAX)
		return -1;
	int height = 4 + ilog2_ceil(K);
	if (height > HEIGHT_MAX)
		return HEIGHT_MAX;
	return height;
}

static int build_tree(int K, int height, int dflag, int plen)
{
	int dlen = hash_length(dflag);
	for (int i = 0; i < 1 << height; ++i) {
		write_header(block, K, height, dflag, i);
		if (cme_encode_block(block+4, K, i, plen))
			return -1;
		if (merkle_digest_leaf(hashes, block, height, 4 + plen, dlen, i))
			return -1;
	}
	if (merkle_build_tree(hashes, height, dlen))
		return -1;
	return 0;
}

__attribute__((visibility("default")))
int encode_message(int mlen, int blen, int height, int dflag)
{
	tree_state = 0;
	int K = needed_blocks(mlen, blen, height, dflag);
	if (K < 0)
		return -1;
	int plen = payload_length(blen, height, dflag);
	if (cme_prepare_message(message, K, mlen, plen))
		return -1;
	if (build_tree(K, height, dflag, plen))
		return -1;
	tree_state = 2;
	tree_K = K;
	tree_height = height;
	tree_dflag = dflag;
	tree_blen = blen;
	return K;
}

__attribute__((visibility("default")))
int encode_block(int index)
{
	if (tree_state != 2)
		return -1;
	if (index < 0 || index >= 1 << tree_height)
		return -1;
	int plen = payload_length(tree_blen, tree_height, tree_dflag);
	write_header(block, tree_K, tree_height, tree_dflag, index);
	if (cme_encode_block(block+4, tree_K, index, plen))
		return -1;
	if (merkle_copy_proof(block+4+plen, hashes, tree_height, hash_length(tree_dflag), index))
		return -1;
	return tree_blen;
}

static int check_block(unsigned char *buf, int blen, int *K, int *height, int *dflag, int *index)
{
	if (blen < 4 || blen > BLEN_MAX)
		return -1;
	if (parse_header(buf, K, height, dflag, index))
		return -1;
	int plen = payload_length(blen, *height, *dflag);
	if (plen < 0)
		return -1;
	int capacity = message_capacity(*K, plen);
	if (capacity < 1 || capacity > CAPACITY_MAX)
		return -1;
	if (!padding_is_zero(buf+4, plen))
		return -1;
	if (merkle_verify_leaf(buf+4+plen, buf, *height, 4 + plen, hash_length(*dflag), *index))
		return -1;
	return plen;
}

__attribute__((visibility("default")))
int verify_block(int blen)
{
	int K, height, dflag, index;
	if (check_block(block, blen, &K, &height, &dflag, &index) < 0)
		return -1;
	return 0;
}

__attribute__((visibility("default")))
int decode_message(int blen)
{
	int K, height, dflag, index;
	tree_state = 0;
	int plen = check_block(blocks, blen, &K, &height, &dflag, &index);
	if (plen < 0)
		return -1;
	if (K * blen > BLOCKS_LEN)
		return -1;
	int dlen = hash_length(dflag);
	unsigned params = read_header(blocks) >> 16;
	memset(seen, 0, 1 << height);
	for (int i = 0; i < K; ++i) {
		int K_i, height_i, dflag_i;
		unsigned char *buf = blocks+i*blen;
		if (read_header(buf) >> 16 != params)
			return -1;
		if (check_block(buf, blen, &K_i, &height_i, &dflag_i, &index) < 0)
			return -1;
		if (seen[index])
			return -1;
		seen[index] = 1;
		indices[i] = index;
		if (memcmp(buf+blen-dlen, blocks+blen-dlen, dlen))
			return -1;
	}
	if (cme_decode_message(message, blocks+4, indices, K, plen, blen))
		return -1;
	memcpy(root, blocks+blen-dlen, dlen);
	tree_state = 1;
	tree_K = K;
	tree_height = height;
	tree_dflag = dflag;
	tree_blen = blen;
	return message_capacity(K, plen);
}

__attribute__((visibility("default")))
int regenerate_tree(void)
{
	if (tree_state != 1)
		return -1;
	tree_state = 0;
	int plen = payload_length(tree_blen, tree_height, tree_dflag);
	int capacity = message_capacity(tree_K, plen);
	if (cme_prepare_message(message, tree_K, capacity, plen))
		return -1;
	if (build_tree(tree_K, tree_height, tree_dflag, plen))
		return -1;
	if (memcmp(hashes, root, hash_length(tree_dflag)))
		return -1;
	tree_state = 2;
	return 0;
}

__attribute__((visibility("default")))
int digest_message(int mlen)
{
	if (mlen < 1 || mlen > MLEN_MAX)
		return -1;
	if (merkle_digest_message(digest, message, mlen, 32))
		return -1;
	return 0;
}

