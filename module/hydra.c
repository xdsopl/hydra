/*
WebAssembly HYDRA module for self-healing erasure coding

Copyright 2026 Ahmet Inan <xdsopl@gmail.com>
*/

#include "string.h"
#include "hydra.h"

__attribute__((visibility("default")))
unsigned char digest[32];
__attribute__((visibility("default")))
unsigned char message[MLEN_MAX];
__attribute__((visibility("default")))
unsigned char blocks[BLEN_MAX*BCNT_MAX];
__attribute__((visibility("default")))
unsigned char block[BLEN_MAX];
static unsigned char hashes[32*2*BCNT_MAX];
static unsigned char indices[BCNT_MAX];
static unsigned char seen[BCNT_MAX];

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

static int needed_height(int K)
{
	if (K < 1)
		return -1;
	if (K == 1)
		return 0;
	int height = 1 + ilog2_ceil(K);
	if (height < 2 || height > HEIGHT_MAX)
		return -1;
	return height;
}

static int payload_length(int height, int blen, int dlen)
{
	if (height < 2 || height > HEIGHT_MAX)
		return -1;
	if (blen < 1 || blen > BLEN_MAX)
		return -1;
	if (dlen != 16 && dlen != 32)
		return -1;
	int plen = blen - 2 - dlen * (height + 1);
	if (plen < 1)
		return -1;
	return plen;
}

__attribute__((visibility("default")))
int needed_blocks(int mlen, int blen, int dflag)
{
	if (mlen < 1 || mlen > MLEN_MAX)
		return -1;
	if (blen < 1 || blen > BLEN_MAX)
		return -1;
	if (dflag != 0 && dflag != 1)
		return -1;
	if (mlen <= blen - 1 - (dflag ? 8 : 4))
		return 1;
	int dlen = dflag ? 32 : 16;
	int plen = payload_length(2, blen, dlen);
	if (plen < 0)
		return -1;
	int avail_values = (plen * 8) / 31;
	if (avail_values < 1)
		return -1;
	int avail_bits = avail_values * 31;
	int K = (31 + mlen * 8 + avail_bits - 1) / avail_bits;
	for (;; ++K) {
		plen = payload_length(needed_height(K), blen, dlen);
		if (plen < 0)
			return -1;
		avail_values = (plen * 8) / 31;
		if (avail_values < 1)
			return -1;
		if (message_capacity(K, plen) >= mlen)
			return K;
	}
}

__attribute__((visibility("default")))
int total_blocks(int K)
{
	int height = needed_height(K);
	if (height < 0)
		return -1;
	int N = 1 << height;
	return N;
}

int merkle_digest_message(unsigned char *digest, unsigned char *message, int mlen, int dlen);
int merkle_digest_blocks(unsigned char *hashes, unsigned char *blocks, int height, int blen, int stride, int dlen);
int merkle_extract_block(unsigned char *blocks, unsigned char *hashes, int height, int blen, int stride, int dlen, int index);
int merkle_verify_block(unsigned char *block, int height, int blen, int dlen, int index);
int cme_encode_message(unsigned char *blocks, unsigned char *message, int K, int N, int mlen, int blen, int stride);
int cme_decode_message(unsigned char *message, unsigned char *blocks, unsigned char *indices, int K, int blen, int stride);

static int verify_single(unsigned char *buf, int blen)
{
	unsigned char hash[8];
	int hlen = buf[0] & 128 ? 8 : 4;
	if (blen <= hlen)
		return -1;
	if (merkle_digest_message(hash, buf, blen - hlen, hlen))
		return -1;
	if (memcmp(hash, buf+blen-hlen, hlen))
		return -1;
	return 0;
}

static int encode_single(int mlen, int blen, int dflag)
{
	if (blen < 1 || blen > BLEN_MAX)
		return -1;
	if (dflag != 0 && dflag != 1)
		return -1;
	int hlen = dflag ? 8 : 4;
	if (mlen > blen - 1 - hlen)
		return -1;
	blocks[0] = dflag ? 128 : 0;
	memcpy(blocks+1, message, mlen);
	memset(blocks+1+mlen, 0, blen - 1 - hlen - mlen);
	if (merkle_digest_message(blocks+blen-hlen, blocks, blen - hlen, hlen))
		return -1;
	return 0;
}

static int decode_single(int blen)
{
	if (verify_single(blocks, blen))
		return -1;
	int hlen = blocks[0] & 128 ? 8 : 4;
	int len = blen - 1 - hlen;
	memcpy(message, blocks+1, len);
	return len;
}

__attribute__((visibility("default")))
int verify_block(int blen)
{
	if (blen <= 2 || blen > BLEN_MAX)
		return -1;
	int K = (block[0] & 127) + 1;
	if (K == 1)
		return verify_single(block, blen);
	int dlen = block[0] & 128 ? 32 : 16;
	int height = needed_height(K);
	int N = total_blocks(K);
	if (N < 0)
		return -1;
	if (block[1] >= N)
		return -1;
	int plen = payload_length(height, blen, dlen);
	if (plen < 0)
		return -1;
	if (merkle_verify_block(block, height, 2 + plen, dlen, block[1]))
		return -1;
	return 0;
}

__attribute__((visibility("default")))
int encode_message(int mlen, int blen, int dflag)
{
	int K = needed_blocks(mlen, blen, dflag);
	if (K < 0)
		return -1;
	int N = total_blocks(K);
	if (K == 1) {
		if (encode_single(mlen, blen, dflag))
			return -1;
		return N;
	}
	int dlen = dflag ? 32 : 16;
	int height = needed_height(K);
	int plen = payload_length(height, blen, dlen);
	if (plen < 0)
		return -1;
	int ret = cme_encode_message(blocks+2, message, K, N, mlen, plen, blen);
	if (ret)
		return ret;
	for (int i = 0; i < N; ++i) {
		blocks[i*blen] = (K - 1) | (dflag ? 128 : 0);
		blocks[i*blen+1] = i;
	}
	if (merkle_digest_blocks(hashes, blocks, height, 2 + plen, blen, dlen))
		return -1;
	for (int i = 0; i < N; ++i)
		if (merkle_extract_block(blocks, hashes, height, 2 + plen, blen, dlen, i))
			return -1;
	return N;
}

__attribute__((visibility("default")))
int decode_message(int blen)
{
	if (blen <= 2 || blen > BLEN_MAX)
		return -1;
	int K = (blocks[0] & 127) + 1;
	if (K == 1)
		return decode_single(blen);
	int dlen = blocks[0] & 128 ? 32 : 16;
	int height = needed_height(K);
	int N = total_blocks(K);
	if (N < 0)
		return -1;
	int plen = payload_length(height, blen, dlen);
	if (plen < 0)
		return -1;
	memset(seen, 0, N);
	for (int i = 0; i < K; ++i) {
		if (blocks[i*blen] != blocks[0])
			return -1;
		if (blocks[i*blen+1] >= N)
			return -1;
		indices[i] = blocks[i*blen+1];
		if (seen[indices[i]])
			return -1;
		seen[indices[i]] = 1;
		if (merkle_verify_block(blocks+i*blen, height, 2 + plen, dlen, indices[i]))
			return -1;
		if (memcmp(blocks+i*blen+blen-dlen, blocks+blen-dlen, dlen))
			return -1;
	}
	if (cme_decode_message(message, blocks+2, indices, K, plen, blen))
		return -1;
	return message_capacity(K, plen);
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

