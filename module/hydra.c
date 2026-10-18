/*
WebAssembly HYDRA module for self-healing erasure coding

Copyright 2026 Ahmet Inan <xdsopl@gmail.com>
*/

#include "string.h"

#define MLEN_MAX (1 << 20)
#define BLEN_MAX 8192
#define HEIGHT_MAX 8
#define BCNT_MAX (1 << HEIGHT_MAX)
#define HLEN 2

__attribute__((visibility("default")))
unsigned char digest[32];
__attribute__((visibility("default")))
unsigned char message[MLEN_MAX];
__attribute__((visibility("default")))
unsigned char blocks[BLEN_MAX*BCNT_MAX];
__attribute__((visibility("default")))
unsigned char hashes[32*2*BCNT_MAX];
__attribute__((visibility("default")))
unsigned char block[BLEN_MAX];
__attribute__((visibility("default")))
unsigned char proof[32*(HEIGHT_MAX+1)];
unsigned char indices[BCNT_MAX];

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
int needed_height(int K)
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

__attribute__((visibility("default")))
int payload_length(int height, int blen, int dlen)
{
	if (height < 2 || height > HEIGHT_MAX)
		return -1;
	if (blen < 1 || blen > BLEN_MAX)
		return -1;
	if (dlen != 16 && dlen != 32)
		return -1;
	int plen = blen - HLEN - dlen * (height + 1);
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
	int dlen = dflag ? 32 : 16;
	if (mlen <= blen - 1 - (dlen == 32 ? 8 : 4))
		return 1;
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
		if (K * avail_values * 31 >= 31 + mlen * 8)
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
int merkle_extract_proof(unsigned char *block, unsigned char *proof, unsigned char *blocks, unsigned char *hashes, int height, int blen, int stride, int dlen, int index);
int merkle_verify_proof(unsigned char *block, unsigned char *proof, int height, int blen, int dlen, int index);
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

static int encode_single(int mlen, int blen, int dlen)
{
	if (blen < 1 || blen > BLEN_MAX)
		return -1;
	if (dlen != 16 && dlen != 32)
		return -1;
	int hlen = dlen == 32 ? 8 : 4;
	if (mlen > blen - 1 - hlen)
		return -1;
	blocks[0] = dlen == 32 ? 128 : 0;
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
	memcpy(message, blocks+1, blen - 1 - hlen);
	return 0;
}

__attribute__((visibility("default")))
int digest_message(int mlen, int dlen)
{
	if (mlen < 1 || mlen > MLEN_MAX)
		return 1;
	return merkle_digest_message(digest, message, mlen, dlen);
}

__attribute__((visibility("default")))
int digest_blocks(int height, int blen, int dlen)
{
	if (height < 2 || height > HEIGHT_MAX)
		return 1;
	if (blen < 1 || blen > BLEN_MAX)
		return 1;
	return merkle_digest_blocks(hashes, blocks, height, blen, blen, dlen);
}

__attribute__((visibility("default")))
int extract_proof(int height, int blen, int dlen, int index)
{
	if (height < 2 || height > HEIGHT_MAX)
		return 1;
	if (blen < 1 || blen > BLEN_MAX)
		return 1;
	return merkle_extract_proof(block, proof, blocks, hashes, height, blen, blen, dlen, index);
}

__attribute__((visibility("default")))
int verify_proof(int height, int blen, int dlen, int index)
{
	if (height < 2 || height > HEIGHT_MAX)
		return 1;
	if (blen < 1 || blen > BLEN_MAX)
		return 1;
	return merkle_verify_proof(block, proof, height, blen, dlen, index);
}

__attribute__((visibility("default")))
int verify_block(int blen)
{
	if (blen <= HLEN || blen > BLEN_MAX)
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
	if (merkle_verify_proof(block, block+HLEN+plen, height, HLEN + plen, dlen, block[1]))
		return -1;
	return 0;
}

__attribute__((visibility("default")))
int encode_message(int K, int N, int mlen, int blen, int dflag)
{
	if (N != total_blocks(K))
		return -1;
	if (mlen < 1 || mlen > MLEN_MAX)
		return -1;
	if (dflag != 0 && dflag != 1)
		return -1;
	int dlen = dflag ? 32 : 16;
	if (K == 1)
		return encode_single(mlen, blen, dlen);
	int height = needed_height(K);
	int plen = payload_length(height, blen, dlen);
	if (plen < 0)
		return -1;
	int ret = cme_encode_message(blocks+HLEN, message, K, N, mlen, plen, blen);
	if (ret)
		return ret;
	for (int i = 0; i < N; ++i) {
		blocks[i*blen] = (K - 1) | (dlen == 32 ? 128 : 0);
		blocks[i*blen+1] = i;
	}
	if (merkle_digest_blocks(hashes, blocks, height, HLEN + plen, blen, dlen))
		return -1;
	for (int i = 0; i < N; ++i)
		if (merkle_extract_proof(block, blocks+i*blen+HLEN+plen, blocks, hashes, height, HLEN + plen, blen, dlen, i))
			return -1;
	return 0;
}

__attribute__((visibility("default")))
int decode_message(int blen)
{
	if (blen <= HLEN || blen > BLEN_MAX)
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
	for (int i = 0; i < K; ++i) {
		if (blocks[i*blen] != blocks[0])
			return -1;
		if (blocks[i*blen+1] >= N)
			return -1;
		indices[i] = blocks[i*blen+1];
		if (merkle_verify_proof(blocks+i*blen, blocks+i*blen+HLEN+plen, height, HLEN + plen, dlen, indices[i]))
			return -1;
		if (memcmp(blocks+i*blen+blen-dlen, blocks+blen-dlen, dlen))
			return -1;
	}
	return cme_decode_message(message, blocks+HLEN, indices, K, plen, blen);
}

__attribute__((visibility("default")))
int message_capacity(int blen)
{
	if (blen <= HLEN || blen > BLEN_MAX)
		return -1;
	int K = (blocks[0] & 127) + 1;
	if (K == 1)
		return blen - 1 - (blocks[0] & 128 ? 8 : 4);
	int dlen = blocks[0] & 128 ? 32 : 16;
	int plen = payload_length(needed_height(K), blen, dlen);
	if (plen < 0)
		return -1;
	return (K * ((plen * 8) / 31) * 31 - 31) / 8;
}

