/*
WebAssembly HYDRA module for self-healing erasure coding

Copyright 2026 Ahmet Inan <xdsopl@gmail.com>
*/

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
__attribute__((visibility("default")))
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
int needed_blocks(int mlen, int blen)
{
	if (mlen < 1 || mlen > MLEN_MAX)
		return -1;
	if (blen < 1 || blen > BLEN_MAX)
		return -1;
	if (mlen <= blen)
		return -1;
	int avail_values = ((blen - HLEN) * 8) / 31;
	if (avail_values < 1)
		return -1;
	int avail_bits = avail_values * 31;
	int K = (31 + mlen * 8 + avail_bits - 1) / avail_bits;
	return K;
}

__attribute__((visibility("default")))
int needed_height(int K)
{
	if (K < 1)
		return -1;
	int height = 1 + ilog2_ceil(K);
	if (height < 2 || height > HEIGHT_MAX)
		return -1;
	return height;
}

__attribute__((visibility("default")))
int total_blocks(int height)
{
	if (height < 2 || height > HEIGHT_MAX)
		return -1;
	int N = 1 << height;
	return N;
}

int merkle_digest_message(unsigned char *digest, unsigned char *message, int mlen, int dlen);
int merkle_digest_blocks(unsigned char *hashes, unsigned char *blocks, int height, int blen, int dlen);
int merkle_extract_proof(unsigned char *block, unsigned char *proof, unsigned char *blocks, unsigned char *hashes, int height, int blen, int dlen, int index);
int merkle_verify_proof(unsigned char *block, unsigned char *proof, int height, int blen, int dlen, int index);
int cme_encode_message(unsigned char *blocks, unsigned char *message, int K, int N, int mlen, int blen, int stride);
int cme_decode_message(unsigned char *message, unsigned char *blocks, unsigned char *indices, int K, int blen, int stride);

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
	return merkle_digest_blocks(hashes, blocks, height, blen, dlen);
}

__attribute__((visibility("default")))
int extract_proof(int height, int blen, int dlen, int index)
{
	if (height < 2 || height > HEIGHT_MAX)
		return 1;
	if (blen < 1 || blen > BLEN_MAX)
		return 1;
	return merkle_extract_proof(block, proof, blocks, hashes, height, blen, dlen, index);
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
int encode_message(int K, int N, int mlen, int blen)
{
	if (N != total_blocks(needed_height(K)))
		return -1;
	if (mlen < 1 || mlen > MLEN_MAX)
		return -1;
	if (blen <= HLEN || blen > BLEN_MAX)
		return -1;
	int ret = cme_encode_message(blocks+HLEN, message, K, N, mlen, blen-HLEN, blen);
	if (ret)
		return ret;
	for (int i = 0; i < N; ++i) {
		blocks[i*blen] = K - 1;
		blocks[i*blen+1] = i;
	}
	return 0;
}

__attribute__((visibility("default")))
int decode_message(int K, int blen)
{
	if (needed_height(K) < 0)
		return -1;
	if (blen <= HLEN || blen > BLEN_MAX)
		return -1;
	return cme_decode_message(message, blocks+HLEN, indices, K, blen-HLEN, blen);
}

