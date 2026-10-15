/*
WebAssembly HYDRA module for self-healing erasure coding

Copyright 2026 Ahmet Inan <xdsopl@gmail.com>
*/

#define MLEN_MAX (1 << 20)
#define BLEN_MAX 8192
#define HEIGHT_MAX 8
#define BCNT_MAX (1 << HEIGHT_MAX)

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
	int avail_values = (blen * 8) / 31;
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

