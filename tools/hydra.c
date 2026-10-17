/*
Command line tool for HYDRA

Copyright 2026 Ahmet Inan <xdsopl@gmail.com>
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MLEN_MAX (1 << 20)
#define BLEN_MAX 8192
#define HEIGHT_MAX 8
#define BCNT_MAX (1 << HEIGHT_MAX)
#define HLEN 2

extern unsigned char message[MLEN_MAX];
extern unsigned char blocks[BLEN_MAX*BCNT_MAX];
static unsigned char seen[BCNT_MAX];

int needed_blocks(int mlen, int blen);
int needed_height(int K);
int total_blocks(int height);
int encode_message(int K, int N, int mlen, int blen);
int decode_message(int blen);

static int read_file(unsigned char *buf, int max, const char *name)
{
	FILE *file = fopen(name, "rb");
	if (!file)
		return -1;
	int len = fread(buf, 1, max + 1, file);
	fclose(file);
	if (len > max)
		return -1;
	return len;
}

static int write_file(const unsigned char *buf, int len, const char *name)
{
	FILE *file = fopen(name, "wb");
	if (!file)
		return -1;
	int ret = fwrite(buf, 1, len, file) != (size_t)len;
	if (fclose(file))
		return -1;
	return -ret;
}

static int encode(int blen, const char *input, const char *prefix)
{
	int mlen = read_file(message, MLEN_MAX, input);
	if (mlen < 0) {
		fprintf(stderr, "could not read message from %s\n", input);
		return 1;
	}
	int K = needed_blocks(mlen, blen);
	int N = total_blocks(needed_height(K));
	if (K < 0 || N < 0) {
		fprintf(stderr, "unsupported message length %d for block length %d\n", mlen, blen);
		return 1;
	}
	if (encode_message(K, N, mlen, blen)) {
		fprintf(stderr, "encoding failed\n");
		return 1;
	}
	for (int i = 0; i < N; ++i) {
		char name[4096];
		snprintf(name, sizeof(name), "%s%03d", prefix, i);
		if (write_file(blocks+i*blen, blen, name)) {
			fprintf(stderr, "could not write block to %s\n", name);
			return 1;
		}
	}
	fprintf(stderr, "K = %d, N = %d\n", K, N);
	return 0;
}

static int decode(const char *output, char **names, int count)
{
	int blen = 0, K = 0, got = 0;
	for (int i = 0; i < count && (!K || got < K); ++i) {
		unsigned char *block = blocks+got*blen;
		int len = read_file(block, BLEN_MAX, names[i]);
		if (len <= HLEN) {
			fprintf(stderr, "skipping %s: could not read block\n", names[i]);
			continue;
		}
		if (!blen)
			blen = len;
		if (len != blen) {
			fprintf(stderr, "skipping %s: length %d differs from %d\n", names[i], len, blen);
			continue;
		}
		if (!K)
			K = (block[0] & 127) + 1;
		if ((block[0] & 127) + 1 != K) {
			fprintf(stderr, "skipping %s: K differs\n", names[i]);
			continue;
		}
		if (seen[block[1]]) {
			fprintf(stderr, "skipping %s: duplicate index %d\n", names[i], block[1]);
			continue;
		}
		seen[block[1]] = 1;
		++got;
	}
	if (!K || got < K) {
		fprintf(stderr, "not enough blocks: got %d of %d\n", got, K);
		return 1;
	}
	if (decode_message(blen)) {
		fprintf(stderr, "decoding failed\n");
		return 1;
	}
	int block_values = ((blen - HLEN) * 8) / 31;
	int capacity = (K * block_values * 31 - 31) / 8;
	if (write_file(message, capacity, output)) {
		fprintf(stderr, "could not write message to %s\n", output);
		return 1;
	}
	return 0;
}

int main(int argc, char **argv)
{
	if (argc == 5 && !strcmp(argv[1], "encode"))
		return encode(atoi(argv[2]), argv[3], argv[4]);
	if (argc >= 4 && !strcmp(argv[1], "decode"))
		return decode(argv[2], argv+3, argc - 3);
	fprintf(stderr, "usage: %s encode BLEN MESSAGE PREFIX\n", argv[0]);
	fprintf(stderr, "       %s decode MESSAGE BLOCK...\n", argv[0]);
	return 1;
}

