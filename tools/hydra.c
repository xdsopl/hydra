/*
Command line tool for HYDRA

Copyright 2026 Ahmet Inan <xdsopl@gmail.com>
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../module/hydra.h"

extern unsigned char message[CAPACITY_MAX];
extern unsigned char blocks[];
extern unsigned char block[BLEN_MAX];
static unsigned char seen[BCNT_MAX];

int needed_blocks(int mlen, int blen, int height, int dflag);
int block_length(int mlen, int K, int height, int dflag);
int useful_height(int K);
int encode_message(int mlen, int blen, int height, int dflag);
int encode_block(int index);
int verify_block(int blen);
int decode_message(int blen);

static int read_file(unsigned char *buf, int max, const char *name)
{
	FILE *file = fopen(name, "rb");
	if (!file)
		return -1;
	int len = fread(buf, 1, max, file);
	int more = fgetc(file) != EOF;
	fclose(file);
	if (more)
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

static int encode(int budget, int dflag, const char *input, const char *prefix, int height)
{
	int mlen = read_file(message, MLEN_MAX, input);
	if (mlen < 1) {
		fprintf(stderr, "could not read message from %s\n", input);
		return 1;
	}
	int K = -1;
	if (height) {
		K = needed_blocks(mlen, budget, height, dflag);
	} else {
		int best = 0, best_K = 0;
		for (height = 1; height <= HEIGHT_MAX; ++height) {
			K = needed_blocks(mlen, budget, height, dflag);
			if (K > 0 && (!best || (1 << height) * best_K > (1 << best) * K)) {
				best = height;
				best_K = K;
			}
			if (K > 0 && useful_height(K) <= height)
				break;
		}
		if (height > HEIGHT_MAX && best) {
			height = best;
			K = needed_blocks(mlen, budget, height, dflag);
		}
	}
	if (K < 1) {
		fprintf(stderr, "could not encode mlen %d, blen %d, dflag %d\n", mlen, budget, dflag);
		return 1;
	}
	int blen = block_length(mlen, K, height, dflag);
	if (blen < 1 || encode_message(mlen, blen, height, dflag) != K) {
		fprintf(stderr, "could not encode mlen %d, blen %d, dflag %d\n", mlen, budget, dflag);
		return 1;
	}
	for (int i = 0; i < 1 << height; ++i) {
		char name[4096];
		snprintf(name, sizeof(name), "%s%05d", prefix, i);
		if (encode_block(i) != blen || write_file(block, blen, name)) {
			fprintf(stderr, "could not write block to %s\n", name);
			return 1;
		}
	}
	fprintf(stderr, "K = %d, N = %d, blen = %d\n", K, 1 << height, blen);
	return 0;
}

static int decode(const char *output, char **names, int count)
{
	int blen = 0, K = 0, got = 0;
	for (int i = 0; i < count && (!K || got < K); ++i) {
		int len = read_file(block, BLEN_MAX, names[i]);
		if (len < 4) {
			fprintf(stderr, "skipping %s: could not read block\n", names[i]);
			continue;
		}
		if (verify_block(len)) {
			fprintf(stderr, "skipping %s: proof failed\n", names[i]);
			continue;
		}
		if (!blen) {
			blen = len;
			K = ((block[2] | block[3] << 8) & 1023) + 1;
			memcpy(blocks, block, blen);
		}
		int dlen = blocks[3] & 128 ? 32 : 16;
		if (len != blen || memcmp(block+2, blocks+2, 2) || memcmp(block+blen-dlen, blocks+blen-dlen, dlen)) {
			fprintf(stderr, "skipping %s: from another message\n", names[i]);
			continue;
		}
		int index = block[0] | block[1] << 8;
		if (seen[index]) {
			fprintf(stderr, "skipping %s: duplicate index %d\n", names[i], index);
			continue;
		}
		seen[index] = 1;
		memcpy(blocks+got*blen, block, blen);
		++got;
	}
	if (!K || got < K) {
		fprintf(stderr, "not enough blocks: got %d of %d\n", got, K);
		return 1;
	}
	int mlen = decode_message(blen);
	if (mlen < 0) {
		fprintf(stderr, "decoding failed\n");
		return 1;
	}
	if (write_file(message, mlen, output)) {
		fprintf(stderr, "could not write message to %s\n", output);
		return 1;
	}
	return 0;
}

int main(int argc, char **argv)
{
	if ((argc == 6 || argc == 7) && !strcmp(argv[1], "encode"))
		return encode(atoi(argv[2]), atoi(argv[3]), argv[4], argv[5], argc == 7 ? atoi(argv[6]) : 0);
	if (argc >= 4 && !strcmp(argv[1], "decode"))
		return decode(argv[2], argv+3, argc - 3);
	fprintf(stderr, "usage: %s encode BLEN DFLAG MESSAGE PREFIX [HEIGHT]\n", argv[0]);
	fprintf(stderr, "       %s decode MESSAGE BLOCK...\n", argv[0]);
	return 1;
}

