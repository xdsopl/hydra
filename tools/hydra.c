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
extern unsigned char block[BLEN_MAX];
static unsigned char seen[BCNT_MAX];

int verify_block(int blen);
int encode_message(int mlen, int blen, int dflag);
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

static int encode(int blen, int dflag, const char *input, const char *prefix)
{
	int mlen = read_file(message, MLEN_MAX, input);
	if (mlen < 0) {
		fprintf(stderr, "could not read message from %s\n", input);
		return 1;
	}
	int N = encode_message(mlen, blen, dflag);
	if (N < 0) {
		fprintf(stderr, "could not encode mlen %d, blen %d, dflag %d\n", mlen, blen, dflag);
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
	fprintf(stderr, "K = %d, N = %d\n", (blocks[0] & 127) + 1, N);
	return 0;
}

static int decode(const char *output, char **names, int count)
{
	int blen = 0, K = 0, got = 0;
	for (int i = 0; i < count && (!K || got < K); ++i) {
		int len = read_file(block, BLEN_MAX, names[i]);
		if (len <= HLEN) {
			fprintf(stderr, "skipping %s: could not read block\n", names[i]);
			continue;
		}
		if (verify_block(len)) {
			fprintf(stderr, "skipping %s: proof failed\n", names[i]);
			continue;
		}
		if (!blen) {
			blen = len;
			K = (block[0] & 127) + 1;
			memcpy(blocks, block, blen);
		}
		if (len != blen || block[0] != blocks[0]) {
			fprintf(stderr, "skipping %s: from another message\n", names[i]);
			continue;
		}
		int dlen = blocks[0] & 128 ? 32 : 16;
		if (K > 1 && memcmp(block+blen-dlen, blocks+blen-dlen, dlen)) {
			fprintf(stderr, "skipping %s: from another message\n", names[i]);
			continue;
		}
		if (seen[block[1]]) {
			fprintf(stderr, "skipping %s: duplicate index %d\n", names[i], block[1]);
			continue;
		}
		seen[block[1]] = 1;
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
	if (argc == 6 && !strcmp(argv[1], "encode"))
		return encode(atoi(argv[2]), atoi(argv[3]), argv[4], argv[5]);
	if (argc >= 4 && !strcmp(argv[1], "decode"))
		return decode(argv[2], argv+3, argc - 3);
	fprintf(stderr, "usage: %s encode BLEN DFLAG MESSAGE PREFIX\n", argv[0]);
	fprintf(stderr, "       %s decode MESSAGE BLOCK...\n", argv[0]);
	return 1;
}

