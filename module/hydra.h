/*
WebAssembly HYDRA module for self-healing erasure coding

Copyright 2026 Ahmet Inan <xdsopl@gmail.com>
*/

#pragma once

#define MLEN_MAX (1 << 23)
#define BLEN_MAX 8192
#define CAPACITY_MAX (MLEN_MAX + BLEN_MAX)
#define HEIGHT_MAX 16
#define BCNT_MAX (1 << HEIGHT_MAX)
#define K_MAX 1024
#define N_MAX (1 << 16)

static inline int message_capacity(int K, int plen)
{
	return (K * ((plen * 8) / 31) * 31 - 31) / 8;
}

