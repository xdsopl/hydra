/*
Quirks

Copyright 2024 Ahmet Inan <xdsopl@gmail.com>
*/

#include "string.h"

int memcmp(const void *s1, const void *s2, size_t len)
{
	const unsigned char *a = s1, *b = s2;
	if (!len)
		return 0;
	while (--len && *a == *b) {
		++a;
		++b;
	}
	return *a - *b;
}

void *memset(void *buf, int val, size_t len)
{
	unsigned char *c = buf;
	while (len--)
		*c++ = val;
	return buf;
}

void *memcpy(void *dst, const void *src, size_t len)
{
	unsigned char *d = dst;
	const unsigned char *s = src;
	if (dst == src)
		return dst;
	while (len--)
		*d++ = *s++;
	return dst;
}

void *memmove(void *dst, const void *src, size_t len)
{
	unsigned char *d = dst;
	const unsigned char *s = src;
	if (dst == src)
		return dst;
	if (dst > src && dst < src + len) {
		d += len - 1;
		s += len - 1;
		while (len--)
			*d-- = *s--;
	} else {
		while (len--)
			*d++ = *s++;
	}
	return dst;
}
