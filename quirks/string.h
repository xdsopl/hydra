/*
Quirks

Copyright 2024 Ahmet Inan <xdsopl@gmail.com>
*/

#pragma once

#include <stddef.h>

int memcmp(const void *s1, const void *s2, size_t len);
void *memset(void *buf, int val, size_t len);
void *memcpy(void *dst, const void *src, size_t len);
void *memmove(void *dst, const void *src, size_t len);

