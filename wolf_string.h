/* wolf_string.h
 *
 * Copyright (C) 2006-2021 wolfSSL Inc.  All rights reserved.
 *
 * This file is part of wolfSSL.
 *
 * Contact licensing@wolfssl.com with any questions or comments.
 *
 * https://www.wolfssl.com
 */

#ifndef _WOLF_STR_H
#define _WOLF_STR_H

#include "user_settings.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef BUILD_LOCAL_TEST
#include <stdio.h>
#include <string.h>

#else
void *memset(void *s, int c, unsigned int n);
void *memcpy(void *dst, const void *src, unsigned int n);
int memcmp(const void *_s1, const void *_s2, unsigned int n);
void *memmove(void *dst, const void *src, unsigned int n);

char *strncpy(char *dst, const char *src, unsigned int n);
unsigned int strlen(const char *s);
int strncmp(const char *s1, const char *s2, unsigned int n);
#endif
#ifdef __cplusplus
}
#endif

#endif /* _WOLF_STR_H */
