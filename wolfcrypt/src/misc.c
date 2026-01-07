/* misc.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */
/*

DESCRIPTION
This module implements the arithmetic-shift right, left, byte swapping, XOR,
masking and clearing memory logic.

*/
#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#ifndef WOLF_CRYPT_MISC_C
#define WOLF_CRYPT_MISC_C

#include <wolfssl/wolfcrypt/misc.h>

/* inlining these functions is a huge speed increase and a small size decrease,
   because the functions are smaller than function call setup/cleanup, e.g.,
   md5 benchmark is twice as fast with inline.  If you don't want it, then
   define NO_INLINE and compile this file into wolfssl, otherwise it's used as
   a source header
 */

#ifdef NO_INLINE
    #define WC_STATIC
#else
    #define WC_STATIC static
#endif

/* Check for if compiling misc.c when not needed. */
#if !defined(WOLFSSL_MISC_INCLUDED) && !defined(NO_INLINE)
    #ifndef WOLFSSL_IGNORE_FILE_WARN
        #warning misc.c does not need to be compiled when using inline (NO_INLINE not defined)
    #endif

#else

/* This routine performs a left circular arithmetic shift of <x> by <y> value. */

    WC_STATIC WC_INLINE word32 rotlFixed(word32 x, word32 y)
    {
        return (x << y) | (x >> (sizeof(y) * 8 - y));
    }

/* This routine performs a right circular arithmetic shift of <x> by <y> value. */
    WC_STATIC WC_INLINE word32 rotrFixed(word32 x, word32 y)
    {
        return (x >> y) | (x << (sizeof(y) * 8 - y));
    }

/* This routine performs a byte swap of 32-bit word value. */
WC_STATIC WC_INLINE word32 ByteReverseWord32(word32 value)
{
#if defined(WOLFSSL_BYTESWAP32_ASM) && defined(__GNUC__) && \
      (defined(__thumb__) || defined(__arm__))
    __asm__ volatile (
        "REV %0, %0  \n"
        : "+r" (value)
        :
    );
    return value;
#else
    value = ((value & 0xFF00FF00) >> 8) | ((value & 0x00FF00FF) << 8);
    return rotlFixed(value, 16U);
#endif
}
/* This routine performs a byte swap of words array of a given count. */
WC_STATIC WC_INLINE void ByteReverseWords(word32* out, const word32* in,
                                    word32 byteCount)
{
    word32 count = byteCount/(word32)sizeof(word32), i;

    for (i = 0; i < count; i++)
        out[i] = ByteReverseWord32(in[i]);

}

#if defined(WORD64_AVAILABLE) && !defined(WOLFSSL_NO_WORD64_OPS)

/* This routine performs a left rotation of a given value of word64 type
<x> by <y> and returns the result */
WC_STATIC WC_INLINE word64 rotlFixed64(word64 x, word64 y)
{
    return (x << y) | (x >> (sizeof(y) * 8 - y));
}

WC_STATIC WC_INLINE word64 ByteReverseWord64(word64 value)
{
	value = ((value & W64LIT(0xFF00FF00FF00FF00)) >> 8) |
            ((value & W64LIT(0x00FF00FF00FF00FF)) << 8);
	value = ((value & W64LIT(0xFFFF0000FFFF0000)) >> 16) |
            ((value & W64LIT(0x0000FFFF0000FFFF)) << 16);
	return rotlFixed64(value, 32U);
}

/*!
    \brief This function performs a byte swap and returns the result in a provided buffer.

    \param out pointer to a buffer to hold the swapped bytes
    \param in pointer containing values of a word64 type
    \param byteCount the length of <in> in bytes
*/

WC_STATIC WC_INLINE void ByteReverseWords64(word64* out, const word64* in,
                                      word32 byteCount)
{
    word32 count = byteCount/(word32)sizeof(word64), i;

    for (i = 0; i < count; i++)
        out[i] = ByteReverseWord64(in[i]);

}

#endif /* WORD64_AVAILABLE && !WOLFSSL_NO_WORD64_OPS */
/* This routine performs a bitwise XOR operation of <*r> and <*a> for <n> number
of wolfssl_words, placing the result in <*r>. */
WC_STATIC WC_INLINE void XorWords(wolfssl_word* r, const wolfssl_word* a, word32 n)
{
    word32 i;

    for (i = 0; i < n; i++) r[i] ^= a[i];
}

/* This routine performs a bitwise XOR operation of <*buf> and <*mask> of n
counts, placing the result in <*buf>. */

WC_STATIC WC_INLINE void xorbuf(void* buf, const void* mask, word32 count)
{
    if (((wolfssl_word)buf | (wolfssl_word)mask | count) % WOLFSSL_WORD_SIZE == 0)
        XorWords( (wolfssl_word*)buf,
                  (const wolfssl_word*)mask, count / WOLFSSL_WORD_SIZE);
    else {
        word32 i;
        byte*       b = (byte*)buf;
        const byte* m = (const byte*)mask;

        for (i = 0; i < count; i++) b[i] ^= m[i];
    }
}

WC_STATIC WC_INLINE void ForceZero(const void* mem, word32 len)
{
    volatile byte* z = (volatile byte*)mem;

    while (len--) *z++ = 0;
}

WC_STATIC WC_INLINE int ConstantCompare(const byte* a, const byte* b, int length)
{
    int i;
    int compareSum = 0;

    for (i = 0; i < length; i++) {
        compareSum |= a[i] ^ b[i];
    }

    return compareSum;
}

#undef WC_STATIC

#endif /* !WOLFSSL_MISC_INCLUDED && !NO_INLINE */

#endif /* WOLF_CRYPT_MISC_C */
