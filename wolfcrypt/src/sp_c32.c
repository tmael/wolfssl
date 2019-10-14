/* sp.c
 *
 * Copyright (C) 2006-2019 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
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

/* Implementation by Sean Parkinson. */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/cpuid.h>
#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#if defined(WOLFSSL_HAVE_SP_RSA) || defined(WOLFSSL_HAVE_SP_DH) || \
                                    defined(WOLFSSL_HAVE_SP_ECC)

#ifdef RSA_LOW_MEM
#ifndef SP_RSA_PRIVATE_EXP_D
#define SP_RSA_PRIVATE_EXP_D
#endif

#ifndef WOLFSSL_SP_SMALL
#define WOLFSSL_SP_SMALL
#endif
#endif

#include <wolfssl/wolfcrypt/sp.h>

#ifndef WOLFSSL_SP_ASM
#if SP_WORD_SIZE == 32
#if (defined(WOLFSSL_SP_CACHE_RESISTANT) || defined(WOLFSSL_SP_SMALL)) && \
    (defined(WOLFSSL_HAVE_SP_ECC) || !defined(WOLFSSL_RSA_PUBLIC_ONLY))
/* Mask for address to obfuscate which of the two address will be used. */
static const size_t addr_mask[2] = { 0, (size_t)-1 };
#endif

#if defined(WOLFSSL_HAVE_SP_RSA) || defined(WOLFSSL_HAVE_SP_DH)
#ifndef WOLFSSL_SP_NO_2048
/* Read big endian unsigned byte aray into r.
 *
 * r  A single precision integer.
 * a  Byte array.
 * n  Number of bytes in array to read.
 */
static void sp_2048_from_bin(sp_digit* r, int max, const byte* a, int n)
{
    int i, j = 0, s = 0;

    r[0] = 0;
    for (i = n-1; i >= 0; i--) {
        r[j] |= ((sp_digit)a[i]) << s;
        if (s >= 15) {
            r[j] &= 0x7fffff;
            s = 23 - s;
            if (j + 1 >= max)
                break;
            r[++j] = a[i] >> s;
            s = 8 - s;
        }
        else
            s += 8;
    }

    for (j++; j < max; j++)
        r[j] = 0;
}

/* Convert an mp_int to an array of sp_digit.
 *
 * r  A single precision integer.
 * a  A multi-precision integer.
 */
static void sp_2048_from_mp(sp_digit* r, int max, const mp_int* a)
{
#if DIGIT_BIT == 23
    int j;

    XMEMCPY(r, a->dp, sizeof(sp_digit) * a->used);

    for (j = a->used; j < max; j++)
        r[j] = 0;
#elif DIGIT_BIT > 23
    int i, j = 0, s = 0;

    r[0] = 0;
    for (i = 0; i < a->used && j < max; i++) {
        r[j] |= a->dp[i] << s;
        r[j] &= 0x7fffff;
        s = 23 - s;
        if (j + 1 >= max)
            break;
        r[++j] = (sp_digit)(a->dp[i] >> s);
        while (s + 23 <= DIGIT_BIT) {
            s += 23;
            r[j] &= 0x7fffff;
            if (j + 1 >= max)
                break;
            if (s < DIGIT_BIT)
                r[++j] = (sp_digit)(a->dp[i] >> s);
            else
                r[++j] = 0;
        }
        s = DIGIT_BIT - s;
    }

    for (j++; j < max; j++)
        r[j] = 0;
#else
    int i, j = 0, s = 0;

    r[0] = 0;
    for (i = 0; i < a->used && j < max; i++) {
        r[j] |= ((sp_digit)a->dp[i]) << s;
        if (s + DIGIT_BIT >= 23) {
            r[j] &= 0x7fffff;
            if (j + 1 >= max)
                break;
            s = 23 - s;
            if (s == DIGIT_BIT) {
                r[++j] = 0;
                s = 0;
            }
            else {
                r[++j] = a->dp[i] >> s;
                s = DIGIT_BIT - s;
            }
        }
        else
            s += DIGIT_BIT;
    }

    for (j++; j < max; j++)
        r[j] = 0;
#endif
}

/* Write r as big endian to byte aray.
 * Fixed length number of bytes written: 256
 *
 * r  A single precision integer.
 * a  Byte array.
 */
static void sp_2048_to_bin(sp_digit* r, byte* a)
{
    int i, j, s = 0, b;

    for (i=0; i<89; i++) {
        r[i+1] += r[i] >> 23;
        r[i] &= 0x7fffff;
    }
    j = 2048 / 8 - 1;
    a[j] = 0;
    for (i=0; i<90 && j>=0; i++) {
        b = 0;
        a[j--] |= r[i] << s; b += 8 - s;
        if (j < 0)
            break;
        while (b < 23) {
            a[j--] = r[i] >> b; b += 8;
            if (j < 0)
                break;
        }
        s = 8 - (b - 23);
        if (j >= 0)
            a[j] = 0;
        if (s != 0)
            j++;
    }
}

#ifndef WOLFSSL_SP_SMALL
/* Multiply a and b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static void sp_2048_mul_15(sp_digit* r, const sp_digit* a,
    const sp_digit* b)
{
    int64_t t0   = ((int64_t)a[ 0]) * b[ 0];
    int64_t t1   = ((int64_t)a[ 0]) * b[ 1]
                 + ((int64_t)a[ 1]) * b[ 0];
    int64_t t2   = ((int64_t)a[ 0]) * b[ 2]
                 + ((int64_t)a[ 1]) * b[ 1]
                 + ((int64_t)a[ 2]) * b[ 0];
    int64_t t3   = ((int64_t)a[ 0]) * b[ 3]
                 + ((int64_t)a[ 1]) * b[ 2]
                 + ((int64_t)a[ 2]) * b[ 1]
                 + ((int64_t)a[ 3]) * b[ 0];
    int64_t t4   = ((int64_t)a[ 0]) * b[ 4]
                 + ((int64_t)a[ 1]) * b[ 3]
                 + ((int64_t)a[ 2]) * b[ 2]
                 + ((int64_t)a[ 3]) * b[ 1]
                 + ((int64_t)a[ 4]) * b[ 0];
    int64_t t5   = ((int64_t)a[ 0]) * b[ 5]
                 + ((int64_t)a[ 1]) * b[ 4]
                 + ((int64_t)a[ 2]) * b[ 3]
                 + ((int64_t)a[ 3]) * b[ 2]
                 + ((int64_t)a[ 4]) * b[ 1]
                 + ((int64_t)a[ 5]) * b[ 0];
    int64_t t6   = ((int64_t)a[ 0]) * b[ 6]
                 + ((int64_t)a[ 1]) * b[ 5]
                 + ((int64_t)a[ 2]) * b[ 4]
                 + ((int64_t)a[ 3]) * b[ 3]
                 + ((int64_t)a[ 4]) * b[ 2]
                 + ((int64_t)a[ 5]) * b[ 1]
                 + ((int64_t)a[ 6]) * b[ 0];
    int64_t t7   = ((int64_t)a[ 0]) * b[ 7]
                 + ((int64_t)a[ 1]) * b[ 6]
                 + ((int64_t)a[ 2]) * b[ 5]
                 + ((int64_t)a[ 3]) * b[ 4]
                 + ((int64_t)a[ 4]) * b[ 3]
                 + ((int64_t)a[ 5]) * b[ 2]
                 + ((int64_t)a[ 6]) * b[ 1]
                 + ((int64_t)a[ 7]) * b[ 0];
    int64_t t8   = ((int64_t)a[ 0]) * b[ 8]
                 + ((int64_t)a[ 1]) * b[ 7]
                 + ((int64_t)a[ 2]) * b[ 6]
                 + ((int64_t)a[ 3]) * b[ 5]
                 + ((int64_t)a[ 4]) * b[ 4]
                 + ((int64_t)a[ 5]) * b[ 3]
                 + ((int64_t)a[ 6]) * b[ 2]
                 + ((int64_t)a[ 7]) * b[ 1]
                 + ((int64_t)a[ 8]) * b[ 0];
    int64_t t9   = ((int64_t)a[ 0]) * b[ 9]
                 + ((int64_t)a[ 1]) * b[ 8]
                 + ((int64_t)a[ 2]) * b[ 7]
                 + ((int64_t)a[ 3]) * b[ 6]
                 + ((int64_t)a[ 4]) * b[ 5]
                 + ((int64_t)a[ 5]) * b[ 4]
                 + ((int64_t)a[ 6]) * b[ 3]
                 + ((int64_t)a[ 7]) * b[ 2]
                 + ((int64_t)a[ 8]) * b[ 1]
                 + ((int64_t)a[ 9]) * b[ 0];
    int64_t t10  = ((int64_t)a[ 0]) * b[10]
                 + ((int64_t)a[ 1]) * b[ 9]
                 + ((int64_t)a[ 2]) * b[ 8]
                 + ((int64_t)a[ 3]) * b[ 7]
                 + ((int64_t)a[ 4]) * b[ 6]
                 + ((int64_t)a[ 5]) * b[ 5]
                 + ((int64_t)a[ 6]) * b[ 4]
                 + ((int64_t)a[ 7]) * b[ 3]
                 + ((int64_t)a[ 8]) * b[ 2]
                 + ((int64_t)a[ 9]) * b[ 1]
                 + ((int64_t)a[10]) * b[ 0];
    int64_t t11  = ((int64_t)a[ 0]) * b[11]
                 + ((int64_t)a[ 1]) * b[10]
                 + ((int64_t)a[ 2]) * b[ 9]
                 + ((int64_t)a[ 3]) * b[ 8]
                 + ((int64_t)a[ 4]) * b[ 7]
                 + ((int64_t)a[ 5]) * b[ 6]
                 + ((int64_t)a[ 6]) * b[ 5]
                 + ((int64_t)a[ 7]) * b[ 4]
                 + ((int64_t)a[ 8]) * b[ 3]
                 + ((int64_t)a[ 9]) * b[ 2]
                 + ((int64_t)a[10]) * b[ 1]
                 + ((int64_t)a[11]) * b[ 0];
    int64_t t12  = ((int64_t)a[ 0]) * b[12]
                 + ((int64_t)a[ 1]) * b[11]
                 + ((int64_t)a[ 2]) * b[10]
                 + ((int64_t)a[ 3]) * b[ 9]
                 + ((int64_t)a[ 4]) * b[ 8]
                 + ((int64_t)a[ 5]) * b[ 7]
                 + ((int64_t)a[ 6]) * b[ 6]
                 + ((int64_t)a[ 7]) * b[ 5]
                 + ((int64_t)a[ 8]) * b[ 4]
                 + ((int64_t)a[ 9]) * b[ 3]
                 + ((int64_t)a[10]) * b[ 2]
                 + ((int64_t)a[11]) * b[ 1]
                 + ((int64_t)a[12]) * b[ 0];
    int64_t t13  = ((int64_t)a[ 0]) * b[13]
                 + ((int64_t)a[ 1]) * b[12]
                 + ((int64_t)a[ 2]) * b[11]
                 + ((int64_t)a[ 3]) * b[10]
                 + ((int64_t)a[ 4]) * b[ 9]
                 + ((int64_t)a[ 5]) * b[ 8]
                 + ((int64_t)a[ 6]) * b[ 7]
                 + ((int64_t)a[ 7]) * b[ 6]
                 + ((int64_t)a[ 8]) * b[ 5]
                 + ((int64_t)a[ 9]) * b[ 4]
                 + ((int64_t)a[10]) * b[ 3]
                 + ((int64_t)a[11]) * b[ 2]
                 + ((int64_t)a[12]) * b[ 1]
                 + ((int64_t)a[13]) * b[ 0];
    int64_t t14  = ((int64_t)a[ 0]) * b[14]
                 + ((int64_t)a[ 1]) * b[13]
                 + ((int64_t)a[ 2]) * b[12]
                 + ((int64_t)a[ 3]) * b[11]
                 + ((int64_t)a[ 4]) * b[10]
                 + ((int64_t)a[ 5]) * b[ 9]
                 + ((int64_t)a[ 6]) * b[ 8]
                 + ((int64_t)a[ 7]) * b[ 7]
                 + ((int64_t)a[ 8]) * b[ 6]
                 + ((int64_t)a[ 9]) * b[ 5]
                 + ((int64_t)a[10]) * b[ 4]
                 + ((int64_t)a[11]) * b[ 3]
                 + ((int64_t)a[12]) * b[ 2]
                 + ((int64_t)a[13]) * b[ 1]
                 + ((int64_t)a[14]) * b[ 0];
    int64_t t15  = ((int64_t)a[ 1]) * b[14]
                 + ((int64_t)a[ 2]) * b[13]
                 + ((int64_t)a[ 3]) * b[12]
                 + ((int64_t)a[ 4]) * b[11]
                 + ((int64_t)a[ 5]) * b[10]
                 + ((int64_t)a[ 6]) * b[ 9]
                 + ((int64_t)a[ 7]) * b[ 8]
                 + ((int64_t)a[ 8]) * b[ 7]
                 + ((int64_t)a[ 9]) * b[ 6]
                 + ((int64_t)a[10]) * b[ 5]
                 + ((int64_t)a[11]) * b[ 4]
                 + ((int64_t)a[12]) * b[ 3]
                 + ((int64_t)a[13]) * b[ 2]
                 + ((int64_t)a[14]) * b[ 1];
    int64_t t16  = ((int64_t)a[ 2]) * b[14]
                 + ((int64_t)a[ 3]) * b[13]
                 + ((int64_t)a[ 4]) * b[12]
                 + ((int64_t)a[ 5]) * b[11]
                 + ((int64_t)a[ 6]) * b[10]
                 + ((int64_t)a[ 7]) * b[ 9]
                 + ((int64_t)a[ 8]) * b[ 8]
                 + ((int64_t)a[ 9]) * b[ 7]
                 + ((int64_t)a[10]) * b[ 6]
                 + ((int64_t)a[11]) * b[ 5]
                 + ((int64_t)a[12]) * b[ 4]
                 + ((int64_t)a[13]) * b[ 3]
                 + ((int64_t)a[14]) * b[ 2];
    int64_t t17  = ((int64_t)a[ 3]) * b[14]
                 + ((int64_t)a[ 4]) * b[13]
                 + ((int64_t)a[ 5]) * b[12]
                 + ((int64_t)a[ 6]) * b[11]
                 + ((int64_t)a[ 7]) * b[10]
                 + ((int64_t)a[ 8]) * b[ 9]
                 + ((int64_t)a[ 9]) * b[ 8]
                 + ((int64_t)a[10]) * b[ 7]
                 + ((int64_t)a[11]) * b[ 6]
                 + ((int64_t)a[12]) * b[ 5]
                 + ((int64_t)a[13]) * b[ 4]
                 + ((int64_t)a[14]) * b[ 3];
    int64_t t18  = ((int64_t)a[ 4]) * b[14]
                 + ((int64_t)a[ 5]) * b[13]
                 + ((int64_t)a[ 6]) * b[12]
                 + ((int64_t)a[ 7]) * b[11]
                 + ((int64_t)a[ 8]) * b[10]
                 + ((int64_t)a[ 9]) * b[ 9]
                 + ((int64_t)a[10]) * b[ 8]
                 + ((int64_t)a[11]) * b[ 7]
                 + ((int64_t)a[12]) * b[ 6]
                 + ((int64_t)a[13]) * b[ 5]
                 + ((int64_t)a[14]) * b[ 4];
    int64_t t19  = ((int64_t)a[ 5]) * b[14]
                 + ((int64_t)a[ 6]) * b[13]
                 + ((int64_t)a[ 7]) * b[12]
                 + ((int64_t)a[ 8]) * b[11]
                 + ((int64_t)a[ 9]) * b[10]
                 + ((int64_t)a[10]) * b[ 9]
                 + ((int64_t)a[11]) * b[ 8]
                 + ((int64_t)a[12]) * b[ 7]
                 + ((int64_t)a[13]) * b[ 6]
                 + ((int64_t)a[14]) * b[ 5];
    int64_t t20  = ((int64_t)a[ 6]) * b[14]
                 + ((int64_t)a[ 7]) * b[13]
                 + ((int64_t)a[ 8]) * b[12]
                 + ((int64_t)a[ 9]) * b[11]
                 + ((int64_t)a[10]) * b[10]
                 + ((int64_t)a[11]) * b[ 9]
                 + ((int64_t)a[12]) * b[ 8]
                 + ((int64_t)a[13]) * b[ 7]
                 + ((int64_t)a[14]) * b[ 6];
    int64_t t21  = ((int64_t)a[ 7]) * b[14]
                 + ((int64_t)a[ 8]) * b[13]
                 + ((int64_t)a[ 9]) * b[12]
                 + ((int64_t)a[10]) * b[11]
                 + ((int64_t)a[11]) * b[10]
                 + ((int64_t)a[12]) * b[ 9]
                 + ((int64_t)a[13]) * b[ 8]
                 + ((int64_t)a[14]) * b[ 7];
    int64_t t22  = ((int64_t)a[ 8]) * b[14]
                 + ((int64_t)a[ 9]) * b[13]
                 + ((int64_t)a[10]) * b[12]
                 + ((int64_t)a[11]) * b[11]
                 + ((int64_t)a[12]) * b[10]
                 + ((int64_t)a[13]) * b[ 9]
                 + ((int64_t)a[14]) * b[ 8];
    int64_t t23  = ((int64_t)a[ 9]) * b[14]
                 + ((int64_t)a[10]) * b[13]
                 + ((int64_t)a[11]) * b[12]
                 + ((int64_t)a[12]) * b[11]
                 + ((int64_t)a[13]) * b[10]
                 + ((int64_t)a[14]) * b[ 9];
    int64_t t24  = ((int64_t)a[10]) * b[14]
                 + ((int64_t)a[11]) * b[13]
                 + ((int64_t)a[12]) * b[12]
                 + ((int64_t)a[13]) * b[11]
                 + ((int64_t)a[14]) * b[10];
    int64_t t25  = ((int64_t)a[11]) * b[14]
                 + ((int64_t)a[12]) * b[13]
                 + ((int64_t)a[13]) * b[12]
                 + ((int64_t)a[14]) * b[11];
    int64_t t26  = ((int64_t)a[12]) * b[14]
                 + ((int64_t)a[13]) * b[13]
                 + ((int64_t)a[14]) * b[12];
    int64_t t27  = ((int64_t)a[13]) * b[14]
                 + ((int64_t)a[14]) * b[13];
    int64_t t28  = ((int64_t)a[14]) * b[14];

    t1   += t0  >> 23; r[ 0] = t0  & 0x7fffff;
    t2   += t1  >> 23; r[ 1] = t1  & 0x7fffff;
    t3   += t2  >> 23; r[ 2] = t2  & 0x7fffff;
    t4   += t3  >> 23; r[ 3] = t3  & 0x7fffff;
    t5   += t4  >> 23; r[ 4] = t4  & 0x7fffff;
    t6   += t5  >> 23; r[ 5] = t5  & 0x7fffff;
    t7   += t6  >> 23; r[ 6] = t6  & 0x7fffff;
    t8   += t7  >> 23; r[ 7] = t7  & 0x7fffff;
    t9   += t8  >> 23; r[ 8] = t8  & 0x7fffff;
    t10  += t9  >> 23; r[ 9] = t9  & 0x7fffff;
    t11  += t10 >> 23; r[10] = t10 & 0x7fffff;
    t12  += t11 >> 23; r[11] = t11 & 0x7fffff;
    t13  += t12 >> 23; r[12] = t12 & 0x7fffff;
    t14  += t13 >> 23; r[13] = t13 & 0x7fffff;
    t15  += t14 >> 23; r[14] = t14 & 0x7fffff;
    t16  += t15 >> 23; r[15] = t15 & 0x7fffff;
    t17  += t16 >> 23; r[16] = t16 & 0x7fffff;
    t18  += t17 >> 23; r[17] = t17 & 0x7fffff;
    t19  += t18 >> 23; r[18] = t18 & 0x7fffff;
    t20  += t19 >> 23; r[19] = t19 & 0x7fffff;
    t21  += t20 >> 23; r[20] = t20 & 0x7fffff;
    t22  += t21 >> 23; r[21] = t21 & 0x7fffff;
    t23  += t22 >> 23; r[22] = t22 & 0x7fffff;
    t24  += t23 >> 23; r[23] = t23 & 0x7fffff;
    t25  += t24 >> 23; r[24] = t24 & 0x7fffff;
    t26  += t25 >> 23; r[25] = t25 & 0x7fffff;
    t27  += t26 >> 23; r[26] = t26 & 0x7fffff;
    t28  += t27 >> 23; r[27] = t27 & 0x7fffff;
    r[29] = (sp_digit)(t28 >> 23);
                       r[28] = t28 & 0x7fffff;
}

/* Square a and put result in r. (r = a * a)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 */
SP_NOINLINE static void sp_2048_sqr_15(sp_digit* r, const sp_digit* a)
{
    int64_t t0   =  ((int64_t)a[ 0]) * a[ 0];
    int64_t t1   = (((int64_t)a[ 0]) * a[ 1]) * 2;
    int64_t t2   = (((int64_t)a[ 0]) * a[ 2]) * 2
                 +  ((int64_t)a[ 1]) * a[ 1];
    int64_t t3   = (((int64_t)a[ 0]) * a[ 3]
                 +  ((int64_t)a[ 1]) * a[ 2]) * 2;
    int64_t t4   = (((int64_t)a[ 0]) * a[ 4]
                 +  ((int64_t)a[ 1]) * a[ 3]) * 2
                 +  ((int64_t)a[ 2]) * a[ 2];
    int64_t t5   = (((int64_t)a[ 0]) * a[ 5]
                 +  ((int64_t)a[ 1]) * a[ 4]
                 +  ((int64_t)a[ 2]) * a[ 3]) * 2;
    int64_t t6   = (((int64_t)a[ 0]) * a[ 6]
                 +  ((int64_t)a[ 1]) * a[ 5]
                 +  ((int64_t)a[ 2]) * a[ 4]) * 2
                 +  ((int64_t)a[ 3]) * a[ 3];
    int64_t t7   = (((int64_t)a[ 0]) * a[ 7]
                 +  ((int64_t)a[ 1]) * a[ 6]
                 +  ((int64_t)a[ 2]) * a[ 5]
                 +  ((int64_t)a[ 3]) * a[ 4]) * 2;
    int64_t t8   = (((int64_t)a[ 0]) * a[ 8]
                 +  ((int64_t)a[ 1]) * a[ 7]
                 +  ((int64_t)a[ 2]) * a[ 6]
                 +  ((int64_t)a[ 3]) * a[ 5]) * 2
                 +  ((int64_t)a[ 4]) * a[ 4];
    int64_t t9   = (((int64_t)a[ 0]) * a[ 9]
                 +  ((int64_t)a[ 1]) * a[ 8]
                 +  ((int64_t)a[ 2]) * a[ 7]
                 +  ((int64_t)a[ 3]) * a[ 6]
                 +  ((int64_t)a[ 4]) * a[ 5]) * 2;
    int64_t t10  = (((int64_t)a[ 0]) * a[10]
                 +  ((int64_t)a[ 1]) * a[ 9]
                 +  ((int64_t)a[ 2]) * a[ 8]
                 +  ((int64_t)a[ 3]) * a[ 7]
                 +  ((int64_t)a[ 4]) * a[ 6]) * 2
                 +  ((int64_t)a[ 5]) * a[ 5];
    int64_t t11  = (((int64_t)a[ 0]) * a[11]
                 +  ((int64_t)a[ 1]) * a[10]
                 +  ((int64_t)a[ 2]) * a[ 9]
                 +  ((int64_t)a[ 3]) * a[ 8]
                 +  ((int64_t)a[ 4]) * a[ 7]
                 +  ((int64_t)a[ 5]) * a[ 6]) * 2;
    int64_t t12  = (((int64_t)a[ 0]) * a[12]
                 +  ((int64_t)a[ 1]) * a[11]
                 +  ((int64_t)a[ 2]) * a[10]
                 +  ((int64_t)a[ 3]) * a[ 9]
                 +  ((int64_t)a[ 4]) * a[ 8]
                 +  ((int64_t)a[ 5]) * a[ 7]) * 2
                 +  ((int64_t)a[ 6]) * a[ 6];
    int64_t t13  = (((int64_t)a[ 0]) * a[13]
                 +  ((int64_t)a[ 1]) * a[12]
                 +  ((int64_t)a[ 2]) * a[11]
                 +  ((int64_t)a[ 3]) * a[10]
                 +  ((int64_t)a[ 4]) * a[ 9]
                 +  ((int64_t)a[ 5]) * a[ 8]
                 +  ((int64_t)a[ 6]) * a[ 7]) * 2;
    int64_t t14  = (((int64_t)a[ 0]) * a[14]
                 +  ((int64_t)a[ 1]) * a[13]
                 +  ((int64_t)a[ 2]) * a[12]
                 +  ((int64_t)a[ 3]) * a[11]
                 +  ((int64_t)a[ 4]) * a[10]
                 +  ((int64_t)a[ 5]) * a[ 9]
                 +  ((int64_t)a[ 6]) * a[ 8]) * 2
                 +  ((int64_t)a[ 7]) * a[ 7];
    int64_t t15  = (((int64_t)a[ 1]) * a[14]
                 +  ((int64_t)a[ 2]) * a[13]
                 +  ((int64_t)a[ 3]) * a[12]
                 +  ((int64_t)a[ 4]) * a[11]
                 +  ((int64_t)a[ 5]) * a[10]
                 +  ((int64_t)a[ 6]) * a[ 9]
                 +  ((int64_t)a[ 7]) * a[ 8]) * 2;
    int64_t t16  = (((int64_t)a[ 2]) * a[14]
                 +  ((int64_t)a[ 3]) * a[13]
                 +  ((int64_t)a[ 4]) * a[12]
                 +  ((int64_t)a[ 5]) * a[11]
                 +  ((int64_t)a[ 6]) * a[10]
                 +  ((int64_t)a[ 7]) * a[ 9]) * 2
                 +  ((int64_t)a[ 8]) * a[ 8];
    int64_t t17  = (((int64_t)a[ 3]) * a[14]
                 +  ((int64_t)a[ 4]) * a[13]
                 +  ((int64_t)a[ 5]) * a[12]
                 +  ((int64_t)a[ 6]) * a[11]
                 +  ((int64_t)a[ 7]) * a[10]
                 +  ((int64_t)a[ 8]) * a[ 9]) * 2;
    int64_t t18  = (((int64_t)a[ 4]) * a[14]
                 +  ((int64_t)a[ 5]) * a[13]
                 +  ((int64_t)a[ 6]) * a[12]
                 +  ((int64_t)a[ 7]) * a[11]
                 +  ((int64_t)a[ 8]) * a[10]) * 2
                 +  ((int64_t)a[ 9]) * a[ 9];
    int64_t t19  = (((int64_t)a[ 5]) * a[14]
                 +  ((int64_t)a[ 6]) * a[13]
                 +  ((int64_t)a[ 7]) * a[12]
                 +  ((int64_t)a[ 8]) * a[11]
                 +  ((int64_t)a[ 9]) * a[10]) * 2;
    int64_t t20  = (((int64_t)a[ 6]) * a[14]
                 +  ((int64_t)a[ 7]) * a[13]
                 +  ((int64_t)a[ 8]) * a[12]
                 +  ((int64_t)a[ 9]) * a[11]) * 2
                 +  ((int64_t)a[10]) * a[10];
    int64_t t21  = (((int64_t)a[ 7]) * a[14]
                 +  ((int64_t)a[ 8]) * a[13]
                 +  ((int64_t)a[ 9]) * a[12]
                 +  ((int64_t)a[10]) * a[11]) * 2;
    int64_t t22  = (((int64_t)a[ 8]) * a[14]
                 +  ((int64_t)a[ 9]) * a[13]
                 +  ((int64_t)a[10]) * a[12]) * 2
                 +  ((int64_t)a[11]) * a[11];
    int64_t t23  = (((int64_t)a[ 9]) * a[14]
                 +  ((int64_t)a[10]) * a[13]
                 +  ((int64_t)a[11]) * a[12]) * 2;
    int64_t t24  = (((int64_t)a[10]) * a[14]
                 +  ((int64_t)a[11]) * a[13]) * 2
                 +  ((int64_t)a[12]) * a[12];
    int64_t t25  = (((int64_t)a[11]) * a[14]
                 +  ((int64_t)a[12]) * a[13]) * 2;
    int64_t t26  = (((int64_t)a[12]) * a[14]) * 2
                 +  ((int64_t)a[13]) * a[13];
    int64_t t27  = (((int64_t)a[13]) * a[14]) * 2;
    int64_t t28  =  ((int64_t)a[14]) * a[14];

    t1   += t0  >> 23; r[ 0] = t0  & 0x7fffff;
    t2   += t1  >> 23; r[ 1] = t1  & 0x7fffff;
    t3   += t2  >> 23; r[ 2] = t2  & 0x7fffff;
    t4   += t3  >> 23; r[ 3] = t3  & 0x7fffff;
    t5   += t4  >> 23; r[ 4] = t4  & 0x7fffff;
    t6   += t5  >> 23; r[ 5] = t5  & 0x7fffff;
    t7   += t6  >> 23; r[ 6] = t6  & 0x7fffff;
    t8   += t7  >> 23; r[ 7] = t7  & 0x7fffff;
    t9   += t8  >> 23; r[ 8] = t8  & 0x7fffff;
    t10  += t9  >> 23; r[ 9] = t9  & 0x7fffff;
    t11  += t10 >> 23; r[10] = t10 & 0x7fffff;
    t12  += t11 >> 23; r[11] = t11 & 0x7fffff;
    t13  += t12 >> 23; r[12] = t12 & 0x7fffff;
    t14  += t13 >> 23; r[13] = t13 & 0x7fffff;
    t15  += t14 >> 23; r[14] = t14 & 0x7fffff;
    t16  += t15 >> 23; r[15] = t15 & 0x7fffff;
    t17  += t16 >> 23; r[16] = t16 & 0x7fffff;
    t18  += t17 >> 23; r[17] = t17 & 0x7fffff;
    t19  += t18 >> 23; r[18] = t18 & 0x7fffff;
    t20  += t19 >> 23; r[19] = t19 & 0x7fffff;
    t21  += t20 >> 23; r[20] = t20 & 0x7fffff;
    t22  += t21 >> 23; r[21] = t21 & 0x7fffff;
    t23  += t22 >> 23; r[22] = t22 & 0x7fffff;
    t24  += t23 >> 23; r[23] = t23 & 0x7fffff;
    t25  += t24 >> 23; r[24] = t24 & 0x7fffff;
    t26  += t25 >> 23; r[25] = t25 & 0x7fffff;
    t27  += t26 >> 23; r[26] = t26 & 0x7fffff;
    t28  += t27 >> 23; r[27] = t27 & 0x7fffff;
    r[29] = (sp_digit)(t28 >> 23);
                       r[28] = t28 & 0x7fffff;
}

/* Add b to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_2048_add_15(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    r[ 0] = a[ 0] + b[ 0];
    r[ 1] = a[ 1] + b[ 1];
    r[ 2] = a[ 2] + b[ 2];
    r[ 3] = a[ 3] + b[ 3];
    r[ 4] = a[ 4] + b[ 4];
    r[ 5] = a[ 5] + b[ 5];
    r[ 6] = a[ 6] + b[ 6];
    r[ 7] = a[ 7] + b[ 7];
    r[ 8] = a[ 8] + b[ 8];
    r[ 9] = a[ 9] + b[ 9];
    r[10] = a[10] + b[10];
    r[11] = a[11] + b[11];
    r[12] = a[12] + b[12];
    r[13] = a[13] + b[13];
    r[14] = a[14] + b[14];

    return 0;
}

/* Sub b from a into r. (r = a - b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_2048_sub_30(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 24; i += 8) {
        r[i + 0] = a[i + 0] - b[i + 0];
        r[i + 1] = a[i + 1] - b[i + 1];
        r[i + 2] = a[i + 2] - b[i + 2];
        r[i + 3] = a[i + 3] - b[i + 3];
        r[i + 4] = a[i + 4] - b[i + 4];
        r[i + 5] = a[i + 5] - b[i + 5];
        r[i + 6] = a[i + 6] - b[i + 6];
        r[i + 7] = a[i + 7] - b[i + 7];
    }
    r[24] = a[24] - b[24];
    r[25] = a[25] - b[25];
    r[26] = a[26] - b[26];
    r[27] = a[27] - b[27];
    r[28] = a[28] - b[28];
    r[29] = a[29] - b[29];

    return 0;
}

/* Add b to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_2048_add_30(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 24; i += 8) {
        r[i + 0] = a[i + 0] + b[i + 0];
        r[i + 1] = a[i + 1] + b[i + 1];
        r[i + 2] = a[i + 2] + b[i + 2];
        r[i + 3] = a[i + 3] + b[i + 3];
        r[i + 4] = a[i + 4] + b[i + 4];
        r[i + 5] = a[i + 5] + b[i + 5];
        r[i + 6] = a[i + 6] + b[i + 6];
        r[i + 7] = a[i + 7] + b[i + 7];
    }
    r[24] = a[24] + b[24];
    r[25] = a[25] + b[25];
    r[26] = a[26] + b[26];
    r[27] = a[27] + b[27];
    r[28] = a[28] + b[28];
    r[29] = a[29] + b[29];

    return 0;
}

/* Multiply a and b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static void sp_2048_mul_45(sp_digit* r, const sp_digit* a,
    const sp_digit* b)
{
    sp_digit p0[30];
    sp_digit p1[30];
    sp_digit p2[30];
    sp_digit p3[30];
    sp_digit p4[30];
    sp_digit p5[30];
    sp_digit t0[30];
    sp_digit t1[30];
    sp_digit t2[30];
    sp_digit a0[15];
    sp_digit a1[15];
    sp_digit a2[15];
    sp_digit b0[15];
    sp_digit b1[15];
    sp_digit b2[15];
    sp_2048_add_15(a0, a, &a[15]);
    sp_2048_add_15(b0, b, &b[15]);
    sp_2048_add_15(a1, &a[15], &a[30]);
    sp_2048_add_15(b1, &b[15], &b[30]);
    sp_2048_add_15(a2, a0, &a[30]);
    sp_2048_add_15(b2, b0, &b[30]);
    sp_2048_mul_15(p0, a, b);
    sp_2048_mul_15(p2, &a[15], &b[15]);
    sp_2048_mul_15(p4, &a[30], &b[30]);
    sp_2048_mul_15(p1, a0, b0);
    sp_2048_mul_15(p3, a1, b1);
    sp_2048_mul_15(p5, a2, b2);
    XMEMSET(r, 0, sizeof(*r)*2*45);
    sp_2048_sub_30(t0, p3, p2);
    sp_2048_sub_30(t1, p1, p2);
    sp_2048_sub_30(t2, p5, t0);
    sp_2048_sub_30(t2, t2, t1);
    sp_2048_sub_30(t0, t0, p4);
    sp_2048_sub_30(t1, t1, p0);
    sp_2048_add_30(r, r, p0);
    sp_2048_add_30(&r[15], &r[15], t1);
    sp_2048_add_30(&r[30], &r[30], t2);
    sp_2048_add_30(&r[45], &r[45], t0);
    sp_2048_add_30(&r[60], &r[60], p4);
}

/* Square a into r. (r = a * a)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 */
SP_NOINLINE static void sp_2048_sqr_45(sp_digit* r, const sp_digit* a)
{
    sp_digit p0[30];
    sp_digit p1[30];
    sp_digit p2[30];
    sp_digit p3[30];
    sp_digit p4[30];
    sp_digit p5[30];
    sp_digit t0[30];
    sp_digit t1[30];
    sp_digit t2[30];
    sp_digit a0[15];
    sp_digit a1[15];
    sp_digit a2[15];
    sp_2048_add_15(a0, a, &a[15]);
    sp_2048_add_15(a1, &a[15], &a[30]);
    sp_2048_add_15(a2, a0, &a[30]);
    sp_2048_sqr_15(p0, a);
    sp_2048_sqr_15(p2, &a[15]);
    sp_2048_sqr_15(p4, &a[30]);
    sp_2048_sqr_15(p1, a0);
    sp_2048_sqr_15(p3, a1);
    sp_2048_sqr_15(p5, a2);
    XMEMSET(r, 0, sizeof(*r)*2*45);
    sp_2048_sub_30(t0, p3, p2);
    sp_2048_sub_30(t1, p1, p2);
    sp_2048_sub_30(t2, p5, t0);
    sp_2048_sub_30(t2, t2, t1);
    sp_2048_sub_30(t0, t0, p4);
    sp_2048_sub_30(t1, t1, p0);
    sp_2048_add_30(r, r, p0);
    sp_2048_add_30(&r[15], &r[15], t1);
    sp_2048_add_30(&r[30], &r[30], t2);
    sp_2048_add_30(&r[45], &r[45], t0);
    sp_2048_add_30(&r[60], &r[60], p4);
}

/* Add b to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_2048_add_45(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 40; i += 8) {
        r[i + 0] = a[i + 0] + b[i + 0];
        r[i + 1] = a[i + 1] + b[i + 1];
        r[i + 2] = a[i + 2] + b[i + 2];
        r[i + 3] = a[i + 3] + b[i + 3];
        r[i + 4] = a[i + 4] + b[i + 4];
        r[i + 5] = a[i + 5] + b[i + 5];
        r[i + 6] = a[i + 6] + b[i + 6];
        r[i + 7] = a[i + 7] + b[i + 7];
    }
    r[40] = a[40] + b[40];
    r[41] = a[41] + b[41];
    r[42] = a[42] + b[42];
    r[43] = a[43] + b[43];
    r[44] = a[44] + b[44];

    return 0;
}

/* Add b to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_2048_add_90(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 88; i += 8) {
        r[i + 0] = a[i + 0] + b[i + 0];
        r[i + 1] = a[i + 1] + b[i + 1];
        r[i + 2] = a[i + 2] + b[i + 2];
        r[i + 3] = a[i + 3] + b[i + 3];
        r[i + 4] = a[i + 4] + b[i + 4];
        r[i + 5] = a[i + 5] + b[i + 5];
        r[i + 6] = a[i + 6] + b[i + 6];
        r[i + 7] = a[i + 7] + b[i + 7];
    }
    r[88] = a[88] + b[88];
    r[89] = a[89] + b[89];

    return 0;
}

/* Sub b from a into r. (r = a - b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_2048_sub_90(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 88; i += 8) {
        r[i + 0] = a[i + 0] - b[i + 0];
        r[i + 1] = a[i + 1] - b[i + 1];
        r[i + 2] = a[i + 2] - b[i + 2];
        r[i + 3] = a[i + 3] - b[i + 3];
        r[i + 4] = a[i + 4] - b[i + 4];
        r[i + 5] = a[i + 5] - b[i + 5];
        r[i + 6] = a[i + 6] - b[i + 6];
        r[i + 7] = a[i + 7] - b[i + 7];
    }
    r[88] = a[88] - b[88];
    r[89] = a[89] - b[89];

    return 0;
}

/* Multiply a and b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static void sp_2048_mul_90(sp_digit* r, const sp_digit* a,
    const sp_digit* b)
{
    sp_digit* z0 = r;
    sp_digit z1[90];
    sp_digit* a1 = z1;
    sp_digit b1[45];
    sp_digit* z2 = r + 90;
    sp_2048_add_45(a1, a, &a[45]);
    sp_2048_add_45(b1, b, &b[45]);
    sp_2048_mul_45(z2, &a[45], &b[45]);
    sp_2048_mul_45(z0, a, b);
    sp_2048_mul_45(z1, a1, b1);
    sp_2048_sub_90(z1, z1, z2);
    sp_2048_sub_90(z1, z1, z0);
    sp_2048_add_90(r + 45, r + 45, z1);
}

/* Square a and put result in r. (r = a * a)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 */
SP_NOINLINE static void sp_2048_sqr_90(sp_digit* r, const sp_digit* a)
{
    sp_digit* z0 = r;
    sp_digit z1[90];
    sp_digit* a1 = z1;
    sp_digit* z2 = r + 90;
    sp_2048_add_45(a1, a, &a[45]);
    sp_2048_sqr_45(z2, &a[45]);
    sp_2048_sqr_45(z0, a);
    sp_2048_sqr_45(z1, a1);
    sp_2048_sub_90(z1, z1, z2);
    sp_2048_sub_90(z1, z1, z0);
    sp_2048_add_90(r + 45, r + 45, z1);
}

#endif /* !WOLFSSL_SP_SMALL */
#ifdef WOLFSSL_SP_SMALL
/* Add b to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_2048_add_90(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 90; i++)
        r[i] = a[i] + b[i];

    return 0;
}
#endif /* WOLFSSL_SP_SMALL */
#ifdef WOLFSSL_SP_SMALL
/* Sub b from a into r. (r = a - b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_2048_sub_90(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 90; i++)
        r[i] = a[i] - b[i];

    return 0;
}

#endif /* WOLFSSL_SP_SMALL */
#ifdef WOLFSSL_SP_SMALL
/* Multiply a and b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static void sp_2048_mul_90(sp_digit* r, const sp_digit* a,
    const sp_digit* b)
{
    int i, j, k;
    int64_t c;

    c = ((int64_t)a[89]) * b[89];
    r[179] = (sp_digit)(c >> 23);
    c = (c & 0x7fffff) << 23;
    for (k = 177; k >= 0; k--) {
        for (i = 89; i >= 0; i--) {
            j = k - i;
            if (j >= 90)
                break;
            if (j < 0)
                continue;

            c += ((int64_t)a[i]) * b[j];
        }
        r[k + 2] += c >> 46;
        r[k + 1] = (c >> 23) & 0x7fffff;
        c = (c & 0x7fffff) << 23;
    }
    r[0] = (sp_digit)(c >> 23);
}

/* Square a and put result in r. (r = a * a)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 */
SP_NOINLINE static void sp_2048_sqr_90(sp_digit* r, const sp_digit* a)
{
    int i, j, k;
    int64_t c;

    c = ((int64_t)a[89]) * a[89];
    r[179] = (sp_digit)(c >> 23);
    c = (c & 0x7fffff) << 23;
    for (k = 177; k >= 0; k--) {
        for (i = 89; i >= 0; i--) {
            j = k - i;
            if (j >= 90 || i <= j)
                break;
            if (j < 0)
                continue;

            c += ((int64_t)a[i]) * a[j] * 2;
        }
        if (i == j)
           c += ((int64_t)a[i]) * a[i];

        r[k + 2] += c >> 46;
        r[k + 1] = (c >> 23) & 0x7fffff;
        c = (c & 0x7fffff) << 23;
    }
    r[0] = (sp_digit)(c >> 23);
}

#endif /* WOLFSSL_SP_SMALL */
#if (defined(WOLFSSL_HAVE_SP_RSA) || defined(WOLFSSL_HAVE_SP_DH)) && !defined(WOLFSSL_RSA_PUBLIC_ONLY)
#ifdef WOLFSSL_SP_SMALL
/* Add b to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_2048_add_45(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 45; i++)
        r[i] = a[i] + b[i];

    return 0;
}
#endif /* WOLFSSL_SP_SMALL */
#ifdef WOLFSSL_SP_SMALL
/* Sub b from a into r. (r = a - b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_2048_sub_45(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 45; i++)
        r[i] = a[i] - b[i];

    return 0;
}

#else
/* Sub b from a into r. (r = a - b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_2048_sub_45(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 40; i += 8) {
        r[i + 0] = a[i + 0] - b[i + 0];
        r[i + 1] = a[i + 1] - b[i + 1];
        r[i + 2] = a[i + 2] - b[i + 2];
        r[i + 3] = a[i + 3] - b[i + 3];
        r[i + 4] = a[i + 4] - b[i + 4];
        r[i + 5] = a[i + 5] - b[i + 5];
        r[i + 6] = a[i + 6] - b[i + 6];
        r[i + 7] = a[i + 7] - b[i + 7];
    }
    r[40] = a[40] - b[40];
    r[41] = a[41] - b[41];
    r[42] = a[42] - b[42];
    r[43] = a[43] - b[43];
    r[44] = a[44] - b[44];

    return 0;
}

#endif /* WOLFSSL_SP_SMALL */
#ifdef WOLFSSL_SP_SMALL
/* Multiply a and b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static void sp_2048_mul_45(sp_digit* r, const sp_digit* a,
    const sp_digit* b)
{
    int i, j, k;
    int64_t c;

    c = ((int64_t)a[44]) * b[44];
    r[89] = (sp_digit)(c >> 23);
    c = (c & 0x7fffff) << 23;
    for (k = 87; k >= 0; k--) {
        for (i = 44; i >= 0; i--) {
            j = k - i;
            if (j >= 45)
                break;
            if (j < 0)
                continue;

            c += ((int64_t)a[i]) * b[j];
        }
        r[k + 2] += c >> 46;
        r[k + 1] = (c >> 23) & 0x7fffff;
        c = (c & 0x7fffff) << 23;
    }
    r[0] = (sp_digit)(c >> 23);
}

/* Square a and put result in r. (r = a * a)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 */
SP_NOINLINE static void sp_2048_sqr_45(sp_digit* r, const sp_digit* a)
{
    int i, j, k;
    int64_t c;

    c = ((int64_t)a[44]) * a[44];
    r[89] = (sp_digit)(c >> 23);
    c = (c & 0x7fffff) << 23;
    for (k = 87; k >= 0; k--) {
        for (i = 44; i >= 0; i--) {
            j = k - i;
            if (j >= 45 || i <= j)
                break;
            if (j < 0)
                continue;

            c += ((int64_t)a[i]) * a[j] * 2;
        }
        if (i == j)
           c += ((int64_t)a[i]) * a[i];

        r[k + 2] += c >> 46;
        r[k + 1] = (c >> 23) & 0x7fffff;
        c = (c & 0x7fffff) << 23;
    }
    r[0] = (sp_digit)(c >> 23);
}

#endif /* WOLFSSL_SP_SMALL */
#endif /* (WOLFSSL_HAVE_SP_RSA || WOLFSSL_HAVE_SP_DH) && !WOLFSSL_RSA_PUBLIC_ONLY */

/* Caclulate the bottom digit of -1/a mod 2^n.
 *
 * a    A single precision number.
 * rho  Bottom word of inverse.
 */
static void sp_2048_mont_setup(const sp_digit* a, sp_digit* rho)
{
    sp_digit x, b;

    b = a[0];
    x = (((b + 2) & 4) << 1) + b; /* here x*a==1 mod 2**4 */
    x *= 2 - b * x;               /* here x*a==1 mod 2**8 */
    x *= 2 - b * x;               /* here x*a==1 mod 2**16 */
    x *= 2 - b * x;               /* here x*a==1 mod 2**32 */
    x &= 0x7fffff;

    /* rho = -1/m mod b */
    *rho = (1L << 23) - x;
}

/* Multiply a by scalar b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A scalar.
 */
SP_NOINLINE static void sp_2048_mul_d_90(sp_digit* r, const sp_digit* a,
    sp_digit b)
{
#ifdef WOLFSSL_SP_SMALL
    int64_t tb = b;
    int64_t t = 0;
    int i;

    for (i = 0; i < 90; i++) {
        t += tb * a[i];
        r[i] = t & 0x7fffff;
        t >>= 23;
    }
    r[90] = (sp_digit)t;
#else
    int64_t tb = b;
    int64_t t[8];
    int i;

    t[0] = tb * a[0]; r[0] = t[0] & 0x7fffff;
    for (i = 0; i < 88; i += 8) {
        t[1] = tb * a[i+1];
        r[i+1] = (sp_digit)(t[0] >> 23) + (t[1] & 0x7fffff);
        t[2] = tb * a[i+2];
        r[i+2] = (sp_digit)(t[1] >> 23) + (t[2] & 0x7fffff);
        t[3] = tb * a[i+3];
        r[i+3] = (sp_digit)(t[2] >> 23) + (t[3] & 0x7fffff);
        t[4] = tb * a[i+4];
        r[i+4] = (sp_digit)(t[3] >> 23) + (t[4] & 0x7fffff);
        t[5] = tb * a[i+5];
        r[i+5] = (sp_digit)(t[4] >> 23) + (t[5] & 0x7fffff);
        t[6] = tb * a[i+6];
        r[i+6] = (sp_digit)(t[5] >> 23) + (t[6] & 0x7fffff);
        t[7] = tb * a[i+7];
        r[i+7] = (sp_digit)(t[6] >> 23) + (t[7] & 0x7fffff);
        t[0] = tb * a[i+8];
        r[i+8] = (sp_digit)(t[7] >> 23) + (t[0] & 0x7fffff);
    }
    t[1] = tb * a[89];
    r[89] = (sp_digit)(t[0] >> 23) + (t[1] & 0x7fffff);
    r[90] =  (sp_digit)(t[1] >> 23);
#endif /* WOLFSSL_SP_SMALL */
}

#if (defined(WOLFSSL_HAVE_SP_RSA) || defined(WOLFSSL_HAVE_SP_DH)) && !defined(WOLFSSL_RSA_PUBLIC_ONLY)
/* r = 2^n mod m where n is the number of bits to reduce by.
 * Given m must be 2048 bits, just need to subtract.
 *
 * r  A single precision number.
 * m  A signle precision number.
 */
static void sp_2048_mont_norm_45(sp_digit* r, const sp_digit* m)
{
    /* Set r = 2^n - 1. */
#ifdef WOLFSSL_SP_SMALL
    int i;

    for (i=0; i<44; i++)
        r[i] = 0x7fffff;
#else
    int i;

    for (i = 0; i < 40; i += 8) {
        r[i + 0] = 0x7fffff;
        r[i + 1] = 0x7fffff;
        r[i + 2] = 0x7fffff;
        r[i + 3] = 0x7fffff;
        r[i + 4] = 0x7fffff;
        r[i + 5] = 0x7fffff;
        r[i + 6] = 0x7fffff;
        r[i + 7] = 0x7fffff;
    }
    r[40] = 0x7fffff;
    r[41] = 0x7fffff;
    r[42] = 0x7fffff;
    r[43] = 0x7fffff;
#endif
    r[44] = 0xfffl;

    /* r = (2^n - 1) mod n */
    sp_2048_sub_45(r, r, m);

    /* Add one so r = 2^n mod m */
    r[0] += 1;
}

/* Compare a with b in constant time.
 *
 * a  A single precision integer.
 * b  A single precision integer.
 * return -ve, 0 or +ve if a is less than, equal to or greater than b
 * respectively.
 */
static sp_digit sp_2048_cmp_45(const sp_digit* a, const sp_digit* b)
{
    sp_digit r = 0;
#ifdef WOLFSSL_SP_SMALL
    int i;

    for (i=44; i>=0; i--)
        r |= (a[i] - b[i]) & (0 - !r);
#else
    int i;

    r |= (a[44] - b[44]) & (0 - !r);
    r |= (a[43] - b[43]) & (0 - !r);
    r |= (a[42] - b[42]) & (0 - !r);
    r |= (a[41] - b[41]) & (0 - !r);
    r |= (a[40] - b[40]) & (0 - !r);
    for (i = 32; i >= 0; i -= 8) {
        r |= (a[i + 7] - b[i + 7]) & (0 - !r);
        r |= (a[i + 6] - b[i + 6]) & (0 - !r);
        r |= (a[i + 5] - b[i + 5]) & (0 - !r);
        r |= (a[i + 4] - b[i + 4]) & (0 - !r);
        r |= (a[i + 3] - b[i + 3]) & (0 - !r);
        r |= (a[i + 2] - b[i + 2]) & (0 - !r);
        r |= (a[i + 1] - b[i + 1]) & (0 - !r);
        r |= (a[i + 0] - b[i + 0]) & (0 - !r);
    }
#endif /* WOLFSSL_SP_SMALL */

    return r;
}

/* Conditionally subtract b from a using the mask m.
 * m is -1 to subtract and 0 when not.
 *
 * r  A single precision number representing condition subtract result.
 * a  A single precision number to subtract from.
 * b  A single precision number to subtract.
 * m  Mask value to apply.
 */
static void sp_2048_cond_sub_45(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit m)
{
#ifdef WOLFSSL_SP_SMALL
    int i;

    for (i = 0; i < 45; i++)
        r[i] = a[i] - (b[i] & m);
#else
    int i;

    for (i = 0; i < 40; i += 8) {
        r[i + 0] = a[i + 0] - (b[i + 0] & m);
        r[i + 1] = a[i + 1] - (b[i + 1] & m);
        r[i + 2] = a[i + 2] - (b[i + 2] & m);
        r[i + 3] = a[i + 3] - (b[i + 3] & m);
        r[i + 4] = a[i + 4] - (b[i + 4] & m);
        r[i + 5] = a[i + 5] - (b[i + 5] & m);
        r[i + 6] = a[i + 6] - (b[i + 6] & m);
        r[i + 7] = a[i + 7] - (b[i + 7] & m);
    }
    r[40] = a[40] - (b[40] & m);
    r[41] = a[41] - (b[41] & m);
    r[42] = a[42] - (b[42] & m);
    r[43] = a[43] - (b[43] & m);
    r[44] = a[44] - (b[44] & m);
#endif /* WOLFSSL_SP_SMALL */
}

/* Mul a by scalar b and add into r. (r += a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A scalar.
 */
SP_NOINLINE static void sp_2048_mul_add_45(sp_digit* r, const sp_digit* a,
        const sp_digit b)
{
#ifdef WOLFSSL_SP_SMALL
    int64_t tb = b;
    int64_t t = 0;
    int i;

    for (i = 0; i < 45; i++) {
        t += (tb * a[i]) + r[i];
        r[i] = t & 0x7fffff;
        t >>= 23;
    }
    r[45] += t;
#else
    int64_t tb = b;
    int64_t t[8];
    int i;

    t[0] = tb * a[0]; r[0] += t[0] & 0x7fffff;
    for (i = 0; i < 40; i += 8) {
        t[1] = tb * a[i+1];
        r[i+1] += (t[0] >> 23) + (t[1] & 0x7fffff);
        t[2] = tb * a[i+2];
        r[i+2] += (t[1] >> 23) + (t[2] & 0x7fffff);
        t[3] = tb * a[i+3];
        r[i+3] += (t[2] >> 23) + (t[3] & 0x7fffff);
        t[4] = tb * a[i+4];
        r[i+4] += (t[3] >> 23) + (t[4] & 0x7fffff);
        t[5] = tb * a[i+5];
        r[i+5] += (t[4] >> 23) + (t[5] & 0x7fffff);
        t[6] = tb * a[i+6];
        r[i+6] += (t[5] >> 23) + (t[6] & 0x7fffff);
        t[7] = tb * a[i+7];
        r[i+7] += (t[6] >> 23) + (t[7] & 0x7fffff);
        t[0] = tb * a[i+8];
        r[i+8] += (t[7] >> 23) + (t[0] & 0x7fffff);
    }
    t[1] = tb * a[41]; r[41] += (t[0] >> 23) + (t[1] & 0x7fffff);
    t[2] = tb * a[42]; r[42] += (t[1] >> 23) + (t[2] & 0x7fffff);
    t[3] = tb * a[43]; r[43] += (t[2] >> 23) + (t[3] & 0x7fffff);
    t[4] = tb * a[44]; r[44] += (t[3] >> 23) + (t[4] & 0x7fffff);
    r[45] +=  t[4] >> 23;
#endif /* WOLFSSL_SP_SMALL */
}

/* Normalize the values in each word to 23.
 *
 * a  Array of sp_digit to normalize.
 */
static void sp_2048_norm_45(sp_digit* a)
{
#ifdef WOLFSSL_SP_SMALL
    int i;
    for (i = 0; i < 44; i++) {
        a[i+1] += a[i] >> 23;
        a[i] &= 0x7fffff;
    }
#else
    int i;
    for (i = 0; i < 40; i += 8) {
        a[i+1] += a[i+0] >> 23; a[i+0] &= 0x7fffff;
        a[i+2] += a[i+1] >> 23; a[i+1] &= 0x7fffff;
        a[i+3] += a[i+2] >> 23; a[i+2] &= 0x7fffff;
        a[i+4] += a[i+3] >> 23; a[i+3] &= 0x7fffff;
        a[i+5] += a[i+4] >> 23; a[i+4] &= 0x7fffff;
        a[i+6] += a[i+5] >> 23; a[i+5] &= 0x7fffff;
        a[i+7] += a[i+6] >> 23; a[i+6] &= 0x7fffff;
        a[i+8] += a[i+7] >> 23; a[i+7] &= 0x7fffff;
        a[i+9] += a[i+8] >> 23; a[i+8] &= 0x7fffff;
    }
    a[40+1] += a[40] >> 23;
    a[40] &= 0x7fffff;
    a[41+1] += a[41] >> 23;
    a[41] &= 0x7fffff;
    a[42+1] += a[42] >> 23;
    a[42] &= 0x7fffff;
    a[43+1] += a[43] >> 23;
    a[43] &= 0x7fffff;
#endif
}

/* Shift the result in the high 1024 bits down to the bottom.
 *
 * r  A single precision number.
 * a  A single precision number.
 */
static void sp_2048_mont_shift_45(sp_digit* r, const sp_digit* a)
{
#ifdef WOLFSSL_SP_SMALL
    int i;
    int64_t n = a[44] >> 12;
    n += ((int64_t)a[45]) << 11;

    for (i = 0; i < 44; i++) {
        r[i] = n & 0x7fffff;
        n >>= 23;
        n += ((int64_t)a[46 + i]) << 11;
    }
    r[44] = (sp_digit)n;
#else
    int i;
    int64_t n = a[44] >> 12;
    n += ((int64_t)a[45]) << 11;
    for (i = 0; i < 40; i += 8) {
        r[i + 0] = n & 0x7fffff;
        n >>= 23; n += ((int64_t)a[i + 46]) << 11;
        r[i + 1] = n & 0x7fffff;
        n >>= 23; n += ((int64_t)a[i + 47]) << 11;
        r[i + 2] = n & 0x7fffff;
        n >>= 23; n += ((int64_t)a[i + 48]) << 11;
        r[i + 3] = n & 0x7fffff;
        n >>= 23; n += ((int64_t)a[i + 49]) << 11;
        r[i + 4] = n & 0x7fffff;
        n >>= 23; n += ((int64_t)a[i + 50]) << 11;
        r[i + 5] = n & 0x7fffff;
        n >>= 23; n += ((int64_t)a[i + 51]) << 11;
        r[i + 6] = n & 0x7fffff;
        n >>= 23; n += ((int64_t)a[i + 52]) << 11;
        r[i + 7] = n & 0x7fffff;
        n >>= 23; n += ((int64_t)a[i + 53]) << 11;
    }
    r[40] = n & 0x7fffff; n >>= 23; n += ((int64_t)a[86]) << 11;
    r[41] = n & 0x7fffff; n >>= 23; n += ((int64_t)a[87]) << 11;
    r[42] = n & 0x7fffff; n >>= 23; n += ((int64_t)a[88]) << 11;
    r[43] = n & 0x7fffff; n >>= 23; n += ((int64_t)a[89]) << 11;
    r[44] = (sp_digit)n;
#endif /* WOLFSSL_SP_SMALL */
    XMEMSET(&r[45], 0, sizeof(*r) * 45);
}

/* Reduce the number back to 2048 bits using Montgomery reduction.
 *
 * a   A single precision number to reduce in place.
 * m   The single precision number representing the modulus.
 * mp  The digit representing the negative inverse of m mod 2^n.
 */
static void sp_2048_mont_reduce_45(sp_digit* a, const sp_digit* m, sp_digit mp)
{
    int i;
    sp_digit mu;

    for (i=0; i<44; i++) {
        mu = (a[i] * mp) & 0x7fffff;
        sp_2048_mul_add_45(a+i, m, mu);
        a[i+1] += a[i] >> 23;
    }
    mu = (a[i] * mp) & 0xfffl;
    sp_2048_mul_add_45(a+i, m, mu);
    a[i+1] += a[i] >> 23;
    a[i] &= 0x7fffff;

    sp_2048_mont_shift_45(a, a);
    sp_2048_cond_sub_45(a, a, m, 0 - ((a[44] >> 12) > 0));
    sp_2048_norm_45(a);
}

/* Multiply two Montogmery form numbers mod the modulus (prime).
 * (r = a * b mod m)
 *
 * r   Result of multiplication.
 * a   First number to multiply in Montogmery form.
 * b   Second number to multiply in Montogmery form.
 * m   Modulus (prime).
 * mp  Montogmery mulitplier.
 */
static void sp_2048_mont_mul_45(sp_digit* r, const sp_digit* a, const sp_digit* b,
        const sp_digit* m, sp_digit mp)
{
    sp_2048_mul_45(r, a, b);
    sp_2048_mont_reduce_45(r, m, mp);
}

/* Square the Montgomery form number. (r = a * a mod m)
 *
 * r   Result of squaring.
 * a   Number to square in Montogmery form.
 * m   Modulus (prime).
 * mp  Montogmery mulitplier.
 */
static void sp_2048_mont_sqr_45(sp_digit* r, const sp_digit* a, const sp_digit* m,
        sp_digit mp)
{
    sp_2048_sqr_45(r, a);
    sp_2048_mont_reduce_45(r, m, mp);
}

/* Multiply a by scalar b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A scalar.
 */
SP_NOINLINE static void sp_2048_mul_d_45(sp_digit* r, const sp_digit* a,
    sp_digit b)
{
#ifdef WOLFSSL_SP_SMALL
    int64_t tb = b;
    int64_t t = 0;
    int i;

    for (i = 0; i < 45; i++) {
        t += tb * a[i];
        r[i] = t & 0x7fffff;
        t >>= 23;
    }
    r[45] = (sp_digit)t;
#else
    int64_t tb = b;
    int64_t t[8];
    int i;

    t[0] = tb * a[0]; r[0] = t[0] & 0x7fffff;
    for (i = 0; i < 40; i += 8) {
        t[1] = tb * a[i+1];
        r[i+1] = (sp_digit)(t[0] >> 23) + (t[1] & 0x7fffff);
        t[2] = tb * a[i+2];
        r[i+2] = (sp_digit)(t[1] >> 23) + (t[2] & 0x7fffff);
        t[3] = tb * a[i+3];
        r[i+3] = (sp_digit)(t[2] >> 23) + (t[3] & 0x7fffff);
        t[4] = tb * a[i+4];
        r[i+4] = (sp_digit)(t[3] >> 23) + (t[4] & 0x7fffff);
        t[5] = tb * a[i+5];
        r[i+5] = (sp_digit)(t[4] >> 23) + (t[5] & 0x7fffff);
        t[6] = tb * a[i+6];
        r[i+6] = (sp_digit)(t[5] >> 23) + (t[6] & 0x7fffff);
        t[7] = tb * a[i+7];
        r[i+7] = (sp_digit)(t[6] >> 23) + (t[7] & 0x7fffff);
        t[0] = tb * a[i+8];
        r[i+8] = (sp_digit)(t[7] >> 23) + (t[0] & 0x7fffff);
    }
    t[1] = tb * a[41];
    r[41] = (sp_digit)(t[0] >> 23) + (t[1] & 0x7fffff);
    t[2] = tb * a[42];
    r[42] = (sp_digit)(t[1] >> 23) + (t[2] & 0x7fffff);
    t[3] = tb * a[43];
    r[43] = (sp_digit)(t[2] >> 23) + (t[3] & 0x7fffff);
    t[4] = tb * a[44];
    r[44] = (sp_digit)(t[3] >> 23) + (t[4] & 0x7fffff);
    r[45] =  (sp_digit)(t[4] >> 23);
#endif /* WOLFSSL_SP_SMALL */
}

/* Conditionally add a and b using the mask m.
 * m is -1 to add and 0 when not.
 *
 * r  A single precision number representing conditional add result.
 * a  A single precision number to add with.
 * b  A single precision number to add.
 * m  Mask value to apply.
 */
static void sp_2048_cond_add_45(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit m)
{
#ifdef WOLFSSL_SP_SMALL
    int i;

    for (i = 0; i < 45; i++)
        r[i] = a[i] + (b[i] & m);
#else
    int i;

    for (i = 0; i < 40; i += 8) {
        r[i + 0] = a[i + 0] + (b[i + 0] & m);
        r[i + 1] = a[i + 1] + (b[i + 1] & m);
        r[i + 2] = a[i + 2] + (b[i + 2] & m);
        r[i + 3] = a[i + 3] + (b[i + 3] & m);
        r[i + 4] = a[i + 4] + (b[i + 4] & m);
        r[i + 5] = a[i + 5] + (b[i + 5] & m);
        r[i + 6] = a[i + 6] + (b[i + 6] & m);
        r[i + 7] = a[i + 7] + (b[i + 7] & m);
    }
    r[40] = a[40] + (b[40] & m);
    r[41] = a[41] + (b[41] & m);
    r[42] = a[42] + (b[42] & m);
    r[43] = a[43] + (b[43] & m);
    r[44] = a[44] + (b[44] & m);
#endif /* WOLFSSL_SP_SMALL */
}

#ifdef WOLFSSL_SMALL
/* Add b to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_2048_add_45(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 45; i++)
        r[i] = a[i] + b[i];

    return 0;
}
#endif
SP_NOINLINE static void sp_2048_rshift_45(sp_digit* r, sp_digit* a, byte n)
{
    int i;

#ifdef WOLFSSL_SP_SMALL
    for (i=0; i<44; i++)
        r[i] = ((a[i] >> n) | (a[i + 1] << (23 - n))) & 0x7fffff;
#else
    for (i=0; i<40; i += 8) {
        r[i+0] = ((a[i+0] >> n) | (a[i+1] << (23 - n))) & 0x7fffff;
        r[i+1] = ((a[i+1] >> n) | (a[i+2] << (23 - n))) & 0x7fffff;
        r[i+2] = ((a[i+2] >> n) | (a[i+3] << (23 - n))) & 0x7fffff;
        r[i+3] = ((a[i+3] >> n) | (a[i+4] << (23 - n))) & 0x7fffff;
        r[i+4] = ((a[i+4] >> n) | (a[i+5] << (23 - n))) & 0x7fffff;
        r[i+5] = ((a[i+5] >> n) | (a[i+6] << (23 - n))) & 0x7fffff;
        r[i+6] = ((a[i+6] >> n) | (a[i+7] << (23 - n))) & 0x7fffff;
        r[i+7] = ((a[i+7] >> n) | (a[i+8] << (23 - n))) & 0x7fffff;
    }
    r[40] = ((a[40] >> n) | (a[41] << (23 - n))) & 0x7fffff;
    r[41] = ((a[41] >> n) | (a[42] << (23 - n))) & 0x7fffff;
    r[42] = ((a[42] >> n) | (a[43] << (23 - n))) & 0x7fffff;
    r[43] = ((a[43] >> n) | (a[44] << (23 - n))) & 0x7fffff;
#endif
    r[44] = a[44] >> n;
}

#ifdef WOLFSSL_SP_DIV_32
static WC_INLINE sp_digit sp_2048_div_word_45(sp_digit d1, sp_digit d0,
    sp_digit div)
{
    sp_digit d, r, t;

    /* All 23 bits from d1 and top 8 bits from d0. */
    d = (d1 << 8) | (d0 >> 15);
    r = d / div;
    d -= r * div;
    /* Up to 9 bits in r */
    /* Next 8 bits from d0. */
    r <<= 8;
    d <<= 8;
    d |= (d0 >> 7) & ((1 << 8) - 1);
    t = d / div;
    d -= t * div;
    r += t;
    /* Up to 17 bits in r */
    /* Remaining 7 bits from d0. */
    r <<= 7;
    d <<= 7;
    d |= d0 & ((1 << 7) - 1);
    t = d / div;
    r += t;

    return r;
}
#endif /* WOLFSSL_SP_DIV_32 */

/* Divide d in a and put remainder into r (m*d + r = a)
 * m is not calculated as it is not needed at this time.
 *
 * a  Nmber to be divided.
 * d  Number to divide with.
 * m  Multiplier result.
 * r  Remainder from the division.
 * returns MEMORY_E when unable to allocate memory and MP_OKAY otherwise.
 */
static int sp_2048_div_45(const sp_digit* a, const sp_digit* d, sp_digit* m,
        sp_digit* r)
{
    int i;
#ifndef WOLFSSL_SP_DIV_32
    int64_t d1;
#endif
    sp_digit div, r1;
#if !defined(HAVE_DO178) && (defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK))
    sp_digit* td;
#else
    sp_digit t1d[90 + 1], t2d[45 + 1], sdd[45 + 1];
#endif
    sp_digit* t1;
    sp_digit* t2;
    sp_digit* sd;
    int err = MP_OKAY;

#if !defined(HAVE_DO178) && (defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK))
    td = (sp_digit*)XMALLOC(sizeof(sp_digit) * (4 * 45 + 3), NULL,
                                                       DYNAMIC_TYPE_TMP_BUFFER);
    if (td != NULL) {
        t1 = td;
        t2 = td + 90 + 1;
        sd = t2 + 45 + 1;
    }
    else
        err = MEMORY_E;
#else
    t1 = t1d;
    t2 = t2d;
    sd = sdd;
#endif

    (void)m;

    if (err == MP_OKAY) {
        sp_2048_mul_d_45(sd, d, 1 << 11);
        sp_2048_mul_d_90(t1, a, 1 << 11);
        div = sd[44];
        for (i=45; i>=0; i--) {
            t1[45 + i] += t1[45 + i - 1] >> 23;
            t1[45 + i - 1] &= 0x7fffff;
#ifndef WOLFSSL_SP_DIV_32
            d1 = t1[45 + i];
            d1 <<= 23;
            d1 += t1[45 + i - 1];
            r1 = (sp_digit)(d1 / div);
#else
            r1 = sp_2048_div_word_45(t1[45 + i], t1[45 + i - 1], div);
#endif

            sp_2048_mul_d_45(t2, sd, r1);
            sp_2048_sub_45(&t1[i], &t1[i], t2);
            t1[45 + i] -= t2[45];
            t1[45 + i] += t1[45 + i - 1] >> 23;
            t1[45 + i - 1] &= 0x7fffff;
            r1 = (((-t1[45 + i]) << 23) - t1[45 + i - 1]) / div;
            r1 -= t1[45 + i];
            sp_2048_mul_d_45(t2, sd, r1);
            sp_2048_add_45(&t1[i], &t1[i], t2);
            t1[45 + i] += t1[45 + i - 1] >> 23;
            t1[45 + i - 1] &= 0x7fffff;
        }
        t1[45 - 1] += t1[45 - 2] >> 23;
        t1[45 - 2] &= 0x7fffff;
        r1 = t1[45 - 1] / div;

        sp_2048_mul_d_45(t2, sd, r1);
        sp_2048_sub_45(t1, t1, t2);
        XMEMCPY(r, t1, sizeof(*r) * 2 * 45);
        for (i=0; i<43; i++) {
            r[i+1] += r[i] >> 23;
            r[i] &= 0x7fffff;
        }
        sp_2048_cond_add_45(r, r, sd, 0 - (r[44] < 0));
    }

    sp_2048_norm_45(r);
    sp_2048_rshift_45(r, r, 11);

#if !defined(HAVE_DO178) && (defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK))
    if (td != NULL)
        XFREE(td, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return err;
}

/* Reduce a modulo m into r. (r = a mod m)
 *
 * r  A single precision number that is the reduced result.
 * a  A single precision number that is to be reduced.
 * m  A single precision number that is the modulus to reduce with.
 * returns MEMORY_E when unable to allocate memory and MP_OKAY otherwise.
 */
static int sp_2048_mod_45(sp_digit* r, const sp_digit* a, const sp_digit* m)
{
    return sp_2048_div_45(a, m, NULL, r);
}

/* Modular exponentiate a to the e mod m. (r = a^e mod m)
 *
 * r     A single precision number that is the result of the operation.
 * a     A single precision number being exponentiated.
 * e     A single precision number that is the exponent.
 * bits  The number of bits in the exponent.
 * m     A single precision number that is the modulus.
 * returns 0 on success and MEMORY_E on dynamic memory allocation failure.
 */
static int sp_2048_mod_exp_45(sp_digit* r, const sp_digit* a, const sp_digit* e, int bits,
    const sp_digit* m, int reduceA)
{
#ifdef WOLFSSL_SP_SMALL
    sp_digit* td;
    sp_digit* t[3];
    sp_digit* norm;
    sp_digit mp = 1;
    sp_digit n;
    int i;
    int c, y;
    int err = MP_OKAY;

    td = (sp_digit*)XMALLOC(sizeof(*td) * 3 * 45 * 2, NULL,
                            DYNAMIC_TYPE_TMP_BUFFER);
    if (td == NULL)
        err = MEMORY_E;

    if (err == MP_OKAY) {
        XMEMSET(td, 0, sizeof(*td) * 3 * 45 * 2);

        norm = t[0] = td;
        t[1] = &td[45 * 2];
        t[2] = &td[2 * 45 * 2];

        sp_2048_mont_setup(m, &mp);
        sp_2048_mont_norm_45(norm, m);

        if (reduceA)
            err = sp_2048_mod_45(t[1], a, m);
        else
            XMEMCPY(t[1], a, sizeof(sp_digit) * 45);
    }
    if (err == MP_OKAY) {
        sp_2048_mul_45(t[1], t[1], norm);
        err = sp_2048_mod_45(t[1], t[1], m);
    }

    if (err == MP_OKAY) {
        i = bits / 23;
        c = bits % 23;
        n = e[i--] << (23 - c);
        for (; ; c--) {
            if (c == 0) {
                if (i == -1)
                    break;

                n = e[i--];
                c = 23;
            }

            y = (n >> 22) & 1;
            n <<= 1;

            sp_2048_mont_mul_45(t[y^1], t[0], t[1], m, mp);

            XMEMCPY(t[2], (void*)(((size_t)t[0] & addr_mask[y^1]) +
                                  ((size_t)t[1] & addr_mask[y])),
                    sizeof(*t[2]) * 45 * 2);
            sp_2048_mont_sqr_45(t[2], t[2], m, mp);
            XMEMCPY((void*)(((size_t)t[0] & addr_mask[y^1]) +
                            ((size_t)t[1] & addr_mask[y])), t[2],
                    sizeof(*t[2]) * 45 * 2);
        }

        sp_2048_mont_reduce_45(t[0], m, mp);
        n = sp_2048_cmp_45(t[0], m);
        sp_2048_cond_sub_45(t[0], t[0], m, (n < 0) - 1);
        XMEMCPY(r, t[0], sizeof(*r) * 45 * 2);

    }

    if (td != NULL)
        XFREE(td, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    return err;
#elif defined(WOLFSSL_SP_CACHE_RESISTANT)
#if defined(HAVE_DO178) || !defined(WOLFSSL_SMALL_STACK)
    sp_digit t[3][90];
#else
    sp_digit* td;
    sp_digit* t[3];
#endif
    sp_digit* norm;
    sp_digit mp = 1;
    sp_digit n;
    int i;
    int c, y;
    int err = MP_OKAY;

#if !defined(HAVE_DO178) && defined(WOLFSSL_SMALL_STACK)
    td = (sp_digit*)XMALLOC(sizeof(*td) * 3 * 45 * 2, NULL,
                            DYNAMIC_TYPE_TMP_BUFFER);
    if (td == NULL)
        err = MEMORY_E;

    if (err == MP_OKAY) {
        t[0] = td;
        t[1] = &td[45 * 2];
        t[2] = &td[2 * 45 * 2];
        norm = t[0];
    }
#else
    norm = t[0];
#endif

    if (err == MP_OKAY) {
        sp_2048_mont_setup(m, &mp);
        sp_2048_mont_norm_45(norm, m);

        if (reduceA) {
            err = sp_2048_mod_45(t[1], a, m);
            if (err == MP_OKAY) {
                sp_2048_mul_45(t[1], t[1], norm);
                err = sp_2048_mod_45(t[1], t[1], m);
            }
        }
        else {
            sp_2048_mul_45(t[1], a, norm);
            err = sp_2048_mod_45(t[1], t[1], m);
        }
    }

    if (err == MP_OKAY) {
        i = bits / 23;
        c = bits % 23;
        n = e[i--] << (23 - c);
        for (; ; c--) {
            if (c == 0) {
                if (i == -1)
                    break;

                n = e[i--];
                c = 23;
            }

            y = (n >> 22) & 1;
            n <<= 1;

            sp_2048_mont_mul_45(t[y^1], t[0], t[1], m, mp);

            XMEMCPY(t[2], (void*)(((size_t)t[0] & addr_mask[y^1]) +
                                 ((size_t)t[1] & addr_mask[y])), sizeof(t[2]));
            sp_2048_mont_sqr_45(t[2], t[2], m, mp);
            XMEMCPY((void*)(((size_t)t[0] & addr_mask[y^1]) +
                           ((size_t)t[1] & addr_mask[y])), t[2], sizeof(t[2]));
        }

        sp_2048_mont_reduce_45(t[0], m, mp);
        n = sp_2048_cmp_45(t[0], m);
        sp_2048_cond_sub_45(t[0], t[0], m, (n < 0) - 1);
        XMEMCPY(r, t[0], sizeof(t[0]));
    }

#if !defined(HAVE_DO178) && defined(WOLFSSL_SMALL_STACK)
    if (td != NULL)
        XFREE(td, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return err;
#else
#if defined(HAVE_DO178) || !defined(WOLFSSL_SMALL_STACK)
    sp_digit t[32][90];
#else
    sp_digit* t[32];
    sp_digit* td;
#endif
    sp_digit* norm;
    sp_digit rt[90];
    sp_digit mp = 1;
    sp_digit n;
    int i;
    int c, y;
    int err = MP_OKAY;

#if !defined(HAVE_DO178) && defined(WOLFSSL_SMALL_STACK)
    td = (sp_digit*)XMALLOC(sizeof(sp_digit) * 32 * 90, NULL,
                            DYNAMIC_TYPE_TMP_BUFFER);
    if (td == NULL)
        err = MEMORY_E;

    if (err == MP_OKAY) {
        for (i=0; i<32; i++)
            t[i] = td + i * 90;
        norm = t[0];
    }
#else
    norm = t[0];
#endif

    if (err == MP_OKAY) {
        sp_2048_mont_setup(m, &mp);
        sp_2048_mont_norm_45(norm, m);

        if (reduceA) {
            err = sp_2048_mod_45(t[1], a, m);
            if (err == MP_OKAY) {
                sp_2048_mul_45(t[1], t[1], norm);
                err = sp_2048_mod_45(t[1], t[1], m);
            }
        }
        else {
            sp_2048_mul_45(t[1], a, norm);
            err = sp_2048_mod_45(t[1], t[1], m);
        }
    }

    if (err == MP_OKAY) {
        sp_2048_mont_sqr_45(t[ 2], t[ 1], m, mp);
        sp_2048_mont_mul_45(t[ 3], t[ 2], t[ 1], m, mp);
        sp_2048_mont_sqr_45(t[ 4], t[ 2], m, mp);
        sp_2048_mont_mul_45(t[ 5], t[ 3], t[ 2], m, mp);
        sp_2048_mont_sqr_45(t[ 6], t[ 3], m, mp);
        sp_2048_mont_mul_45(t[ 7], t[ 4], t[ 3], m, mp);
        sp_2048_mont_sqr_45(t[ 8], t[ 4], m, mp);
        sp_2048_mont_mul_45(t[ 9], t[ 5], t[ 4], m, mp);
        sp_2048_mont_sqr_45(t[10], t[ 5], m, mp);
        sp_2048_mont_mul_45(t[11], t[ 6], t[ 5], m, mp);
        sp_2048_mont_sqr_45(t[12], t[ 6], m, mp);
        sp_2048_mont_mul_45(t[13], t[ 7], t[ 6], m, mp);
        sp_2048_mont_sqr_45(t[14], t[ 7], m, mp);
        sp_2048_mont_mul_45(t[15], t[ 8], t[ 7], m, mp);
        sp_2048_mont_sqr_45(t[16], t[ 8], m, mp);
        sp_2048_mont_mul_45(t[17], t[ 9], t[ 8], m, mp);
        sp_2048_mont_sqr_45(t[18], t[ 9], m, mp);
        sp_2048_mont_mul_45(t[19], t[10], t[ 9], m, mp);
        sp_2048_mont_sqr_45(t[20], t[10], m, mp);
        sp_2048_mont_mul_45(t[21], t[11], t[10], m, mp);
        sp_2048_mont_sqr_45(t[22], t[11], m, mp);
        sp_2048_mont_mul_45(t[23], t[12], t[11], m, mp);
        sp_2048_mont_sqr_45(t[24], t[12], m, mp);
        sp_2048_mont_mul_45(t[25], t[13], t[12], m, mp);
        sp_2048_mont_sqr_45(t[26], t[13], m, mp);
        sp_2048_mont_mul_45(t[27], t[14], t[13], m, mp);
        sp_2048_mont_sqr_45(t[28], t[14], m, mp);
        sp_2048_mont_mul_45(t[29], t[15], t[14], m, mp);
        sp_2048_mont_sqr_45(t[30], t[15], m, mp);
        sp_2048_mont_mul_45(t[31], t[16], t[15], m, mp);

        bits = ((bits + 4) / 5) * 5;
        i = ((bits + 22) / 23) - 1;
        c = bits % 23;
        if (c == 0)
            c = 23;
        if (i < 45)
            n = e[i--] << (32 - c);
        else {
            n = 0;
            i--;
        }
        if (c < 5) {
            n |= e[i--] << (9 - c);
            c += 23;
        }
        y = (n >> 27) & 0x1f;
        n <<= 5;
        c -= 5;
        XMEMCPY(rt, t[y], sizeof(rt));
        for (; i>=0 || c>=5; ) {
            if (c < 5) {
                n |= e[i--] << (9 - c);
                c += 23;
            }
            y = (n >> 27) & 0x1f;
            n <<= 5;
            c -= 5;

            sp_2048_mont_sqr_45(rt, rt, m, mp);
            sp_2048_mont_sqr_45(rt, rt, m, mp);
            sp_2048_mont_sqr_45(rt, rt, m, mp);
            sp_2048_mont_sqr_45(rt, rt, m, mp);
            sp_2048_mont_sqr_45(rt, rt, m, mp);

            sp_2048_mont_mul_45(rt, rt, t[y], m, mp);
        }

        sp_2048_mont_reduce_45(rt, m, mp);
        n = sp_2048_cmp_45(rt, m);
        sp_2048_cond_sub_45(rt, rt, m, (n < 0) - 1);
        XMEMCPY(r, rt, sizeof(rt));
    }
#if !defined(HAVE_DO178) && defined(WOLFSSL_SMALL_STACK)
    if (td != NULL)
        XFREE(td, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return err;
#endif
}

#endif /* (WOLFSSL_HAVE_SP_RSA || WOLFSSL_HAVE_SP_DH) && !WOLFSSL_RSA_PUBLIC_ONLY */

/* r = 2^n mod m where n is the number of bits to reduce by.
 * Given m must be 2048 bits, just need to subtract.
 *
 * r  A single precision number.
 * m  A signle precision number.
 */
static void sp_2048_mont_norm_90(sp_digit* r, const sp_digit* m)
{
    /* Set r = 2^n - 1. */
#ifdef WOLFSSL_SP_SMALL
    int i;

    for (i=0; i<89; i++)
        r[i] = 0x7fffff;
#else
    int i;

    for (i = 0; i < 88; i += 8) {
        r[i + 0] = 0x7fffff;
        r[i + 1] = 0x7fffff;
        r[i + 2] = 0x7fffff;
        r[i + 3] = 0x7fffff;
        r[i + 4] = 0x7fffff;
        r[i + 5] = 0x7fffff;
        r[i + 6] = 0x7fffff;
        r[i + 7] = 0x7fffff;
    }
    r[88] = 0x7fffff;
#endif
    r[89] = 0x1l;

    /* r = (2^n - 1) mod n */
    sp_2048_sub_90(r, r, m);

    /* Add one so r = 2^n mod m */
    r[0] += 1;
}

/* Compare a with b in constant time.
 *
 * a  A single precision integer.
 * b  A single precision integer.
 * return -ve, 0 or +ve if a is less than, equal to or greater than b
 * respectively.
 */
static sp_digit sp_2048_cmp_90(const sp_digit* a, const sp_digit* b)
{
    sp_digit r = 0;
#ifdef WOLFSSL_SP_SMALL
    int i;

    for (i=89; i>=0; i--)
        r |= (a[i] - b[i]) & (0 - !r);
#else
    int i;

    r |= (a[89] - b[89]) & (0 - !r);
    r |= (a[88] - b[88]) & (0 - !r);
    for (i = 80; i >= 0; i -= 8) {
        r |= (a[i + 7] - b[i + 7]) & (0 - !r);
        r |= (a[i + 6] - b[i + 6]) & (0 - !r);
        r |= (a[i + 5] - b[i + 5]) & (0 - !r);
        r |= (a[i + 4] - b[i + 4]) & (0 - !r);
        r |= (a[i + 3] - b[i + 3]) & (0 - !r);
        r |= (a[i + 2] - b[i + 2]) & (0 - !r);
        r |= (a[i + 1] - b[i + 1]) & (0 - !r);
        r |= (a[i + 0] - b[i + 0]) & (0 - !r);
    }
#endif /* WOLFSSL_SP_SMALL */

    return r;
}

/* Conditionally subtract b from a using the mask m.
 * m is -1 to subtract and 0 when not.
 *
 * r  A single precision number representing condition subtract result.
 * a  A single precision number to subtract from.
 * b  A single precision number to subtract.
 * m  Mask value to apply.
 */
static void sp_2048_cond_sub_90(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit m)
{
#ifdef WOLFSSL_SP_SMALL
    int i;

    for (i = 0; i < 90; i++)
        r[i] = a[i] - (b[i] & m);
#else
    int i;

    for (i = 0; i < 88; i += 8) {
        r[i + 0] = a[i + 0] - (b[i + 0] & m);
        r[i + 1] = a[i + 1] - (b[i + 1] & m);
        r[i + 2] = a[i + 2] - (b[i + 2] & m);
        r[i + 3] = a[i + 3] - (b[i + 3] & m);
        r[i + 4] = a[i + 4] - (b[i + 4] & m);
        r[i + 5] = a[i + 5] - (b[i + 5] & m);
        r[i + 6] = a[i + 6] - (b[i + 6] & m);
        r[i + 7] = a[i + 7] - (b[i + 7] & m);
    }
    r[88] = a[88] - (b[88] & m);
    r[89] = a[89] - (b[89] & m);
#endif /* WOLFSSL_SP_SMALL */
}

/* Mul a by scalar b and add into r. (r += a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A scalar.
 */
SP_NOINLINE static void sp_2048_mul_add_90(sp_digit* r, const sp_digit* a,
        const sp_digit b)
{
#ifdef WOLFSSL_SP_SMALL
    int64_t tb = b;
    int64_t t = 0;
    int i;

    for (i = 0; i < 90; i++) {
        t += (tb * a[i]) + r[i];
        r[i] = t & 0x7fffff;
        t >>= 23;
    }
    r[90] += t;
#else
    int64_t tb = b;
    int64_t t[8];
    int i;

    t[0] = tb * a[0]; r[0] += t[0] & 0x7fffff;
    for (i = 0; i < 88; i += 8) {
        t[1] = tb * a[i+1];
        r[i+1] += (t[0] >> 23) + (t[1] & 0x7fffff);
        t[2] = tb * a[i+2];
        r[i+2] += (t[1] >> 23) + (t[2] & 0x7fffff);
        t[3] = tb * a[i+3];
        r[i+3] += (t[2] >> 23) + (t[3] & 0x7fffff);
        t[4] = tb * a[i+4];
        r[i+4] += (t[3] >> 23) + (t[4] & 0x7fffff);
        t[5] = tb * a[i+5];
        r[i+5] += (t[4] >> 23) + (t[5] & 0x7fffff);
        t[6] = tb * a[i+6];
        r[i+6] += (t[5] >> 23) + (t[6] & 0x7fffff);
        t[7] = tb * a[i+7];
        r[i+7] += (t[6] >> 23) + (t[7] & 0x7fffff);
        t[0] = tb * a[i+8];
        r[i+8] += (t[7] >> 23) + (t[0] & 0x7fffff);
    }
    t[1] = tb * a[89]; r[89] += (t[0] >> 23) + (t[1] & 0x7fffff);
    r[90] +=  t[1] >> 23;
#endif /* WOLFSSL_SP_SMALL */
}

/* Normalize the values in each word to 23.
 *
 * a  Array of sp_digit to normalize.
 */
static void sp_2048_norm_90(sp_digit* a)
{
#ifdef WOLFSSL_SP_SMALL
    int i;
    for (i = 0; i < 89; i++) {
        a[i+1] += a[i] >> 23;
        a[i] &= 0x7fffff;
    }
#else
    int i;
    for (i = 0; i < 88; i += 8) {
        a[i+1] += a[i+0] >> 23; a[i+0] &= 0x7fffff;
        a[i+2] += a[i+1] >> 23; a[i+1] &= 0x7fffff;
        a[i+3] += a[i+2] >> 23; a[i+2] &= 0x7fffff;
        a[i+4] += a[i+3] >> 23; a[i+3] &= 0x7fffff;
        a[i+5] += a[i+4] >> 23; a[i+4] &= 0x7fffff;
        a[i+6] += a[i+5] >> 23; a[i+5] &= 0x7fffff;
        a[i+7] += a[i+6] >> 23; a[i+6] &= 0x7fffff;
        a[i+8] += a[i+7] >> 23; a[i+7] &= 0x7fffff;
        a[i+9] += a[i+8] >> 23; a[i+8] &= 0x7fffff;
    }
    a[88+1] += a[88] >> 23;
    a[88] &= 0x7fffff;
#endif
}

/* Shift the result in the high 2048 bits down to the bottom.
 *
 * r  A single precision number.
 * a  A single precision number.
 */
static void sp_2048_mont_shift_90(sp_digit* r, const sp_digit* a)
{
#ifdef WOLFSSL_SP_SMALL
    int i;
    int64_t n = a[89] >> 1;
    n += ((int64_t)a[90]) << 22;

    for (i = 0; i < 89; i++) {
        r[i] = n & 0x7fffff;
        n >>= 23;
        n += ((int64_t)a[91 + i]) << 22;
    }
    r[89] = (sp_digit)n;
#else
    int i;
    int64_t n = a[89] >> 1;
    n += ((int64_t)a[90]) << 22;
    for (i = 0; i < 88; i += 8) {
        r[i + 0] = n & 0x7fffff;
        n >>= 23; n += ((int64_t)a[i + 91]) << 22;
        r[i + 1] = n & 0x7fffff;
        n >>= 23; n += ((int64_t)a[i + 92]) << 22;
        r[i + 2] = n & 0x7fffff;
        n >>= 23; n += ((int64_t)a[i + 93]) << 22;
        r[i + 3] = n & 0x7fffff;
        n >>= 23; n += ((int64_t)a[i + 94]) << 22;
        r[i + 4] = n & 0x7fffff;
        n >>= 23; n += ((int64_t)a[i + 95]) << 22;
        r[i + 5] = n & 0x7fffff;
        n >>= 23; n += ((int64_t)a[i + 96]) << 22;
        r[i + 6] = n & 0x7fffff;
        n >>= 23; n += ((int64_t)a[i + 97]) << 22;
        r[i + 7] = n & 0x7fffff;
        n >>= 23; n += ((int64_t)a[i + 98]) << 22;
    }
    r[88] = n & 0x7fffff; n >>= 23; n += ((int64_t)a[179]) << 22;
    r[89] = (sp_digit)n;
#endif /* WOLFSSL_SP_SMALL */
    XMEMSET(&r[90], 0, sizeof(*r) * 90);
}

/* Reduce the number back to 2048 bits using Montgomery reduction.
 *
 * a   A single precision number to reduce in place.
 * m   The single precision number representing the modulus.
 * mp  The digit representing the negative inverse of m mod 2^n.
 */
static void sp_2048_mont_reduce_90(sp_digit* a, const sp_digit* m, sp_digit mp)
{
    int i;
    sp_digit mu;

#ifdef WOLFSSL_SP_DH
    if (mp != 1) {
        for (i=0; i<89; i++) {
            mu = (a[i] * mp) & 0x7fffff;
            sp_2048_mul_add_90(a+i, m, mu);
            a[i+1] += a[i] >> 23;
        }
        mu = (a[i] * mp) & 0x1l;
        sp_2048_mul_add_90(a+i, m, mu);
        a[i+1] += a[i] >> 23;
        a[i] &= 0x7fffff;
    }
    else {
        for (i=0; i<89; i++) {
            mu = a[i] & 0x7fffff;
            sp_2048_mul_add_90(a+i, m, mu);
            a[i+1] += a[i] >> 23;
        }
        mu = a[i] & 0x1l;
        sp_2048_mul_add_90(a+i, m, mu);
        a[i+1] += a[i] >> 23;
        a[i] &= 0x7fffff;
    }
#else
    for (i=0; i<89; i++) {
        mu = (a[i] * mp) & 0x7fffff;
        sp_2048_mul_add_90(a+i, m, mu);
        a[i+1] += a[i] >> 23;
    }
    mu = (a[i] * mp) & 0x1l;
    sp_2048_mul_add_90(a+i, m, mu);
    a[i+1] += a[i] >> 23;
    a[i] &= 0x7fffff;
#endif

    sp_2048_mont_shift_90(a, a);
    sp_2048_cond_sub_90(a, a, m, 0 - ((a[89] >> 1) > 0));
    sp_2048_norm_90(a);
}

/* Multiply two Montogmery form numbers mod the modulus (prime).
 * (r = a * b mod m)
 *
 * r   Result of multiplication.
 * a   First number to multiply in Montogmery form.
 * b   Second number to multiply in Montogmery form.
 * m   Modulus (prime).
 * mp  Montogmery mulitplier.
 */
static void sp_2048_mont_mul_90(sp_digit* r, const sp_digit* a, const sp_digit* b,
        const sp_digit* m, sp_digit mp)
{
    sp_2048_mul_90(r, a, b);
    sp_2048_mont_reduce_90(r, m, mp);
}

/* Square the Montgomery form number. (r = a * a mod m)
 *
 * r   Result of squaring.
 * a   Number to square in Montogmery form.
 * m   Modulus (prime).
 * mp  Montogmery mulitplier.
 */
static void sp_2048_mont_sqr_90(sp_digit* r, const sp_digit* a, const sp_digit* m,
        sp_digit mp)
{
    sp_2048_sqr_90(r, a);
    sp_2048_mont_reduce_90(r, m, mp);
}

/* Multiply a by scalar b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A scalar.
 */
SP_NOINLINE static void sp_2048_mul_d_180(sp_digit* r, const sp_digit* a,
    sp_digit b)
{
#ifdef WOLFSSL_SP_SMALL
    int64_t tb = b;
    int64_t t = 0;
    int i;

    for (i = 0; i < 180; i++) {
        t += tb * a[i];
        r[i] = t & 0x7fffff;
        t >>= 23;
    }
    r[180] = (sp_digit)t;
#else
    int64_t tb = b;
    int64_t t[8];
    int i;

    t[0] = tb * a[0]; r[0] = t[0] & 0x7fffff;
    for (i = 0; i < 176; i += 8) {
        t[1] = tb * a[i+1];
        r[i+1] = (sp_digit)(t[0] >> 23) + (t[1] & 0x7fffff);
        t[2] = tb * a[i+2];
        r[i+2] = (sp_digit)(t[1] >> 23) + (t[2] & 0x7fffff);
        t[3] = tb * a[i+3];
        r[i+3] = (sp_digit)(t[2] >> 23) + (t[3] & 0x7fffff);
        t[4] = tb * a[i+4];
        r[i+4] = (sp_digit)(t[3] >> 23) + (t[4] & 0x7fffff);
        t[5] = tb * a[i+5];
        r[i+5] = (sp_digit)(t[4] >> 23) + (t[5] & 0x7fffff);
        t[6] = tb * a[i+6];
        r[i+6] = (sp_digit)(t[5] >> 23) + (t[6] & 0x7fffff);
        t[7] = tb * a[i+7];
        r[i+7] = (sp_digit)(t[6] >> 23) + (t[7] & 0x7fffff);
        t[0] = tb * a[i+8];
        r[i+8] = (sp_digit)(t[7] >> 23) + (t[0] & 0x7fffff);
    }
    t[1] = tb * a[177];
    r[177] = (sp_digit)(t[0] >> 23) + (t[1] & 0x7fffff);
    t[2] = tb * a[178];
    r[178] = (sp_digit)(t[1] >> 23) + (t[2] & 0x7fffff);
    t[3] = tb * a[179];
    r[179] = (sp_digit)(t[2] >> 23) + (t[3] & 0x7fffff);
    r[180] =  (sp_digit)(t[3] >> 23);
#endif /* WOLFSSL_SP_SMALL */
}

/* Conditionally add a and b using the mask m.
 * m is -1 to add and 0 when not.
 *
 * r  A single precision number representing conditional add result.
 * a  A single precision number to add with.
 * b  A single precision number to add.
 * m  Mask value to apply.
 */
static void sp_2048_cond_add_90(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit m)
{
#ifdef WOLFSSL_SP_SMALL
    int i;

    for (i = 0; i < 90; i++)
        r[i] = a[i] + (b[i] & m);
#else
    int i;

    for (i = 0; i < 88; i += 8) {
        r[i + 0] = a[i + 0] + (b[i + 0] & m);
        r[i + 1] = a[i + 1] + (b[i + 1] & m);
        r[i + 2] = a[i + 2] + (b[i + 2] & m);
        r[i + 3] = a[i + 3] + (b[i + 3] & m);
        r[i + 4] = a[i + 4] + (b[i + 4] & m);
        r[i + 5] = a[i + 5] + (b[i + 5] & m);
        r[i + 6] = a[i + 6] + (b[i + 6] & m);
        r[i + 7] = a[i + 7] + (b[i + 7] & m);
    }
    r[88] = a[88] + (b[88] & m);
    r[89] = a[89] + (b[89] & m);
#endif /* WOLFSSL_SP_SMALL */
}

#ifdef WOLFSSL_SMALL
/* Sub b from a into r. (r = a - b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_2048_sub_90(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 90; i++)
        r[i] = a[i] - b[i];

    return 0;
}

#endif
#ifdef WOLFSSL_SMALL
/* Add b to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_2048_add_90(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 90; i++)
        r[i] = a[i] + b[i];

    return 0;
}
#endif
SP_NOINLINE static void sp_2048_rshift_90(sp_digit* r, sp_digit* a, byte n)
{
    int i;

#ifdef WOLFSSL_SP_SMALL
    for (i=0; i<89; i++)
        r[i] = ((a[i] >> n) | (a[i + 1] << (23 - n))) & 0x7fffff;
#else
    for (i=0; i<88; i += 8) {
        r[i+0] = ((a[i+0] >> n) | (a[i+1] << (23 - n))) & 0x7fffff;
        r[i+1] = ((a[i+1] >> n) | (a[i+2] << (23 - n))) & 0x7fffff;
        r[i+2] = ((a[i+2] >> n) | (a[i+3] << (23 - n))) & 0x7fffff;
        r[i+3] = ((a[i+3] >> n) | (a[i+4] << (23 - n))) & 0x7fffff;
        r[i+4] = ((a[i+4] >> n) | (a[i+5] << (23 - n))) & 0x7fffff;
        r[i+5] = ((a[i+5] >> n) | (a[i+6] << (23 - n))) & 0x7fffff;
        r[i+6] = ((a[i+6] >> n) | (a[i+7] << (23 - n))) & 0x7fffff;
        r[i+7] = ((a[i+7] >> n) | (a[i+8] << (23 - n))) & 0x7fffff;
    }
    r[88] = ((a[88] >> n) | (a[89] << (23 - n))) & 0x7fffff;
#endif
    r[89] = a[89] >> n;
}

#ifdef WOLFSSL_SP_DIV_32
static WC_INLINE sp_digit sp_2048_div_word_90(sp_digit d1, sp_digit d0,
    sp_digit div)
{
    sp_digit d, r, t;

    /* All 23 bits from d1 and top 8 bits from d0. */
    d = (d1 << 8) | (d0 >> 15);
    r = d / div;
    d -= r * div;
    /* Up to 9 bits in r */
    /* Next 8 bits from d0. */
    r <<= 8;
    d <<= 8;
    d |= (d0 >> 7) & ((1 << 8) - 1);
    t = d / div;
    d -= t * div;
    r += t;
    /* Up to 17 bits in r */
    /* Remaining 7 bits from d0. */
    r <<= 7;
    d <<= 7;
    d |= d0 & ((1 << 7) - 1);
    t = d / div;
    r += t;

    return r;
}
#endif /* WOLFSSL_SP_DIV_32 */

/* Divide d in a and put remainder into r (m*d + r = a)
 * m is not calculated as it is not needed at this time.
 *
 * a  Nmber to be divided.
 * d  Number to divide with.
 * m  Multiplier result.
 * r  Remainder from the division.
 * returns MEMORY_E when unable to allocate memory and MP_OKAY otherwise.
 */
static int sp_2048_div_90(const sp_digit* a, const sp_digit* d, sp_digit* m,
        sp_digit* r)
{
    int i;
#ifndef WOLFSSL_SP_DIV_32
    int64_t d1;
#endif
    sp_digit div, r1;
#if !defined(HAVE_DO178) && (defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK))
    sp_digit* td;
#else
    sp_digit t1d[180 + 1], t2d[90 + 1], sdd[90 + 1];
#endif
    sp_digit* t1;
    sp_digit* t2;
    sp_digit* sd;
    int err = MP_OKAY;

#if !defined(HAVE_DO178) && (defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK))
    td = (sp_digit*)XMALLOC(sizeof(sp_digit) * (4 * 90 + 3), NULL,
                                                       DYNAMIC_TYPE_TMP_BUFFER);
    if (td != NULL) {
        t1 = td;
        t2 = td + 180 + 1;
        sd = t2 + 90 + 1;
    }
    else
        err = MEMORY_E;
#else
    t1 = t1d;
    t2 = t2d;
    sd = sdd;
#endif

    (void)m;

    if (err == MP_OKAY) {
        sp_2048_mul_d_90(sd, d, 1 << 22);
        sp_2048_mul_d_180(t1, a, 1 << 22);
        div = sd[89];
        for (i=90; i>=0; i--) {
            t1[90 + i] += t1[90 + i - 1] >> 23;
            t1[90 + i - 1] &= 0x7fffff;
#ifndef WOLFSSL_SP_DIV_32
            d1 = t1[90 + i];
            d1 <<= 23;
            d1 += t1[90 + i - 1];
            r1 = (sp_digit)(d1 / div);
#else
            r1 = sp_2048_div_word_90(t1[90 + i], t1[90 + i - 1], div);
#endif

            sp_2048_mul_d_90(t2, sd, r1);
            sp_2048_sub_90(&t1[i], &t1[i], t2);
            t1[90 + i] -= t2[90];
            t1[90 + i] += t1[90 + i - 1] >> 23;
            t1[90 + i - 1] &= 0x7fffff;
            r1 = (((-t1[90 + i]) << 23) - t1[90 + i - 1]) / div;
            r1 -= t1[90 + i];
            sp_2048_mul_d_90(t2, sd, r1);
            sp_2048_add_90(&t1[i], &t1[i], t2);
            t1[90 + i] += t1[90 + i - 1] >> 23;
            t1[90 + i - 1] &= 0x7fffff;
        }
        t1[90 - 1] += t1[90 - 2] >> 23;
        t1[90 - 2] &= 0x7fffff;
        r1 = t1[90 - 1] / div;

        sp_2048_mul_d_90(t2, sd, r1);
        sp_2048_sub_90(t1, t1, t2);
        XMEMCPY(r, t1, sizeof(*r) * 2 * 90);
        for (i=0; i<88; i++) {
            r[i+1] += r[i] >> 23;
            r[i] &= 0x7fffff;
        }
        sp_2048_cond_add_90(r, r, sd, 0 - (r[89] < 0));
    }

    sp_2048_norm_90(r);
    sp_2048_rshift_90(r, r, 22);

#if !defined(HAVE_DO178) && (defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK))
    if (td != NULL)
        XFREE(td, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return err;
}

/* Reduce a modulo m into r. (r = a mod m)
 *
 * r  A single precision number that is the reduced result.
 * a  A single precision number that is to be reduced.
 * m  A single precision number that is the modulus to reduce with.
 * returns MEMORY_E when unable to allocate memory and MP_OKAY otherwise.
 */
static int sp_2048_mod_90(sp_digit* r, const sp_digit* a, const sp_digit* m)
{
    return sp_2048_div_90(a, m, NULL, r);
}

#if (defined(WOLFSSL_HAVE_SP_RSA) && !defined(WOLFSSL_RSA_PUBLIC_ONLY)) || \
                                                     defined(WOLFSSL_HAVE_SP_DH)
/* Modular exponentiate a to the e mod m. (r = a^e mod m)
 *
 * r     A single precision number that is the result of the operation.
 * a     A single precision number being exponentiated.
 * e     A single precision number that is the exponent.
 * bits  The number of bits in the exponent.
 * m     A single precision number that is the modulus.
 * returns 0 on success and MEMORY_E on dynamic memory allocation failure.
 */
static int sp_2048_mod_exp_90(sp_digit* r, const sp_digit* a, const sp_digit* e, int bits,
    const sp_digit* m, int reduceA)
{
#ifdef WOLFSSL_SP_SMALL
    sp_digit* td;
    sp_digit* t[3];
    sp_digit* norm;
    sp_digit mp = 1;
    sp_digit n;
    int i;
    int c, y;
    int err = MP_OKAY;

    td = (sp_digit*)XMALLOC(sizeof(*td) * 3 * 90 * 2, NULL,
                            DYNAMIC_TYPE_TMP_BUFFER);
    if (td == NULL)
        err = MEMORY_E;

    if (err == MP_OKAY) {
        XMEMSET(td, 0, sizeof(*td) * 3 * 90 * 2);

        norm = t[0] = td;
        t[1] = &td[90 * 2];
        t[2] = &td[2 * 90 * 2];

        sp_2048_mont_setup(m, &mp);
        sp_2048_mont_norm_90(norm, m);

        if (reduceA)
            err = sp_2048_mod_90(t[1], a, m);
        else
            XMEMCPY(t[1], a, sizeof(sp_digit) * 90);
    }
    if (err == MP_OKAY) {
        sp_2048_mul_90(t[1], t[1], norm);
        err = sp_2048_mod_90(t[1], t[1], m);
    }

    if (err == MP_OKAY) {
        i = bits / 23;
        c = bits % 23;
        n = e[i--] << (23 - c);
        for (; ; c--) {
            if (c == 0) {
                if (i == -1)
                    break;

                n = e[i--];
                c = 23;
            }

            y = (n >> 22) & 1;
            n <<= 1;

            sp_2048_mont_mul_90(t[y^1], t[0], t[1], m, mp);

            XMEMCPY(t[2], (void*)(((size_t)t[0] & addr_mask[y^1]) +
                                  ((size_t)t[1] & addr_mask[y])),
                    sizeof(*t[2]) * 90 * 2);
            sp_2048_mont_sqr_90(t[2], t[2], m, mp);
            XMEMCPY((void*)(((size_t)t[0] & addr_mask[y^1]) +
                            ((size_t)t[1] & addr_mask[y])), t[2],
                    sizeof(*t[2]) * 90 * 2);
        }

        sp_2048_mont_reduce_90(t[0], m, mp);
        n = sp_2048_cmp_90(t[0], m);
        sp_2048_cond_sub_90(t[0], t[0], m, (n < 0) - 1);
        XMEMCPY(r, t[0], sizeof(*r) * 90 * 2);

    }

    if (td != NULL)
        XFREE(td, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    return err;
#elif defined(WOLFSSL_SP_CACHE_RESISTANT)
#if defined(HAVE_DO178) || !defined(WOLFSSL_SMALL_STACK)
    sp_digit t[3][180];
#else
    sp_digit* td;
    sp_digit* t[3];
#endif
    sp_digit* norm;
    sp_digit mp = 1;
    sp_digit n;
    int i;
    int c, y;
    int err = MP_OKAY;

#if !defined(HAVE_DO178) && defined(WOLFSSL_SMALL_STACK)
    td = (sp_digit*)XMALLOC(sizeof(*td) * 3 * 90 * 2, NULL,
                            DYNAMIC_TYPE_TMP_BUFFER);
    if (td == NULL)
        err = MEMORY_E;

    if (err == MP_OKAY) {
        t[0] = td;
        t[1] = &td[90 * 2];
        t[2] = &td[2 * 90 * 2];
        norm = t[0];
    }
#else
    norm = t[0];
#endif

    if (err == MP_OKAY) {
        sp_2048_mont_setup(m, &mp);
        sp_2048_mont_norm_90(norm, m);

        if (reduceA) {
            err = sp_2048_mod_90(t[1], a, m);
            if (err == MP_OKAY) {
                sp_2048_mul_90(t[1], t[1], norm);
                err = sp_2048_mod_90(t[1], t[1], m);
            }
        }
        else {
            sp_2048_mul_90(t[1], a, norm);
            err = sp_2048_mod_90(t[1], t[1], m);
        }
    }

    if (err == MP_OKAY) {
        i = bits / 23;
        c = bits % 23;
        n = e[i--] << (23 - c);
        for (; ; c--) {
            if (c == 0) {
                if (i == -1)
                    break;

                n = e[i--];
                c = 23;
            }

            y = (n >> 22) & 1;
            n <<= 1;

            sp_2048_mont_mul_90(t[y^1], t[0], t[1], m, mp);

            XMEMCPY(t[2], (void*)(((size_t)t[0] & addr_mask[y^1]) +
                                 ((size_t)t[1] & addr_mask[y])), sizeof(t[2]));
            sp_2048_mont_sqr_90(t[2], t[2], m, mp);
            XMEMCPY((void*)(((size_t)t[0] & addr_mask[y^1]) +
                           ((size_t)t[1] & addr_mask[y])), t[2], sizeof(t[2]));
        }

        sp_2048_mont_reduce_90(t[0], m, mp);
        n = sp_2048_cmp_90(t[0], m);
        sp_2048_cond_sub_90(t[0], t[0], m, (n < 0) - 1);
        XMEMCPY(r, t[0], sizeof(t[0]));
    }

#if !defined(HAVE_DO178) && defined(WOLFSSL_SMALL_STACK)
    if (td != NULL)
        XFREE(td, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return err;
#else
#if defined(HAVE_DO178) || !defined(WOLFSSL_SMALL_STACK)
    sp_digit t[32][180];
#else
    sp_digit* t[32];
    sp_digit* td;
#endif
    sp_digit* norm;
    sp_digit rt[180];
    sp_digit mp = 1;
    sp_digit n;
    int i;
    int c, y;
    int err = MP_OKAY;

#if !defined(HAVE_DO178) && defined(WOLFSSL_SMALL_STACK)
    td = (sp_digit*)XMALLOC(sizeof(sp_digit) * 32 * 180, NULL,
                            DYNAMIC_TYPE_TMP_BUFFER);
    if (td == NULL)
        err = MEMORY_E;

    if (err == MP_OKAY) {
        for (i=0; i<32; i++)
            t[i] = td + i * 180;
        norm = t[0];
    }
#else
    norm = t[0];
#endif

    if (err == MP_OKAY) {
        sp_2048_mont_setup(m, &mp);
        sp_2048_mont_norm_90(norm, m);

        if (reduceA) {
            err = sp_2048_mod_90(t[1], a, m);
            if (err == MP_OKAY) {
                sp_2048_mul_90(t[1], t[1], norm);
                err = sp_2048_mod_90(t[1], t[1], m);
            }
        }
        else {
            sp_2048_mul_90(t[1], a, norm);
            err = sp_2048_mod_90(t[1], t[1], m);
        }
    }

    if (err == MP_OKAY) {
        sp_2048_mont_sqr_90(t[ 2], t[ 1], m, mp);
        sp_2048_mont_mul_90(t[ 3], t[ 2], t[ 1], m, mp);
        sp_2048_mont_sqr_90(t[ 4], t[ 2], m, mp);
        sp_2048_mont_mul_90(t[ 5], t[ 3], t[ 2], m, mp);
        sp_2048_mont_sqr_90(t[ 6], t[ 3], m, mp);
        sp_2048_mont_mul_90(t[ 7], t[ 4], t[ 3], m, mp);
        sp_2048_mont_sqr_90(t[ 8], t[ 4], m, mp);
        sp_2048_mont_mul_90(t[ 9], t[ 5], t[ 4], m, mp);
        sp_2048_mont_sqr_90(t[10], t[ 5], m, mp);
        sp_2048_mont_mul_90(t[11], t[ 6], t[ 5], m, mp);
        sp_2048_mont_sqr_90(t[12], t[ 6], m, mp);
        sp_2048_mont_mul_90(t[13], t[ 7], t[ 6], m, mp);
        sp_2048_mont_sqr_90(t[14], t[ 7], m, mp);
        sp_2048_mont_mul_90(t[15], t[ 8], t[ 7], m, mp);
        sp_2048_mont_sqr_90(t[16], t[ 8], m, mp);
        sp_2048_mont_mul_90(t[17], t[ 9], t[ 8], m, mp);
        sp_2048_mont_sqr_90(t[18], t[ 9], m, mp);
        sp_2048_mont_mul_90(t[19], t[10], t[ 9], m, mp);
        sp_2048_mont_sqr_90(t[20], t[10], m, mp);
        sp_2048_mont_mul_90(t[21], t[11], t[10], m, mp);
        sp_2048_mont_sqr_90(t[22], t[11], m, mp);
        sp_2048_mont_mul_90(t[23], t[12], t[11], m, mp);
        sp_2048_mont_sqr_90(t[24], t[12], m, mp);
        sp_2048_mont_mul_90(t[25], t[13], t[12], m, mp);
        sp_2048_mont_sqr_90(t[26], t[13], m, mp);
        sp_2048_mont_mul_90(t[27], t[14], t[13], m, mp);
        sp_2048_mont_sqr_90(t[28], t[14], m, mp);
        sp_2048_mont_mul_90(t[29], t[15], t[14], m, mp);
        sp_2048_mont_sqr_90(t[30], t[15], m, mp);
        sp_2048_mont_mul_90(t[31], t[16], t[15], m, mp);

        bits = ((bits + 4) / 5) * 5;
        i = ((bits + 22) / 23) - 1;
        c = bits % 23;
        if (c == 0)
            c = 23;
        if (i < 90)
            n = e[i--] << (32 - c);
        else {
            n = 0;
            i--;
        }
        if (c < 5) {
            n |= e[i--] << (9 - c);
            c += 23;
        }
        y = (n >> 27) & 0x1f;
        n <<= 5;
        c -= 5;
        XMEMCPY(rt, t[y], sizeof(rt));
        for (; i>=0 || c>=5; ) {
            if (c < 5) {
                n |= e[i--] << (9 - c);
                c += 23;
            }
            y = (n >> 27) & 0x1f;
            n <<= 5;
            c -= 5;

            sp_2048_mont_sqr_90(rt, rt, m, mp);
            sp_2048_mont_sqr_90(rt, rt, m, mp);
            sp_2048_mont_sqr_90(rt, rt, m, mp);
            sp_2048_mont_sqr_90(rt, rt, m, mp);
            sp_2048_mont_sqr_90(rt, rt, m, mp);

            sp_2048_mont_mul_90(rt, rt, t[y], m, mp);
        }

        sp_2048_mont_reduce_90(rt, m, mp);
        n = sp_2048_cmp_90(rt, m);
        sp_2048_cond_sub_90(rt, rt, m, (n < 0) - 1);
        XMEMCPY(r, rt, sizeof(rt));
    }
#if !defined(HAVE_DO178) && defined(WOLFSSL_SMALL_STACK)
    if (td != NULL)
        XFREE(td, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return err;
#endif
}
#endif /* (WOLFSSL_HAVE_SP_RSA && !WOLFSSL_RSA_PUBLIC_ONLY) || */
       /* WOLFSSL_HAVE_SP_DH */

#if defined(WOLFSSL_HAVE_SP_RSA) && !defined(SP_RSA_PRIVATE_EXP_D) && \
           !defined(RSA_LOW_MEM) && !defined(WOLFSSL_RSA_PUBLIC_ONLY)
/* AND m into each word of a and store in r.
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * m  Mask to AND against each digit.
 */
static void sp_2048_mask_45(sp_digit* r, const sp_digit* a, sp_digit m)
{
#ifdef WOLFSSL_SP_SMALL
    int i;

    for (i=0; i<45; i++)
        r[i] = a[i] & m;
#else
    int i;

    for (i = 0; i < 40; i += 8) {
        r[i+0] = a[i+0] & m;
        r[i+1] = a[i+1] & m;
        r[i+2] = a[i+2] & m;
        r[i+3] = a[i+3] & m;
        r[i+4] = a[i+4] & m;
        r[i+5] = a[i+5] & m;
        r[i+6] = a[i+6] & m;
        r[i+7] = a[i+7] & m;
    }
    r[40] = a[40] & m;
    r[41] = a[41] & m;
    r[42] = a[42] & m;
    r[43] = a[43] & m;
    r[44] = a[44] & m;
#endif
}

#endif
#ifdef WOLFSSL_HAVE_SP_RSA
/* RSA public key operation.
 *
 * in      Array of bytes representing the number to exponentiate, base.
 * inLen   Number of bytes in base.
 * em      Public exponent.
 * mm      Modulus.
 * out     Buffer to hold big-endian bytes of exponentiation result.
 *         Must be at least 256 bytes long.
 * outLen  Number of bytes in result.
 * returns 0 on success, MP_TO_E when the outLen is too small, MP_READ_E when
 * an array is too long and MEMORY_E when dynamic memory allocation fails.
 */
int sp_RsaPublic_2048(const byte* in, word32 inLen, mp_int* em, mp_int* mm,
    byte* out, word32* outLen)
{
#ifdef WOLFSSL_SP_SMALL
    sp_digit* d = NULL;
    sp_digit* a;
    sp_digit* m;
    sp_digit* r;
    sp_digit* norm;
    sp_digit e[1];
    sp_digit mp;
    int i;
    int err = MP_OKAY;

    if (*outLen < 256)
        err = MP_TO_E;
    if (err == MP_OKAY && (mp_count_bits(em) > 23 || inLen > 256 ||
                                                     mp_count_bits(mm) != 2048))
        err = MP_READ_E;

    if (err == MP_OKAY) {
        d = (sp_digit*)XMALLOC(sizeof(sp_digit) * 90 * 5, NULL,
                                                              DYNAMIC_TYPE_RSA);
        if (d == NULL)
            err = MEMORY_E;
    }

    if (err == MP_OKAY) {
        a = d;
        r = a + 90 * 2;
        m = r + 90 * 2;
        norm = r;

        sp_2048_from_bin(a, 90, in, inLen);
#if DIGIT_BIT >= 23
        e[0] = (sp_digit)em->dp[0];
#else
        e[0] = (sp_digit)em->dp[0];
        if (em->used > 1)
            e[0] |= ((sp_digit)em->dp[1]) << DIGIT_BIT;
#endif
        if (e[0] == 0)
            err = MP_EXPTMOD_E;
    }

    if (err == MP_OKAY) {
        sp_2048_from_mp(m, 90, mm);

        sp_2048_mont_setup(m, &mp);
        sp_2048_mont_norm_90(norm, m);
    }
    if (err == MP_OKAY) {
        sp_2048_mul_90(a, a, norm);
        err = sp_2048_mod_90(a, a, m);
    }
    if (err == MP_OKAY) {
        for (i=22; i>=0; i--)
            if (e[0] >> i)
                break;

        XMEMCPY(r, a, sizeof(sp_digit) * 90 * 2);
        for (i--; i>=0; i--) {
            sp_2048_mont_sqr_90(r, r, m, mp);

            if (((e[0] >> i) & 1) == 1)
                sp_2048_mont_mul_90(r, r, a, m, mp);
        }
        sp_2048_mont_reduce_90(r, m, mp);
        mp = sp_2048_cmp_90(r, m);
        sp_2048_cond_sub_90(r, r, m, (mp < 0) - 1);

        sp_2048_to_bin(r, out);
        *outLen = 256;
    }

    if (d != NULL)
        XFREE(d, NULL, DYNAMIC_TYPE_RSA);

    return err;
#else
#if defined(HAVE_DO178) || (!defined(WOLFSSL_SP_SMALL) && !defined(WOLFSSL_SMALL_STACK))
    sp_digit ad[180], md[90], rd[180];
#else
    sp_digit* d = NULL;
#endif
    sp_digit* a;
    sp_digit* m;
    sp_digit* r;
    sp_digit e[1];
    int err = MP_OKAY;

    if (*outLen < 256)
        err = MP_TO_E;
    if (err == MP_OKAY && (mp_count_bits(em) > 23 || inLen > 256 ||
                                                     mp_count_bits(mm) != 2048))
        err = MP_READ_E;

#if !defined(HAVE_DO178) && (defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK))
    if (err == MP_OKAY) {
        d = (sp_digit*)XMALLOC(sizeof(sp_digit) * 90 * 5, NULL,
                                                              DYNAMIC_TYPE_RSA);
        if (d == NULL)
            err = MEMORY_E;
    }

    if (err == MP_OKAY) {
        a = d;
        r = a + 90 * 2;
        m = r + 90 * 2;
    }
#else
    a = ad;
    m = md;
    r = rd;
#endif

    if (err == MP_OKAY) {
        sp_2048_from_bin(a, 90, in, inLen);
#if DIGIT_BIT >= 23
        e[0] = (sp_digit)em->dp[0];
#else
        e[0] = (sp_digit)em->dp[0];
        if (em->used > 1)
            e[0] |= ((sp_digit)em->dp[1]) << DIGIT_BIT;
#endif
        if (e[0] == 0)
            err = MP_EXPTMOD_E;
    }
    if (err == MP_OKAY) {
        sp_2048_from_mp(m, 90, mm);

        if (e[0] == 0x3) {
            if (err == MP_OKAY) {
                sp_2048_sqr_90(r, a);
                err = sp_2048_mod_90(r, r, m);
            }
            if (err == MP_OKAY) {
                sp_2048_mul_90(r, a, r);
                err = sp_2048_mod_90(r, r, m);
            }
        }
        else {
            sp_digit* norm = r;
            int i;
            sp_digit mp;

            sp_2048_mont_setup(m, &mp);
            sp_2048_mont_norm_90(norm, m);

            if (err == MP_OKAY) {
                sp_2048_mul_90(a, a, norm);
                err = sp_2048_mod_90(a, a, m);
            }

            if (err == MP_OKAY) {
                for (i=22; i>=0; i--)
                    if (e[0] >> i)
                        break;

                XMEMCPY(r, a, sizeof(sp_digit) * 180);
                for (i--; i>=0; i--) {
                    sp_2048_mont_sqr_90(r, r, m, mp);

                    if (((e[0] >> i) & 1) == 1)
                        sp_2048_mont_mul_90(r, r, a, m, mp);
                }
                sp_2048_mont_reduce_90(r, m, mp);
                mp = sp_2048_cmp_90(r, m);
                sp_2048_cond_sub_90(r, r, m, (mp < 0) - 1);
            }
        }
    }

    if (err == MP_OKAY) {
        sp_2048_to_bin(r, out);
        *outLen = 256;
    }

#if !defined(HAVE_DO178) && (defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK))
    if (d != NULL)
        XFREE(d, NULL, DYNAMIC_TYPE_RSA);
#endif

    return err;
#endif /* WOLFSSL_SP_SMALL */
}

#ifndef WOLFSSL_RSA_PUBLIC_ONLY
/* RSA private key operation.
 *
 * in      Array of bytes representing the number to exponentiate, base.
 * inLen   Number of bytes in base.
 * dm      Private exponent.
 * pm      First prime.
 * qm      Second prime.
 * dpm     First prime's CRT exponent.
 * dqm     Second prime's CRT exponent.
 * qim     Inverse of second prime mod p.
 * mm      Modulus.
 * out     Buffer to hold big-endian bytes of exponentiation result.
 *         Must be at least 256 bytes long.
 * outLen  Number of bytes in result.
 * returns 0 on success, MP_TO_E when the outLen is too small, MP_READ_E when
 * an array is too long and MEMORY_E when dynamic memory allocation fails.
 */
int sp_RsaPrivate_2048(const byte* in, word32 inLen, mp_int* dm,
    mp_int* pm, mp_int* qm, mp_int* dpm, mp_int* dqm, mp_int* qim, mp_int* mm,
    byte* out, word32* outLen)
{
#if defined(SP_RSA_PRIVATE_EXP_D) || defined(RSA_LOW_MEM)
#if !defined(HAVE_DO178) && \
    (defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK))
    sp_digit* a;
    sp_digit* d = NULL;
    sp_digit* m;
    sp_digit* r;
    int err = MP_OKAY;

    (void)pm;
    (void)qm;
    (void)dpm;
    (void)dqm;
    (void)qim;

    if (*outLen < 256)
        err = MP_TO_E;
    if (err == MP_OKAY && (mp_count_bits(dm) > 2048 || inLen > 256 ||
                                                     mp_count_bits(mm) != 2048))
        err = MP_READ_E;

    if (err == MP_OKAY) {
        d = (sp_digit*)XMALLOC(sizeof(sp_digit) * 90 * 4, NULL,
                                                              DYNAMIC_TYPE_RSA);
        if (d == NULL)
            err = MEMORY_E;
    }
    if (err == MP_OKAY) {
        a = d + 90;
        m = a + 90;
        r = a;

        sp_2048_from_bin(a, 90, in, inLen);
        sp_2048_from_mp(d, 90, dm);
        sp_2048_from_mp(m, 90, mm);
        err = sp_2048_mod_exp_90(r, a, d, 2048, m, 0);
    }
    if (err == MP_OKAY) {
        sp_2048_to_bin(r, out);
        *outLen = 256;
    }

    if (d != NULL) {
        XMEMSET(d, 0, sizeof(sp_digit) * 90);
        XFREE(d, NULL, DYNAMIC_TYPE_RSA);
    }

    return err;
#else
    sp_digit a[180], d[90], m[90];
    sp_digit* r = a;
    int err = MP_OKAY;

    (void)pm;
    (void)qm;
    (void)dpm;
    (void)dqm;
    (void)qim;

    if (*outLen < 256)
        err = MP_TO_E;
    if (err == MP_OKAY && (mp_count_bits(dm) > 2048 || inLen > 256 ||
                                                     mp_count_bits(mm) != 2048))
        err = MP_READ_E;

    if (err == MP_OKAY) {
        sp_2048_from_bin(a, 90, in, inLen);
        sp_2048_from_mp(d, 90, dm);
        sp_2048_from_mp(m, 90, mm);
        err = sp_2048_mod_exp_90(r, a, d, 2048, m, 0);
    }

    if (err == MP_OKAY) {
        sp_2048_to_bin(r, out);
        *outLen = 256;
    }

    XMEMSET(d, 0, sizeof(sp_digit) * 90);

    return err;
#endif /* !HAVE_DO178 && (WOLFSSL_SP_SMALL || defined(WOLFSSL_SMALL_STACK)) */
#else
#if !defined(HAVE_DO178) && \
    (defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK))
    sp_digit* t = NULL;
    sp_digit* a;
    sp_digit* p;
    sp_digit* q;
    sp_digit* dp;
    sp_digit* dq;
    sp_digit* qi;
    sp_digit* tmp;
    sp_digit* tmpa;
    sp_digit* tmpb;
    sp_digit* r;
    int err = MP_OKAY;

    (void)dm;
    (void)mm;

    if (*outLen < 256)
        err = MP_TO_E;
    if (err == MP_OKAY && (inLen > 256 || mp_count_bits(mm) != 2048))
        err = MP_READ_E;

    if (err == MP_OKAY) {
        t = (sp_digit*)XMALLOC(sizeof(sp_digit) * 45 * 11, NULL,
                                                              DYNAMIC_TYPE_RSA);
        if (t == NULL)
            err = MEMORY_E;
    }
    if (err == MP_OKAY) {
        a = t;
        p = a + 90 * 2;
        q = p + 45;
        qi = dq = dp = q + 45;
        tmpa = qi + 45;
        tmpb = tmpa + 90;

        tmp = t;
        r = tmp + 90;

        sp_2048_from_bin(a, 90, in, inLen);
        sp_2048_from_mp(p, 45, pm);
        sp_2048_from_mp(q, 45, qm);
        sp_2048_from_mp(dp, 45, dpm);
        err = sp_2048_mod_exp_45(tmpa, a, dp, 1024, p, 1);
    }
    if (err == MP_OKAY) {
        sp_2048_from_mp(dq, 45, dqm);
        err = sp_2048_mod_exp_45(tmpb, a, dq, 1024, q, 1);
    }
    if (err == MP_OKAY) {
        sp_2048_sub_45(tmpa, tmpa, tmpb);
        sp_2048_mask_45(tmp, p, tmpa[44] >> 31);
        sp_2048_add_45(tmpa, tmpa, tmp);

        sp_2048_from_mp(qi, 45, qim);
        sp_2048_mul_45(tmpa, tmpa, qi);
        err = sp_2048_mod_45(tmpa, tmpa, p);
    }

    if (err == MP_OKAY) {
        sp_2048_mul_45(tmpa, q, tmpa);
        sp_2048_add_90(r, tmpb, tmpa);
        sp_2048_norm_90(r);

        sp_2048_to_bin(r, out);
        *outLen = 256;
    }

    if (t != NULL) {
        XMEMSET(t, 0, sizeof(sp_digit) * 45 * 11);
        XFREE(t, NULL, DYNAMIC_TYPE_RSA);
    }

    return err;
#else
    sp_digit a[90 * 2];
    sp_digit p[45], q[45], dp[45], dq[45], qi[45];
    sp_digit tmp[90], tmpa[90], tmpb[90];
    sp_digit* r = a;
    int err = MP_OKAY;

    (void)dm;
    (void)mm;

    if (*outLen < 256)
        err = MP_TO_E;
    if (err == MP_OKAY && (inLen > 256 || mp_count_bits(mm) != 2048))
        err = MP_READ_E;

    if (err == MP_OKAY) {
        sp_2048_from_bin(a, 90, in, inLen);
        sp_2048_from_mp(p, 45, pm);
        sp_2048_from_mp(q, 45, qm);
        sp_2048_from_mp(dp, 45, dpm);
        sp_2048_from_mp(dq, 45, dqm);
        sp_2048_from_mp(qi, 45, qim);

        err = sp_2048_mod_exp_45(tmpa, a, dp, 1024, p, 1);
    }
    if (err == MP_OKAY)
        err = sp_2048_mod_exp_45(tmpb, a, dq, 1024, q, 1);

    if (err == MP_OKAY) {
        sp_2048_sub_45(tmpa, tmpa, tmpb);
        sp_2048_mask_45(tmp, p, tmpa[44] >> 31);
        sp_2048_add_45(tmpa, tmpa, tmp);
        sp_2048_mul_45(tmpa, tmpa, qi);
        err = sp_2048_mod_45(tmpa, tmpa, p);
    }

    if (err == MP_OKAY) {
        sp_2048_mul_45(tmpa, tmpa, q);
        sp_2048_add_90(r, tmpb, tmpa);
        sp_2048_norm_90(r);

        sp_2048_to_bin(r, out);
        *outLen = 256;
    }

    XMEMSET(tmpa, 0, sizeof(tmpa));
    XMEMSET(tmpb, 0, sizeof(tmpb));
    XMEMSET(p, 0, sizeof(p));
    XMEMSET(q, 0, sizeof(q));
    XMEMSET(dp, 0, sizeof(dp));
    XMEMSET(dq, 0, sizeof(dq));
    XMEMSET(qi, 0, sizeof(qi));

    return err;
#endif /* !HAVE_DO178 && (WOLFSSL_SP_SMALL || defined(WOLFSSL_SMALL_STACK)) */
#endif /* SP_RSA_PRIVATE_EXP_D || RSA_LOW_MEM */
}

#endif /* !WOLFSSL_RSA_PUBLIC_ONLY */
#endif /* WOLFSSL_HAVE_SP_RSA */
#if defined(WOLFSSL_HAVE_SP_DH) || (defined(WOLFSSL_HAVE_SP_RSA) && \
                                              !defined(WOLFSSL_RSA_PUBLIC_ONLY))
/* Convert an array of sp_digit to an mp_int.
 *
 * a  A single precision integer.
 * r  A multi-precision integer.
 */
static int sp_2048_to_mp(const sp_digit* a, mp_int* r)
{
    int err;

    err = mp_grow(r, (2048 + DIGIT_BIT - 1) / DIGIT_BIT);
    if (err == MP_OKAY) {
#if DIGIT_BIT == 23
        XMEMCPY(r->dp, a, sizeof(sp_digit) * 90);
        r->used = 90;
        mp_clamp(r);
#elif DIGIT_BIT < 23
        int i, j = 0, s = 0;

        r->dp[0] = 0;
        for (i = 0; i < 90; i++) {
            r->dp[j] |= a[i] << s;
            r->dp[j] &= (1l << DIGIT_BIT) - 1;
            s = DIGIT_BIT - s;
            r->dp[++j] = a[i] >> s;
            while (s + DIGIT_BIT <= 23) {
                s += DIGIT_BIT;
                r->dp[j++] &= (1l << DIGIT_BIT) - 1;
                if (s == SP_WORD_SIZE)
                    r->dp[j] = 0;
                else
                    r->dp[j] = a[i] >> s;
            }
            s = 23 - s;
        }
        r->used = (2048 + DIGIT_BIT - 1) / DIGIT_BIT;
        mp_clamp(r);
#else
        int i, j = 0, s = 0;

        r->dp[0] = 0;
        for (i = 0; i < 90; i++) {
            r->dp[j] |= ((mp_digit)a[i]) << s;
            if (s + 23 >= DIGIT_BIT) {
    #if DIGIT_BIT != 32 && DIGIT_BIT != 64
                r->dp[j] &= (1l << DIGIT_BIT) - 1;
    #endif
                s = DIGIT_BIT - s;
                r->dp[++j] = a[i] >> s;
                s = 23 - s;
            }
            else
                s += 23;
        }
        r->used = (2048 + DIGIT_BIT - 1) / DIGIT_BIT;
        mp_clamp(r);
#endif
    }

    return err;
}

/* Perform the modular exponentiation for Diffie-Hellman.
 *
 * base  Base. MP integer.
 * exp   Exponent. MP integer.
 * mod   Modulus. MP integer.
 * res   Result. MP integer.
 * returs 0 on success, MP_READ_E if there are too many bytes in an array
 * and MEMORY_E if memory allocation fails.
 */
int sp_ModExp_2048(mp_int* base, mp_int* exp, mp_int* mod, mp_int* res)
{
#ifdef WOLFSSL_SP_SMALL
    int err = MP_OKAY;
    sp_digit* d = NULL;
    sp_digit* b;
    sp_digit* e;
    sp_digit* m;
    sp_digit* r;
    int expBits = mp_count_bits(exp);

    if (mp_count_bits(base) > 2048 || expBits > 2048 ||
                                                   mp_count_bits(mod) != 2048) {
        err = MP_READ_E;
    }

    if (err == MP_OKAY) {
        d = (sp_digit*)XMALLOC(sizeof(*d) * 90 * 4, NULL, DYNAMIC_TYPE_DH);
        if (d == NULL)
            err = MEMORY_E;
    }

    if (err == MP_OKAY) {
        b = d;
        e = b + 90 * 2;
        m = e + 90;
        r = b;

        sp_2048_from_mp(b, 90, base);
        sp_2048_from_mp(e, 90, exp);
        sp_2048_from_mp(m, 90, mod);

        err = sp_2048_mod_exp_90(r, b, e, mp_count_bits(exp), m, 0);
    }

    if (err == MP_OKAY) {
        err = sp_2048_to_mp(r, res);
    }

    if (d != NULL) {
        XMEMSET(e, 0, sizeof(sp_digit) * 90);
        XFREE(d, NULL, DYNAMIC_TYPE_DH);
    }
    return err;
#else
#if defined(HAVE_DO178) || !defined(WOLFSSL_SMALL_STACK)
    sp_digit bd[180], ed[90], md[90];
#else
    sp_digit* d = NULL;
#endif
    sp_digit* b;
    sp_digit* e;
    sp_digit* m;
    sp_digit* r;
    int err = MP_OKAY;
    int expBits = mp_count_bits(exp);

    if (mp_count_bits(base) > 2048 || expBits > 2048 ||
                                                   mp_count_bits(mod) != 2048) {
        err = MP_READ_E;
    }

#if !defined(HAVE_DO178) && defined(WOLFSSL_SMALL_STACK)
    if (err == MP_OKAY) {
        d = (sp_digit*)XMALLOC(sizeof(*d) * 90 * 4, NULL, DYNAMIC_TYPE_DH);
        if (d == NULL)
            err = MEMORY_E;
    }

    if (err == MP_OKAY) {
        b = d;
        e = b + 90 * 2;
        m = e + 90;
        r = b;
    }
#else
    r = b = bd;
    e = ed;
    m = md;
#endif

    if (err == MP_OKAY) {
        sp_2048_from_mp(b, 90, base);
        sp_2048_from_mp(e, 90, exp);
        sp_2048_from_mp(m, 90, mod);

        err = sp_2048_mod_exp_90(r, b, e, expBits, m, 0);
    }

    if (err == MP_OKAY) {
        err = sp_2048_to_mp(r, res);
    }

    XMEMSET(e, 0, sizeof(sp_digit) * 90);

#if !defined(HAVE_DO178) && defined(WOLFSSL_SMALL_STACK)
    if (d != NULL)
        XFREE(d, NULL, DYNAMIC_TYPE_DH);
#endif

    return err;
#endif
}

#endif /* WOLFSSL_HAVE_SP_DH || (WOLFSSL_HAVE_SP_RSA && !WOLFSSL_RSA_PUBLIC_ONLY) */

#endif /* !WOLFSSL_SP_NO_2048 */

#ifndef WOLFSSL_SP_NO_3072
/* Read big endian unsigned byte aray into r.
 *
 * r  A single precision integer.
 * a  Byte array.
 * n  Number of bytes in array to read.
 */
static void sp_3072_from_bin(sp_digit* r, int max, const byte* a, int n)
{
    int i, j = 0, s = 0;

    r[0] = 0;
    for (i = n-1; i >= 0; i--) {
        r[j] |= ((sp_digit)a[i]) << s;
        if (s >= 15) {
            r[j] &= 0x7fffff;
            s = 23 - s;
            if (j + 1 >= max)
                break;
            r[++j] = a[i] >> s;
            s = 8 - s;
        }
        else
            s += 8;
    }

    for (j++; j < max; j++)
        r[j] = 0;
}

/* Convert an mp_int to an array of sp_digit.
 *
 * r  A single precision integer.
 * a  A multi-precision integer.
 */
static void sp_3072_from_mp(sp_digit* r, int max, const mp_int* a)
{
#if DIGIT_BIT == 23
    int j;

    XMEMCPY(r, a->dp, sizeof(sp_digit) * a->used);

    for (j = a->used; j < max; j++)
        r[j] = 0;
#elif DIGIT_BIT > 23
    int i, j = 0, s = 0;

    r[0] = 0;
    for (i = 0; i < a->used && j < max; i++) {
        r[j] |= a->dp[i] << s;
        r[j] &= 0x7fffff;
        s = 23 - s;
        if (j + 1 >= max)
            break;
        r[++j] = (sp_digit)(a->dp[i] >> s);
        while (s + 23 <= DIGIT_BIT) {
            s += 23;
            r[j] &= 0x7fffff;
            if (j + 1 >= max)
                break;
            if (s < DIGIT_BIT)
                r[++j] = (sp_digit)(a->dp[i] >> s);
            else
                r[++j] = 0;
        }
        s = DIGIT_BIT - s;
    }

    for (j++; j < max; j++)
        r[j] = 0;
#else
    int i, j = 0, s = 0;

    r[0] = 0;
    for (i = 0; i < a->used && j < max; i++) {
        r[j] |= ((sp_digit)a->dp[i]) << s;
        if (s + DIGIT_BIT >= 23) {
            r[j] &= 0x7fffff;
            if (j + 1 >= max)
                break;
            s = 23 - s;
            if (s == DIGIT_BIT) {
                r[++j] = 0;
                s = 0;
            }
            else {
                r[++j] = a->dp[i] >> s;
                s = DIGIT_BIT - s;
            }
        }
        else
            s += DIGIT_BIT;
    }

    for (j++; j < max; j++)
        r[j] = 0;
#endif
}

/* Write r as big endian to byte aray.
 * Fixed length number of bytes written: 384
 *
 * r  A single precision integer.
 * a  Byte array.
 */
static void sp_3072_to_bin(sp_digit* r, byte* a)
{
    int i, j, s = 0, b;

    for (i=0; i<133; i++) {
        r[i+1] += r[i] >> 23;
        r[i] &= 0x7fffff;
    }
    j = 3072 / 8 - 1;
    a[j] = 0;
    for (i=0; i<134 && j>=0; i++) {
        b = 0;
        a[j--] |= r[i] << s; b += 8 - s;
        if (j < 0)
            break;
        while (b < 23) {
            a[j--] = r[i] >> b; b += 8;
            if (j < 0)
                break;
        }
        s = 8 - (b - 23);
        if (j >= 0)
            a[j] = 0;
        if (s != 0)
            j++;
    }
}

#ifndef WOLFSSL_SP_SMALL
/* Multiply a and b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static void sp_3072_mul_67(sp_digit* r, const sp_digit* a,
    const sp_digit* b)
{
    int i, j;
    int64_t t[134];

    XMEMSET(t, 0, sizeof(t));
    for (i=0; i<67; i++) {
        for (j=0; j<67; j++)
            t[i+j] += ((int64_t)a[i]) * b[j];
    }
    for (i=0; i<133; i++) {
        r[i] = t[i] & 0x7fffff;
        t[i+1] += t[i] >> 23;
    }
    r[133] = (sp_digit)t[133];
}

/* Square a and put result in r. (r = a * a)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 */
SP_NOINLINE static void sp_3072_sqr_67(sp_digit* r, const sp_digit* a)
{
    int i, j;
    int64_t t[134];

    XMEMSET(t, 0, sizeof(t));
    for (i=0; i<67; i++) {
        for (j=0; j<i; j++)
            t[i+j] += (((int64_t)a[i]) * a[j]) * 2;
        t[i+i] += ((int64_t)a[i]) * a[i];
    }
    for (i=0; i<133; i++) {
        r[i] = t[i] & 0x7fffff;
        t[i+1] += t[i] >> 23;
    }
    r[133] = (sp_digit)t[133];
}

/* Add b to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_3072_add_67(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 64; i += 8) {
        r[i + 0] = a[i + 0] + b[i + 0];
        r[i + 1] = a[i + 1] + b[i + 1];
        r[i + 2] = a[i + 2] + b[i + 2];
        r[i + 3] = a[i + 3] + b[i + 3];
        r[i + 4] = a[i + 4] + b[i + 4];
        r[i + 5] = a[i + 5] + b[i + 5];
        r[i + 6] = a[i + 6] + b[i + 6];
        r[i + 7] = a[i + 7] + b[i + 7];
    }
    r[64] = a[64] + b[64];
    r[65] = a[65] + b[65];
    r[66] = a[66] + b[66];

    return 0;
}

/* Add b to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_3072_add_134(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 128; i += 8) {
        r[i + 0] = a[i + 0] + b[i + 0];
        r[i + 1] = a[i + 1] + b[i + 1];
        r[i + 2] = a[i + 2] + b[i + 2];
        r[i + 3] = a[i + 3] + b[i + 3];
        r[i + 4] = a[i + 4] + b[i + 4];
        r[i + 5] = a[i + 5] + b[i + 5];
        r[i + 6] = a[i + 6] + b[i + 6];
        r[i + 7] = a[i + 7] + b[i + 7];
    }
    r[128] = a[128] + b[128];
    r[129] = a[129] + b[129];
    r[130] = a[130] + b[130];
    r[131] = a[131] + b[131];
    r[132] = a[132] + b[132];
    r[133] = a[133] + b[133];

    return 0;
}

/* Sub b from a into r. (r = a - b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_3072_sub_134(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 128; i += 8) {
        r[i + 0] = a[i + 0] - b[i + 0];
        r[i + 1] = a[i + 1] - b[i + 1];
        r[i + 2] = a[i + 2] - b[i + 2];
        r[i + 3] = a[i + 3] - b[i + 3];
        r[i + 4] = a[i + 4] - b[i + 4];
        r[i + 5] = a[i + 5] - b[i + 5];
        r[i + 6] = a[i + 6] - b[i + 6];
        r[i + 7] = a[i + 7] - b[i + 7];
    }
    r[128] = a[128] - b[128];
    r[129] = a[129] - b[129];
    r[130] = a[130] - b[130];
    r[131] = a[131] - b[131];
    r[132] = a[132] - b[132];
    r[133] = a[133] - b[133];

    return 0;
}

/* Multiply a and b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static void sp_3072_mul_134(sp_digit* r, const sp_digit* a,
    const sp_digit* b)
{
    sp_digit* z0 = r;
    sp_digit z1[134];
    sp_digit* a1 = z1;
    sp_digit b1[67];
    sp_digit* z2 = r + 134;
    sp_3072_add_67(a1, a, &a[67]);
    sp_3072_add_67(b1, b, &b[67]);
    sp_3072_mul_67(z2, &a[67], &b[67]);
    sp_3072_mul_67(z0, a, b);
    sp_3072_mul_67(z1, a1, b1);
    sp_3072_sub_134(z1, z1, z2);
    sp_3072_sub_134(z1, z1, z0);
    sp_3072_add_134(r + 67, r + 67, z1);
}

/* Square a and put result in r. (r = a * a)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 */
SP_NOINLINE static void sp_3072_sqr_134(sp_digit* r, const sp_digit* a)
{
    sp_digit* z0 = r;
    sp_digit z1[134];
    sp_digit* a1 = z1;
    sp_digit* z2 = r + 134;
    sp_3072_add_67(a1, a, &a[67]);
    sp_3072_sqr_67(z2, &a[67]);
    sp_3072_sqr_67(z0, a);
    sp_3072_sqr_67(z1, a1);
    sp_3072_sub_134(z1, z1, z2);
    sp_3072_sub_134(z1, z1, z0);
    sp_3072_add_134(r + 67, r + 67, z1);
}

#endif /* !WOLFSSL_SP_SMALL */
#ifdef WOLFSSL_SP_SMALL
/* Add b to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_3072_add_134(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 134; i++)
        r[i] = a[i] + b[i];

    return 0;
}
#endif /* WOLFSSL_SP_SMALL */
#ifdef WOLFSSL_SP_SMALL
/* Sub b from a into r. (r = a - b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_3072_sub_134(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 134; i++)
        r[i] = a[i] - b[i];

    return 0;
}

#endif /* WOLFSSL_SP_SMALL */
#ifdef WOLFSSL_SP_SMALL
/* Multiply a and b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static void sp_3072_mul_134(sp_digit* r, const sp_digit* a,
    const sp_digit* b)
{
    int i, j, k;
    int64_t c;

    c = ((int64_t)a[133]) * b[133];
    r[267] = (sp_digit)(c >> 23);
    c = (c & 0x7fffff) << 23;
    for (k = 265; k >= 0; k--) {
        for (i = 133; i >= 0; i--) {
            j = k - i;
            if (j >= 134)
                break;
            if (j < 0)
                continue;

            c += ((int64_t)a[i]) * b[j];
        }
        r[k + 2] += c >> 46;
        r[k + 1] = (c >> 23) & 0x7fffff;
        c = (c & 0x7fffff) << 23;
    }
    r[0] = (sp_digit)(c >> 23);
}

/* Square a and put result in r. (r = a * a)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 */
SP_NOINLINE static void sp_3072_sqr_134(sp_digit* r, const sp_digit* a)
{
    int i, j, k;
    int64_t c;

    c = ((int64_t)a[133]) * a[133];
    r[267] = (sp_digit)(c >> 23);
    c = (c & 0x7fffff) << 23;
    for (k = 265; k >= 0; k--) {
        for (i = 133; i >= 0; i--) {
            j = k - i;
            if (j >= 134 || i <= j)
                break;
            if (j < 0)
                continue;

            c += ((int64_t)a[i]) * a[j] * 2;
        }
        if (i == j)
           c += ((int64_t)a[i]) * a[i];

        r[k + 2] += c >> 46;
        r[k + 1] = (c >> 23) & 0x7fffff;
        c = (c & 0x7fffff) << 23;
    }
    r[0] = (sp_digit)(c >> 23);
}

#endif /* WOLFSSL_SP_SMALL */
#if (defined(WOLFSSL_HAVE_SP_RSA) || defined(WOLFSSL_HAVE_SP_DH)) && !defined(WOLFSSL_RSA_PUBLIC_ONLY)
#ifdef WOLFSSL_SP_SMALL
/* Add b to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_3072_add_67(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 67; i++)
        r[i] = a[i] + b[i];

    return 0;
}
#endif /* WOLFSSL_SP_SMALL */
#ifdef WOLFSSL_SP_SMALL
/* Sub b from a into r. (r = a - b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_3072_sub_67(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 67; i++)
        r[i] = a[i] - b[i];

    return 0;
}

#else
/* Sub b from a into r. (r = a - b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_3072_sub_67(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 64; i += 8) {
        r[i + 0] = a[i + 0] - b[i + 0];
        r[i + 1] = a[i + 1] - b[i + 1];
        r[i + 2] = a[i + 2] - b[i + 2];
        r[i + 3] = a[i + 3] - b[i + 3];
        r[i + 4] = a[i + 4] - b[i + 4];
        r[i + 5] = a[i + 5] - b[i + 5];
        r[i + 6] = a[i + 6] - b[i + 6];
        r[i + 7] = a[i + 7] - b[i + 7];
    }
    r[64] = a[64] - b[64];
    r[65] = a[65] - b[65];
    r[66] = a[66] - b[66];

    return 0;
}

#endif /* WOLFSSL_SP_SMALL */
#ifdef WOLFSSL_SP_SMALL
/* Multiply a and b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static void sp_3072_mul_67(sp_digit* r, const sp_digit* a,
    const sp_digit* b)
{
    int i, j, k;
    int64_t c;

    c = ((int64_t)a[66]) * b[66];
    r[133] = (sp_digit)(c >> 23);
    c = (c & 0x7fffff) << 23;
    for (k = 131; k >= 0; k--) {
        for (i = 66; i >= 0; i--) {
            j = k - i;
            if (j >= 67)
                break;
            if (j < 0)
                continue;

            c += ((int64_t)a[i]) * b[j];
        }
        r[k + 2] += c >> 46;
        r[k + 1] = (c >> 23) & 0x7fffff;
        c = (c & 0x7fffff) << 23;
    }
    r[0] = (sp_digit)(c >> 23);
}

/* Square a and put result in r. (r = a * a)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 */
SP_NOINLINE static void sp_3072_sqr_67(sp_digit* r, const sp_digit* a)
{
    int i, j, k;
    int64_t c;

    c = ((int64_t)a[66]) * a[66];
    r[133] = (sp_digit)(c >> 23);
    c = (c & 0x7fffff) << 23;
    for (k = 131; k >= 0; k--) {
        for (i = 66; i >= 0; i--) {
            j = k - i;
            if (j >= 67 || i <= j)
                break;
            if (j < 0)
                continue;

            c += ((int64_t)a[i]) * a[j] * 2;
        }
        if (i == j)
           c += ((int64_t)a[i]) * a[i];

        r[k + 2] += c >> 46;
        r[k + 1] = (c >> 23) & 0x7fffff;
        c = (c & 0x7fffff) << 23;
    }
    r[0] = (sp_digit)(c >> 23);
}

#endif /* WOLFSSL_SP_SMALL */
#endif /* (WOLFSSL_HAVE_SP_RSA || WOLFSSL_HAVE_SP_DH) && !WOLFSSL_RSA_PUBLIC_ONLY */

/* Caclulate the bottom digit of -1/a mod 2^n.
 *
 * a    A single precision number.
 * rho  Bottom word of inverse.
 */
static void sp_3072_mont_setup(const sp_digit* a, sp_digit* rho)
{
    sp_digit x, b;

    b = a[0];
    x = (((b + 2) & 4) << 1) + b; /* here x*a==1 mod 2**4 */
    x *= 2 - b * x;               /* here x*a==1 mod 2**8 */
    x *= 2 - b * x;               /* here x*a==1 mod 2**16 */
    x *= 2 - b * x;               /* here x*a==1 mod 2**32 */
    x &= 0x7fffff;

    /* rho = -1/m mod b */
    *rho = (1L << 23) - x;
}

/* Multiply a by scalar b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A scalar.
 */
SP_NOINLINE static void sp_3072_mul_d_134(sp_digit* r, const sp_digit* a,
    sp_digit b)
{
#ifdef WOLFSSL_SP_SMALL
    int64_t tb = b;
    int64_t t = 0;
    int i;

    for (i = 0; i < 134; i++) {
        t += tb * a[i];
        r[i] = t & 0x7fffff;
        t >>= 23;
    }
    r[134] = (sp_digit)t;
#else
    int64_t tb = b;
    int64_t t[8];
    int i;

    t[0] = tb * a[0]; r[0] = t[0] & 0x7fffff;
    for (i = 0; i < 128; i += 8) {
        t[1] = tb * a[i+1];
        r[i+1] = (sp_digit)(t[0] >> 23) + (t[1] & 0x7fffff);
        t[2] = tb * a[i+2];
        r[i+2] = (sp_digit)(t[1] >> 23) + (t[2] & 0x7fffff);
        t[3] = tb * a[i+3];
        r[i+3] = (sp_digit)(t[2] >> 23) + (t[3] & 0x7fffff);
        t[4] = tb * a[i+4];
        r[i+4] = (sp_digit)(t[3] >> 23) + (t[4] & 0x7fffff);
        t[5] = tb * a[i+5];
        r[i+5] = (sp_digit)(t[4] >> 23) + (t[5] & 0x7fffff);
        t[6] = tb * a[i+6];
        r[i+6] = (sp_digit)(t[5] >> 23) + (t[6] & 0x7fffff);
        t[7] = tb * a[i+7];
        r[i+7] = (sp_digit)(t[6] >> 23) + (t[7] & 0x7fffff);
        t[0] = tb * a[i+8];
        r[i+8] = (sp_digit)(t[7] >> 23) + (t[0] & 0x7fffff);
    }
    t[1] = tb * a[129];
    r[129] = (sp_digit)(t[0] >> 23) + (t[1] & 0x7fffff);
    t[2] = tb * a[130];
    r[130] = (sp_digit)(t[1] >> 23) + (t[2] & 0x7fffff);
    t[3] = tb * a[131];
    r[131] = (sp_digit)(t[2] >> 23) + (t[3] & 0x7fffff);
    t[4] = tb * a[132];
    r[132] = (sp_digit)(t[3] >> 23) + (t[4] & 0x7fffff);
    t[5] = tb * a[133];
    r[133] = (sp_digit)(t[4] >> 23) + (t[5] & 0x7fffff);
    r[134] =  (sp_digit)(t[5] >> 23);
#endif /* WOLFSSL_SP_SMALL */
}

#if (defined(WOLFSSL_HAVE_SP_RSA) || defined(WOLFSSL_HAVE_SP_DH)) && !defined(WOLFSSL_RSA_PUBLIC_ONLY)
/* r = 2^n mod m where n is the number of bits to reduce by.
 * Given m must be 3072 bits, just need to subtract.
 *
 * r  A single precision number.
 * m  A signle precision number.
 */
static void sp_3072_mont_norm_67(sp_digit* r, const sp_digit* m)
{
    /* Set r = 2^n - 1. */
#ifdef WOLFSSL_SP_SMALL
    int i;

    for (i=0; i<66; i++)
        r[i] = 0x7fffff;
#else
    int i;

    for (i = 0; i < 64; i += 8) {
        r[i + 0] = 0x7fffff;
        r[i + 1] = 0x7fffff;
        r[i + 2] = 0x7fffff;
        r[i + 3] = 0x7fffff;
        r[i + 4] = 0x7fffff;
        r[i + 5] = 0x7fffff;
        r[i + 6] = 0x7fffff;
        r[i + 7] = 0x7fffff;
    }
    r[64] = 0x7fffff;
    r[65] = 0x7fffff;
#endif
    r[66] = 0x3ffffl;

    /* r = (2^n - 1) mod n */
    sp_3072_sub_67(r, r, m);

    /* Add one so r = 2^n mod m */
    r[0] += 1;
}

/* Compare a with b in constant time.
 *
 * a  A single precision integer.
 * b  A single precision integer.
 * return -ve, 0 or +ve if a is less than, equal to or greater than b
 * respectively.
 */
static sp_digit sp_3072_cmp_67(const sp_digit* a, const sp_digit* b)
{
    sp_digit r = 0;
#ifdef WOLFSSL_SP_SMALL
    int i;

    for (i=66; i>=0; i--)
        r |= (a[i] - b[i]) & (0 - !r);
#else
    int i;

    r |= (a[66] - b[66]) & (0 - !r);
    r |= (a[65] - b[65]) & (0 - !r);
    r |= (a[64] - b[64]) & (0 - !r);
    for (i = 56; i >= 0; i -= 8) {
        r |= (a[i + 7] - b[i + 7]) & (0 - !r);
        r |= (a[i + 6] - b[i + 6]) & (0 - !r);
        r |= (a[i + 5] - b[i + 5]) & (0 - !r);
        r |= (a[i + 4] - b[i + 4]) & (0 - !r);
        r |= (a[i + 3] - b[i + 3]) & (0 - !r);
        r |= (a[i + 2] - b[i + 2]) & (0 - !r);
        r |= (a[i + 1] - b[i + 1]) & (0 - !r);
        r |= (a[i + 0] - b[i + 0]) & (0 - !r);
    }
#endif /* WOLFSSL_SP_SMALL */

    return r;
}

/* Conditionally subtract b from a using the mask m.
 * m is -1 to subtract and 0 when not.
 *
 * r  A single precision number representing condition subtract result.
 * a  A single precision number to subtract from.
 * b  A single precision number to subtract.
 * m  Mask value to apply.
 */
static void sp_3072_cond_sub_67(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit m)
{
#ifdef WOLFSSL_SP_SMALL
    int i;

    for (i = 0; i < 67; i++)
        r[i] = a[i] - (b[i] & m);
#else
    int i;

    for (i = 0; i < 64; i += 8) {
        r[i + 0] = a[i + 0] - (b[i + 0] & m);
        r[i + 1] = a[i + 1] - (b[i + 1] & m);
        r[i + 2] = a[i + 2] - (b[i + 2] & m);
        r[i + 3] = a[i + 3] - (b[i + 3] & m);
        r[i + 4] = a[i + 4] - (b[i + 4] & m);
        r[i + 5] = a[i + 5] - (b[i + 5] & m);
        r[i + 6] = a[i + 6] - (b[i + 6] & m);
        r[i + 7] = a[i + 7] - (b[i + 7] & m);
    }
    r[64] = a[64] - (b[64] & m);
    r[65] = a[65] - (b[65] & m);
    r[66] = a[66] - (b[66] & m);
#endif /* WOLFSSL_SP_SMALL */
}

/* Mul a by scalar b and add into r. (r += a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A scalar.
 */
SP_NOINLINE static void sp_3072_mul_add_67(sp_digit* r, const sp_digit* a,
        const sp_digit b)
{
#ifdef WOLFSSL_SP_SMALL
    int64_t tb = b;
    int64_t t = 0;
    int i;

    for (i = 0; i < 67; i++) {
        t += (tb * a[i]) + r[i];
        r[i] = t & 0x7fffff;
        t >>= 23;
    }
    r[67] += t;
#else
    int64_t tb = b;
    int64_t t[8];
    int i;

    t[0] = tb * a[0]; r[0] += t[0] & 0x7fffff;
    for (i = 0; i < 64; i += 8) {
        t[1] = tb * a[i+1];
        r[i+1] += (t[0] >> 23) + (t[1] & 0x7fffff);
        t[2] = tb * a[i+2];
        r[i+2] += (t[1] >> 23) + (t[2] & 0x7fffff);
        t[3] = tb * a[i+3];
        r[i+3] += (t[2] >> 23) + (t[3] & 0x7fffff);
        t[4] = tb * a[i+4];
        r[i+4] += (t[3] >> 23) + (t[4] & 0x7fffff);
        t[5] = tb * a[i+5];
        r[i+5] += (t[4] >> 23) + (t[5] & 0x7fffff);
        t[6] = tb * a[i+6];
        r[i+6] += (t[5] >> 23) + (t[6] & 0x7fffff);
        t[7] = tb * a[i+7];
        r[i+7] += (t[6] >> 23) + (t[7] & 0x7fffff);
        t[0] = tb * a[i+8];
        r[i+8] += (t[7] >> 23) + (t[0] & 0x7fffff);
    }
    t[1] = tb * a[65]; r[65] += (t[0] >> 23) + (t[1] & 0x7fffff);
    t[2] = tb * a[66]; r[66] += (t[1] >> 23) + (t[2] & 0x7fffff);
    r[67] +=  t[2] >> 23;
#endif /* WOLFSSL_SP_SMALL */
}

/* Normalize the values in each word to 23.
 *
 * a  Array of sp_digit to normalize.
 */
static void sp_3072_norm_67(sp_digit* a)
{
#ifdef WOLFSSL_SP_SMALL
    int i;
    for (i = 0; i < 66; i++) {
        a[i+1] += a[i] >> 23;
        a[i] &= 0x7fffff;
    }
#else
    int i;
    for (i = 0; i < 64; i += 8) {
        a[i+1] += a[i+0] >> 23; a[i+0] &= 0x7fffff;
        a[i+2] += a[i+1] >> 23; a[i+1] &= 0x7fffff;
        a[i+3] += a[i+2] >> 23; a[i+2] &= 0x7fffff;
        a[i+4] += a[i+3] >> 23; a[i+3] &= 0x7fffff;
        a[i+5] += a[i+4] >> 23; a[i+4] &= 0x7fffff;
        a[i+6] += a[i+5] >> 23; a[i+5] &= 0x7fffff;
        a[i+7] += a[i+6] >> 23; a[i+6] &= 0x7fffff;
        a[i+8] += a[i+7] >> 23; a[i+7] &= 0x7fffff;
        a[i+9] += a[i+8] >> 23; a[i+8] &= 0x7fffff;
    }
    a[64+1] += a[64] >> 23;
    a[64] &= 0x7fffff;
    a[65+1] += a[65] >> 23;
    a[65] &= 0x7fffff;
#endif
}

/* Shift the result in the high 1536 bits down to the bottom.
 *
 * r  A single precision number.
 * a  A single precision number.
 */
static void sp_3072_mont_shift_67(sp_digit* r, const sp_digit* a)
{
#ifdef WOLFSSL_SP_SMALL
    int i;
    sp_digit n, s;

    s = a[67];
    n = a[66] >> 18;
    for (i = 0; i < 66; i++) {
        n += (s & 0x7fffff) << 5;
        r[i] = n & 0x7fffff;
        n >>= 23;
        s = a[68 + i] + (s >> 23);
    }
    n += s << 5;
    r[66] = n;
#else
    sp_digit n, s;
    int i;

    s = a[67]; n = a[66] >> 18;
    for (i = 0; i < 64; i += 8) {
        n += (s & 0x7fffff) << 5; r[i+0] = n & 0x7fffff;
        n >>= 23; s = a[i+68] + (s >> 23);
        n += (s & 0x7fffff) << 5; r[i+1] = n & 0x7fffff;
        n >>= 23; s = a[i+69] + (s >> 23);
        n += (s & 0x7fffff) << 5; r[i+2] = n & 0x7fffff;
        n >>= 23; s = a[i+70] + (s >> 23);
        n += (s & 0x7fffff) << 5; r[i+3] = n & 0x7fffff;
        n >>= 23; s = a[i+71] + (s >> 23);
        n += (s & 0x7fffff) << 5; r[i+4] = n & 0x7fffff;
        n >>= 23; s = a[i+72] + (s >> 23);
        n += (s & 0x7fffff) << 5; r[i+5] = n & 0x7fffff;
        n >>= 23; s = a[i+73] + (s >> 23);
        n += (s & 0x7fffff) << 5; r[i+6] = n & 0x7fffff;
        n >>= 23; s = a[i+74] + (s >> 23);
        n += (s & 0x7fffff) << 5; r[i+7] = n & 0x7fffff;
        n >>= 23; s = a[i+75] + (s >> 23);
    }
    n += (s & 0x7fffff) << 5; r[64] = n & 0x7fffff;
    n >>= 23; s = a[132] + (s >> 23);
    n += (s & 0x7fffff) << 5; r[65] = n & 0x7fffff;
    n >>= 23; s = a[133] + (s >> 23);
    n += s << 5;              r[66] = n;
#endif /* WOLFSSL_SP_SMALL */
    XMEMSET(&r[67], 0, sizeof(*r) * 67);
}

/* Reduce the number back to 3072 bits using Montgomery reduction.
 *
 * a   A single precision number to reduce in place.
 * m   The single precision number representing the modulus.
 * mp  The digit representing the negative inverse of m mod 2^n.
 */
static void sp_3072_mont_reduce_67(sp_digit* a, const sp_digit* m, sp_digit mp)
{
    int i;
    sp_digit mu;

    for (i=0; i<66; i++) {
        mu = (a[i] * mp) & 0x7fffff;
        sp_3072_mul_add_67(a+i, m, mu);
        a[i+1] += a[i] >> 23;
    }
    mu = (a[i] * mp) & 0x3ffffl;
    sp_3072_mul_add_67(a+i, m, mu);
    a[i+1] += a[i] >> 23;
    a[i] &= 0x7fffff;

    sp_3072_mont_shift_67(a, a);
    sp_3072_cond_sub_67(a, a, m, 0 - ((a[66] >> 18) > 0));
    sp_3072_norm_67(a);
}

/* Multiply two Montogmery form numbers mod the modulus (prime).
 * (r = a * b mod m)
 *
 * r   Result of multiplication.
 * a   First number to multiply in Montogmery form.
 * b   Second number to multiply in Montogmery form.
 * m   Modulus (prime).
 * mp  Montogmery mulitplier.
 */
static void sp_3072_mont_mul_67(sp_digit* r, const sp_digit* a, const sp_digit* b,
        const sp_digit* m, sp_digit mp)
{
    sp_3072_mul_67(r, a, b);
    sp_3072_mont_reduce_67(r, m, mp);
}

/* Square the Montgomery form number. (r = a * a mod m)
 *
 * r   Result of squaring.
 * a   Number to square in Montogmery form.
 * m   Modulus (prime).
 * mp  Montogmery mulitplier.
 */
static void sp_3072_mont_sqr_67(sp_digit* r, const sp_digit* a, const sp_digit* m,
        sp_digit mp)
{
    sp_3072_sqr_67(r, a);
    sp_3072_mont_reduce_67(r, m, mp);
}

/* Multiply a by scalar b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A scalar.
 */
SP_NOINLINE static void sp_3072_mul_d_67(sp_digit* r, const sp_digit* a,
    sp_digit b)
{
#ifdef WOLFSSL_SP_SMALL
    int64_t tb = b;
    int64_t t = 0;
    int i;

    for (i = 0; i < 67; i++) {
        t += tb * a[i];
        r[i] = t & 0x7fffff;
        t >>= 23;
    }
    r[67] = (sp_digit)t;
#else
    int64_t tb = b;
    int64_t t[8];
    int i;

    t[0] = tb * a[0]; r[0] = t[0] & 0x7fffff;
    for (i = 0; i < 64; i += 8) {
        t[1] = tb * a[i+1];
        r[i+1] = (sp_digit)(t[0] >> 23) + (t[1] & 0x7fffff);
        t[2] = tb * a[i+2];
        r[i+2] = (sp_digit)(t[1] >> 23) + (t[2] & 0x7fffff);
        t[3] = tb * a[i+3];
        r[i+3] = (sp_digit)(t[2] >> 23) + (t[3] & 0x7fffff);
        t[4] = tb * a[i+4];
        r[i+4] = (sp_digit)(t[3] >> 23) + (t[4] & 0x7fffff);
        t[5] = tb * a[i+5];
        r[i+5] = (sp_digit)(t[4] >> 23) + (t[5] & 0x7fffff);
        t[6] = tb * a[i+6];
        r[i+6] = (sp_digit)(t[5] >> 23) + (t[6] & 0x7fffff);
        t[7] = tb * a[i+7];
        r[i+7] = (sp_digit)(t[6] >> 23) + (t[7] & 0x7fffff);
        t[0] = tb * a[i+8];
        r[i+8] = (sp_digit)(t[7] >> 23) + (t[0] & 0x7fffff);
    }
    t[1] = tb * a[65];
    r[65] = (sp_digit)(t[0] >> 23) + (t[1] & 0x7fffff);
    t[2] = tb * a[66];
    r[66] = (sp_digit)(t[1] >> 23) + (t[2] & 0x7fffff);
    r[67] =  (sp_digit)(t[2] >> 23);
#endif /* WOLFSSL_SP_SMALL */
}

/* Conditionally add a and b using the mask m.
 * m is -1 to add and 0 when not.
 *
 * r  A single precision number representing conditional add result.
 * a  A single precision number to add with.
 * b  A single precision number to add.
 * m  Mask value to apply.
 */
static void sp_3072_cond_add_67(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit m)
{
#ifdef WOLFSSL_SP_SMALL
    int i;

    for (i = 0; i < 67; i++)
        r[i] = a[i] + (b[i] & m);
#else
    int i;

    for (i = 0; i < 64; i += 8) {
        r[i + 0] = a[i + 0] + (b[i + 0] & m);
        r[i + 1] = a[i + 1] + (b[i + 1] & m);
        r[i + 2] = a[i + 2] + (b[i + 2] & m);
        r[i + 3] = a[i + 3] + (b[i + 3] & m);
        r[i + 4] = a[i + 4] + (b[i + 4] & m);
        r[i + 5] = a[i + 5] + (b[i + 5] & m);
        r[i + 6] = a[i + 6] + (b[i + 6] & m);
        r[i + 7] = a[i + 7] + (b[i + 7] & m);
    }
    r[64] = a[64] + (b[64] & m);
    r[65] = a[65] + (b[65] & m);
    r[66] = a[66] + (b[66] & m);
#endif /* WOLFSSL_SP_SMALL */
}

#ifdef WOLFSSL_SMALL
/* Add b to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_3072_add_67(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 67; i++)
        r[i] = a[i] + b[i];

    return 0;
}
#endif
#ifdef WOLFSSL_SP_DIV_32
static WC_INLINE sp_digit sp_3072_div_word_67(sp_digit d1, sp_digit d0,
    sp_digit div)
{
    sp_digit d, r, t;

    /* All 23 bits from d1 and top 8 bits from d0. */
    d = (d1 << 8) | (d0 >> 15);
    r = d / div;
    d -= r * div;
    /* Up to 9 bits in r */
    /* Next 8 bits from d0. */
    r <<= 8;
    d <<= 8;
    d |= (d0 >> 7) & ((1 << 8) - 1);
    t = d / div;
    d -= t * div;
    r += t;
    /* Up to 17 bits in r */
    /* Remaining 7 bits from d0. */
    r <<= 7;
    d <<= 7;
    d |= d0 & ((1 << 7) - 1);
    t = d / div;
    r += t;

    return r;
}
#endif /* WOLFSSL_SP_DIV_32 */

/* Divide d in a and put remainder into r (m*d + r = a)
 * m is not calculated as it is not needed at this time.
 *
 * a  Nmber to be divided.
 * d  Number to divide with.
 * m  Multiplier result.
 * r  Remainder from the division.
 * returns MEMORY_E when unable to allocate memory and MP_OKAY otherwise.
 */
static int sp_3072_div_67(const sp_digit* a, const sp_digit* d, sp_digit* m,
        sp_digit* r)
{
    int i;
#ifndef WOLFSSL_SP_DIV_32
    int64_t d1;
#endif
    sp_digit div, r1;
#if !defined(HAVE_DO178) && (defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK))
    sp_digit* td;
#else
    sp_digit t1d[134], t2d[67 + 1];
#endif
    sp_digit* t1;
    sp_digit* t2;
    int err = MP_OKAY;

#if !defined(HAVE_DO178) && (defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK))
    td = (sp_digit*)XMALLOC(sizeof(sp_digit) * (3 * 67 + 1), NULL,
                                                       DYNAMIC_TYPE_TMP_BUFFER);
    if (td != NULL) {
        t1 = td;
        t2 = td + 2 * 67;
    }
    else
        err = MEMORY_E;
#else
    t1 = t1d;
    t2 = t2d;
#endif

    (void)m;

    if (err == MP_OKAY) {
        div = d[66];
        XMEMCPY(t1, a, sizeof(*t1) * 2 * 67);
        for (i=66; i>=0; i--) {
            t1[67 + i] += t1[67 + i - 1] >> 23;
            t1[67 + i - 1] &= 0x7fffff;
#ifndef WOLFSSL_SP_DIV_32
            d1 = t1[67 + i];
            d1 <<= 23;
            d1 += t1[67 + i - 1];
            r1 = (sp_digit)(d1 / div);
#else
            r1 = sp_3072_div_word_67(t1[67 + i], t1[67 + i - 1], div);
#endif

            sp_3072_mul_d_67(t2, d, r1);
            sp_3072_sub_67(&t1[i], &t1[i], t2);
            t1[67 + i] -= t2[67];
            t1[67 + i] += t1[67 + i - 1] >> 23;
            t1[67 + i - 1] &= 0x7fffff;
            r1 = (((-t1[67 + i]) << 23) - t1[67 + i - 1]) / div;
            r1++;
            sp_3072_mul_d_67(t2, d, r1);
            sp_3072_add_67(&t1[i], &t1[i], t2);
            t1[67 + i] += t1[67 + i - 1] >> 23;
            t1[67 + i - 1] &= 0x7fffff;
        }
        t1[67 - 1] += t1[67 - 2] >> 23;
        t1[67 - 2] &= 0x7fffff;
        r1 = t1[67 - 1] / div;

        sp_3072_mul_d_67(t2, d, r1);
        sp_3072_sub_67(t1, t1, t2);
        XMEMCPY(r, t1, sizeof(*r) * 2 * 67);
        for (i=0; i<65; i++) {
            r[i+1] += r[i] >> 23;
            r[i] &= 0x7fffff;
        }
        sp_3072_cond_add_67(r, r, d, 0 - (r[66] < 0));
    }

#if !defined(HAVE_DO178) && (defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK))
    if (td != NULL)
        XFREE(td, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return err;
}

/* Reduce a modulo m into r. (r = a mod m)
 *
 * r  A single precision number that is the reduced result.
 * a  A single precision number that is to be reduced.
 * m  A single precision number that is the modulus to reduce with.
 * returns MEMORY_E when unable to allocate memory and MP_OKAY otherwise.
 */
static int sp_3072_mod_67(sp_digit* r, const sp_digit* a, const sp_digit* m)
{
    return sp_3072_div_67(a, m, NULL, r);
}

/* Modular exponentiate a to the e mod m. (r = a^e mod m)
 *
 * r     A single precision number that is the result of the operation.
 * a     A single precision number being exponentiated.
 * e     A single precision number that is the exponent.
 * bits  The number of bits in the exponent.
 * m     A single precision number that is the modulus.
 * returns 0 on success and MEMORY_E on dynamic memory allocation failure.
 */
static int sp_3072_mod_exp_67(sp_digit* r, const sp_digit* a, const sp_digit* e, int bits,
    const sp_digit* m, int reduceA)
{
#ifdef WOLFSSL_SP_SMALL
    sp_digit* td;
    sp_digit* t[3];
    sp_digit* norm;
    sp_digit mp = 1;
    sp_digit n;
    int i;
    int c, y;
    int err = MP_OKAY;

    td = (sp_digit*)XMALLOC(sizeof(*td) * 3 * 67 * 2, NULL,
                            DYNAMIC_TYPE_TMP_BUFFER);
    if (td == NULL)
        err = MEMORY_E;

    if (err == MP_OKAY) {
        XMEMSET(td, 0, sizeof(*td) * 3 * 67 * 2);

        norm = t[0] = td;
        t[1] = &td[67 * 2];
        t[2] = &td[2 * 67 * 2];

        sp_3072_mont_setup(m, &mp);
        sp_3072_mont_norm_67(norm, m);

        if (reduceA)
            err = sp_3072_mod_67(t[1], a, m);
        else
            XMEMCPY(t[1], a, sizeof(sp_digit) * 67);
    }
    if (err == MP_OKAY) {
        sp_3072_mul_67(t[1], t[1], norm);
        err = sp_3072_mod_67(t[1], t[1], m);
    }

    if (err == MP_OKAY) {
        i = bits / 23;
        c = bits % 23;
        n = e[i--] << (23 - c);
        for (; ; c--) {
            if (c == 0) {
                if (i == -1)
                    break;

                n = e[i--];
                c = 23;
            }

            y = (n >> 22) & 1;
            n <<= 1;

            sp_3072_mont_mul_67(t[y^1], t[0], t[1], m, mp);

            XMEMCPY(t[2], (void*)(((size_t)t[0] & addr_mask[y^1]) +
                                  ((size_t)t[1] & addr_mask[y])),
                    sizeof(*t[2]) * 67 * 2);
            sp_3072_mont_sqr_67(t[2], t[2], m, mp);
            XMEMCPY((void*)(((size_t)t[0] & addr_mask[y^1]) +
                            ((size_t)t[1] & addr_mask[y])), t[2],
                    sizeof(*t[2]) * 67 * 2);
        }

        sp_3072_mont_reduce_67(t[0], m, mp);
        n = sp_3072_cmp_67(t[0], m);
        sp_3072_cond_sub_67(t[0], t[0], m, (n < 0) - 1);
        XMEMCPY(r, t[0], sizeof(*r) * 67 * 2);

    }

    if (td != NULL)
        XFREE(td, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    return err;
#elif defined(WOLFSSL_SP_CACHE_RESISTANT)
#if defined(HAVE_DO178) || !defined(WOLFSSL_SMALL_STACK)
    sp_digit t[3][134];
#else
    sp_digit* td;
    sp_digit* t[3];
#endif
    sp_digit* norm;
    sp_digit mp = 1;
    sp_digit n;
    int i;
    int c, y;
    int err = MP_OKAY;

#if !defined(HAVE_DO178) && defined(WOLFSSL_SMALL_STACK)
    td = (sp_digit*)XMALLOC(sizeof(*td) * 3 * 67 * 2, NULL,
                            DYNAMIC_TYPE_TMP_BUFFER);
    if (td == NULL)
        err = MEMORY_E;

    if (err == MP_OKAY) {
        t[0] = td;
        t[1] = &td[67 * 2];
        t[2] = &td[2 * 67 * 2];
        norm = t[0];
    }
#else
    norm = t[0];
#endif

    if (err == MP_OKAY) {
        sp_3072_mont_setup(m, &mp);
        sp_3072_mont_norm_67(norm, m);

        if (reduceA) {
            err = sp_3072_mod_67(t[1], a, m);
            if (err == MP_OKAY) {
                sp_3072_mul_67(t[1], t[1], norm);
                err = sp_3072_mod_67(t[1], t[1], m);
            }
        }
        else {
            sp_3072_mul_67(t[1], a, norm);
            err = sp_3072_mod_67(t[1], t[1], m);
        }
    }

    if (err == MP_OKAY) {
        i = bits / 23;
        c = bits % 23;
        n = e[i--] << (23 - c);
        for (; ; c--) {
            if (c == 0) {
                if (i == -1)
                    break;

                n = e[i--];
                c = 23;
            }

            y = (n >> 22) & 1;
            n <<= 1;

            sp_3072_mont_mul_67(t[y^1], t[0], t[1], m, mp);

            XMEMCPY(t[2], (void*)(((size_t)t[0] & addr_mask[y^1]) +
                                 ((size_t)t[1] & addr_mask[y])), sizeof(t[2]));
            sp_3072_mont_sqr_67(t[2], t[2], m, mp);
            XMEMCPY((void*)(((size_t)t[0] & addr_mask[y^1]) +
                           ((size_t)t[1] & addr_mask[y])), t[2], sizeof(t[2]));
        }

        sp_3072_mont_reduce_67(t[0], m, mp);
        n = sp_3072_cmp_67(t[0], m);
        sp_3072_cond_sub_67(t[0], t[0], m, (n < 0) - 1);
        XMEMCPY(r, t[0], sizeof(t[0]));
    }

#if !defined(HAVE_DO178) && defined(WOLFSSL_SMALL_STACK)
    if (td != NULL)
        XFREE(td, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return err;
#else
#if defined(HAVE_DO178) || !defined(WOLFSSL_SMALL_STACK)
    sp_digit t[32][134];
#else
    sp_digit* t[32];
    sp_digit* td;
#endif
    sp_digit* norm;
    sp_digit rt[134];
    sp_digit mp = 1;
    sp_digit n;
    int i;
    int c, y;
    int err = MP_OKAY;

#if !defined(HAVE_DO178) && defined(WOLFSSL_SMALL_STACK)
    td = (sp_digit*)XMALLOC(sizeof(sp_digit) * 32 * 134, NULL,
                            DYNAMIC_TYPE_TMP_BUFFER);
    if (td == NULL)
        err = MEMORY_E;

    if (err == MP_OKAY) {
        for (i=0; i<32; i++)
            t[i] = td + i * 134;
        norm = t[0];
    }
#else
    norm = t[0];
#endif

    if (err == MP_OKAY) {
        sp_3072_mont_setup(m, &mp);
        sp_3072_mont_norm_67(norm, m);

        if (reduceA) {
            err = sp_3072_mod_67(t[1], a, m);
            if (err == MP_OKAY) {
                sp_3072_mul_67(t[1], t[1], norm);
                err = sp_3072_mod_67(t[1], t[1], m);
            }
        }
        else {
            sp_3072_mul_67(t[1], a, norm);
            err = sp_3072_mod_67(t[1], t[1], m);
        }
    }

    if (err == MP_OKAY) {
        sp_3072_mont_sqr_67(t[ 2], t[ 1], m, mp);
        sp_3072_mont_mul_67(t[ 3], t[ 2], t[ 1], m, mp);
        sp_3072_mont_sqr_67(t[ 4], t[ 2], m, mp);
        sp_3072_mont_mul_67(t[ 5], t[ 3], t[ 2], m, mp);
        sp_3072_mont_sqr_67(t[ 6], t[ 3], m, mp);
        sp_3072_mont_mul_67(t[ 7], t[ 4], t[ 3], m, mp);
        sp_3072_mont_sqr_67(t[ 8], t[ 4], m, mp);
        sp_3072_mont_mul_67(t[ 9], t[ 5], t[ 4], m, mp);
        sp_3072_mont_sqr_67(t[10], t[ 5], m, mp);
        sp_3072_mont_mul_67(t[11], t[ 6], t[ 5], m, mp);
        sp_3072_mont_sqr_67(t[12], t[ 6], m, mp);
        sp_3072_mont_mul_67(t[13], t[ 7], t[ 6], m, mp);
        sp_3072_mont_sqr_67(t[14], t[ 7], m, mp);
        sp_3072_mont_mul_67(t[15], t[ 8], t[ 7], m, mp);
        sp_3072_mont_sqr_67(t[16], t[ 8], m, mp);
        sp_3072_mont_mul_67(t[17], t[ 9], t[ 8], m, mp);
        sp_3072_mont_sqr_67(t[18], t[ 9], m, mp);
        sp_3072_mont_mul_67(t[19], t[10], t[ 9], m, mp);
        sp_3072_mont_sqr_67(t[20], t[10], m, mp);
        sp_3072_mont_mul_67(t[21], t[11], t[10], m, mp);
        sp_3072_mont_sqr_67(t[22], t[11], m, mp);
        sp_3072_mont_mul_67(t[23], t[12], t[11], m, mp);
        sp_3072_mont_sqr_67(t[24], t[12], m, mp);
        sp_3072_mont_mul_67(t[25], t[13], t[12], m, mp);
        sp_3072_mont_sqr_67(t[26], t[13], m, mp);
        sp_3072_mont_mul_67(t[27], t[14], t[13], m, mp);
        sp_3072_mont_sqr_67(t[28], t[14], m, mp);
        sp_3072_mont_mul_67(t[29], t[15], t[14], m, mp);
        sp_3072_mont_sqr_67(t[30], t[15], m, mp);
        sp_3072_mont_mul_67(t[31], t[16], t[15], m, mp);

        bits = ((bits + 4) / 5) * 5;
        i = ((bits + 22) / 23) - 1;
        c = bits % 23;
        if (c == 0)
            c = 23;
        if (i < 67)
            n = e[i--] << (32 - c);
        else {
            n = 0;
            i--;
        }
        if (c < 5) {
            n |= e[i--] << (9 - c);
            c += 23;
        }
        y = (n >> 27) & 0x1f;
        n <<= 5;
        c -= 5;
        XMEMCPY(rt, t[y], sizeof(rt));
        for (; i>=0 || c>=5; ) {
            if (c < 5) {
                n |= e[i--] << (9 - c);
                c += 23;
            }
            y = (n >> 27) & 0x1f;
            n <<= 5;
            c -= 5;

            sp_3072_mont_sqr_67(rt, rt, m, mp);
            sp_3072_mont_sqr_67(rt, rt, m, mp);
            sp_3072_mont_sqr_67(rt, rt, m, mp);
            sp_3072_mont_sqr_67(rt, rt, m, mp);
            sp_3072_mont_sqr_67(rt, rt, m, mp);

            sp_3072_mont_mul_67(rt, rt, t[y], m, mp);
        }

        sp_3072_mont_reduce_67(rt, m, mp);
        n = sp_3072_cmp_67(rt, m);
        sp_3072_cond_sub_67(rt, rt, m, (n < 0) - 1);
        XMEMCPY(r, rt, sizeof(rt));
    }
#if !defined(HAVE_DO178) && defined(WOLFSSL_SMALL_STACK)
    if (td != NULL)
        XFREE(td, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return err;
#endif
}

#endif /* (WOLFSSL_HAVE_SP_RSA || WOLFSSL_HAVE_SP_DH) && !WOLFSSL_RSA_PUBLIC_ONLY */

/* r = 2^n mod m where n is the number of bits to reduce by.
 * Given m must be 3072 bits, just need to subtract.
 *
 * r  A single precision number.
 * m  A signle precision number.
 */
static void sp_3072_mont_norm_134(sp_digit* r, const sp_digit* m)
{
    /* Set r = 2^n - 1. */
#ifdef WOLFSSL_SP_SMALL
    int i;

    for (i=0; i<133; i++)
        r[i] = 0x7fffff;
#else
    int i;

    for (i = 0; i < 128; i += 8) {
        r[i + 0] = 0x7fffff;
        r[i + 1] = 0x7fffff;
        r[i + 2] = 0x7fffff;
        r[i + 3] = 0x7fffff;
        r[i + 4] = 0x7fffff;
        r[i + 5] = 0x7fffff;
        r[i + 6] = 0x7fffff;
        r[i + 7] = 0x7fffff;
    }
    r[128] = 0x7fffff;
    r[129] = 0x7fffff;
    r[130] = 0x7fffff;
    r[131] = 0x7fffff;
    r[132] = 0x7fffff;
#endif
    r[133] = 0x1fffl;

    /* r = (2^n - 1) mod n */
    sp_3072_sub_134(r, r, m);

    /* Add one so r = 2^n mod m */
    r[0] += 1;
}

/* Compare a with b in constant time.
 *
 * a  A single precision integer.
 * b  A single precision integer.
 * return -ve, 0 or +ve if a is less than, equal to or greater than b
 * respectively.
 */
static sp_digit sp_3072_cmp_134(const sp_digit* a, const sp_digit* b)
{
    sp_digit r = 0;
#ifdef WOLFSSL_SP_SMALL
    int i;

    for (i=133; i>=0; i--)
        r |= (a[i] - b[i]) & (0 - !r);
#else
    int i;

    r |= (a[133] - b[133]) & (0 - !r);
    r |= (a[132] - b[132]) & (0 - !r);
    r |= (a[131] - b[131]) & (0 - !r);
    r |= (a[130] - b[130]) & (0 - !r);
    r |= (a[129] - b[129]) & (0 - !r);
    r |= (a[128] - b[128]) & (0 - !r);
    for (i = 120; i >= 0; i -= 8) {
        r |= (a[i + 7] - b[i + 7]) & (0 - !r);
        r |= (a[i + 6] - b[i + 6]) & (0 - !r);
        r |= (a[i + 5] - b[i + 5]) & (0 - !r);
        r |= (a[i + 4] - b[i + 4]) & (0 - !r);
        r |= (a[i + 3] - b[i + 3]) & (0 - !r);
        r |= (a[i + 2] - b[i + 2]) & (0 - !r);
        r |= (a[i + 1] - b[i + 1]) & (0 - !r);
        r |= (a[i + 0] - b[i + 0]) & (0 - !r);
    }
#endif /* WOLFSSL_SP_SMALL */

    return r;
}

/* Conditionally subtract b from a using the mask m.
 * m is -1 to subtract and 0 when not.
 *
 * r  A single precision number representing condition subtract result.
 * a  A single precision number to subtract from.
 * b  A single precision number to subtract.
 * m  Mask value to apply.
 */
static void sp_3072_cond_sub_134(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit m)
{
#ifdef WOLFSSL_SP_SMALL
    int i;

    for (i = 0; i < 134; i++)
        r[i] = a[i] - (b[i] & m);
#else
    int i;

    for (i = 0; i < 128; i += 8) {
        r[i + 0] = a[i + 0] - (b[i + 0] & m);
        r[i + 1] = a[i + 1] - (b[i + 1] & m);
        r[i + 2] = a[i + 2] - (b[i + 2] & m);
        r[i + 3] = a[i + 3] - (b[i + 3] & m);
        r[i + 4] = a[i + 4] - (b[i + 4] & m);
        r[i + 5] = a[i + 5] - (b[i + 5] & m);
        r[i + 6] = a[i + 6] - (b[i + 6] & m);
        r[i + 7] = a[i + 7] - (b[i + 7] & m);
    }
    r[128] = a[128] - (b[128] & m);
    r[129] = a[129] - (b[129] & m);
    r[130] = a[130] - (b[130] & m);
    r[131] = a[131] - (b[131] & m);
    r[132] = a[132] - (b[132] & m);
    r[133] = a[133] - (b[133] & m);
#endif /* WOLFSSL_SP_SMALL */
}

/* Mul a by scalar b and add into r. (r += a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A scalar.
 */
SP_NOINLINE static void sp_3072_mul_add_134(sp_digit* r, const sp_digit* a,
        const sp_digit b)
{
#ifdef WOLFSSL_SP_SMALL
    int64_t tb = b;
    int64_t t = 0;
    int i;

    for (i = 0; i < 134; i++) {
        t += (tb * a[i]) + r[i];
        r[i] = t & 0x7fffff;
        t >>= 23;
    }
    r[134] += t;
#else
    int64_t tb = b;
    int64_t t[8];
    int i;

    t[0] = tb * a[0]; r[0] += t[0] & 0x7fffff;
    for (i = 0; i < 128; i += 8) {
        t[1] = tb * a[i+1];
        r[i+1] += (t[0] >> 23) + (t[1] & 0x7fffff);
        t[2] = tb * a[i+2];
        r[i+2] += (t[1] >> 23) + (t[2] & 0x7fffff);
        t[3] = tb * a[i+3];
        r[i+3] += (t[2] >> 23) + (t[3] & 0x7fffff);
        t[4] = tb * a[i+4];
        r[i+4] += (t[3] >> 23) + (t[4] & 0x7fffff);
        t[5] = tb * a[i+5];
        r[i+5] += (t[4] >> 23) + (t[5] & 0x7fffff);
        t[6] = tb * a[i+6];
        r[i+6] += (t[5] >> 23) + (t[6] & 0x7fffff);
        t[7] = tb * a[i+7];
        r[i+7] += (t[6] >> 23) + (t[7] & 0x7fffff);
        t[0] = tb * a[i+8];
        r[i+8] += (t[7] >> 23) + (t[0] & 0x7fffff);
    }
    t[1] = tb * a[129]; r[129] += (t[0] >> 23) + (t[1] & 0x7fffff);
    t[2] = tb * a[130]; r[130] += (t[1] >> 23) + (t[2] & 0x7fffff);
    t[3] = tb * a[131]; r[131] += (t[2] >> 23) + (t[3] & 0x7fffff);
    t[4] = tb * a[132]; r[132] += (t[3] >> 23) + (t[4] & 0x7fffff);
    t[5] = tb * a[133]; r[133] += (t[4] >> 23) + (t[5] & 0x7fffff);
    r[134] +=  t[5] >> 23;
#endif /* WOLFSSL_SP_SMALL */
}

/* Normalize the values in each word to 23.
 *
 * a  Array of sp_digit to normalize.
 */
static void sp_3072_norm_134(sp_digit* a)
{
#ifdef WOLFSSL_SP_SMALL
    int i;
    for (i = 0; i < 133; i++) {
        a[i+1] += a[i] >> 23;
        a[i] &= 0x7fffff;
    }
#else
    int i;
    for (i = 0; i < 128; i += 8) {
        a[i+1] += a[i+0] >> 23; a[i+0] &= 0x7fffff;
        a[i+2] += a[i+1] >> 23; a[i+1] &= 0x7fffff;
        a[i+3] += a[i+2] >> 23; a[i+2] &= 0x7fffff;
        a[i+4] += a[i+3] >> 23; a[i+3] &= 0x7fffff;
        a[i+5] += a[i+4] >> 23; a[i+4] &= 0x7fffff;
        a[i+6] += a[i+5] >> 23; a[i+5] &= 0x7fffff;
        a[i+7] += a[i+6] >> 23; a[i+6] &= 0x7fffff;
        a[i+8] += a[i+7] >> 23; a[i+7] &= 0x7fffff;
        a[i+9] += a[i+8] >> 23; a[i+8] &= 0x7fffff;
    }
    a[128+1] += a[128] >> 23;
    a[128] &= 0x7fffff;
    a[129+1] += a[129] >> 23;
    a[129] &= 0x7fffff;
    a[130+1] += a[130] >> 23;
    a[130] &= 0x7fffff;
    a[131+1] += a[131] >> 23;
    a[131] &= 0x7fffff;
    a[132+1] += a[132] >> 23;
    a[132] &= 0x7fffff;
#endif
}

/* Shift the result in the high 3072 bits down to the bottom.
 *
 * r  A single precision number.
 * a  A single precision number.
 */
static void sp_3072_mont_shift_134(sp_digit* r, const sp_digit* a)
{
#ifdef WOLFSSL_SP_SMALL
    int i;
    int64_t n = a[133] >> 13;
    n += ((int64_t)a[134]) << 10;

    for (i = 0; i < 133; i++) {
        r[i] = n & 0x7fffff;
        n >>= 23;
        n += ((int64_t)a[135 + i]) << 10;
    }
    r[133] = (sp_digit)n;
#else
    int i;
    int64_t n = a[133] >> 13;
    n += ((int64_t)a[134]) << 10;
    for (i = 0; i < 128; i += 8) {
        r[i + 0] = n & 0x7fffff;
        n >>= 23; n += ((int64_t)a[i + 135]) << 10;
        r[i + 1] = n & 0x7fffff;
        n >>= 23; n += ((int64_t)a[i + 136]) << 10;
        r[i + 2] = n & 0x7fffff;
        n >>= 23; n += ((int64_t)a[i + 137]) << 10;
        r[i + 3] = n & 0x7fffff;
        n >>= 23; n += ((int64_t)a[i + 138]) << 10;
        r[i + 4] = n & 0x7fffff;
        n >>= 23; n += ((int64_t)a[i + 139]) << 10;
        r[i + 5] = n & 0x7fffff;
        n >>= 23; n += ((int64_t)a[i + 140]) << 10;
        r[i + 6] = n & 0x7fffff;
        n >>= 23; n += ((int64_t)a[i + 141]) << 10;
        r[i + 7] = n & 0x7fffff;
        n >>= 23; n += ((int64_t)a[i + 142]) << 10;
    }
    r[128] = n & 0x7fffff; n >>= 23; n += ((int64_t)a[263]) << 10;
    r[129] = n & 0x7fffff; n >>= 23; n += ((int64_t)a[264]) << 10;
    r[130] = n & 0x7fffff; n >>= 23; n += ((int64_t)a[265]) << 10;
    r[131] = n & 0x7fffff; n >>= 23; n += ((int64_t)a[266]) << 10;
    r[132] = n & 0x7fffff; n >>= 23; n += ((int64_t)a[267]) << 10;
    r[133] = (sp_digit)n;
#endif /* WOLFSSL_SP_SMALL */
    XMEMSET(&r[134], 0, sizeof(*r) * 134);
}

/* Reduce the number back to 3072 bits using Montgomery reduction.
 *
 * a   A single precision number to reduce in place.
 * m   The single precision number representing the modulus.
 * mp  The digit representing the negative inverse of m mod 2^n.
 */
static void sp_3072_mont_reduce_134(sp_digit* a, const sp_digit* m, sp_digit mp)
{
    int i;
    sp_digit mu;

#ifdef WOLFSSL_SP_DH
    if (mp != 1) {
        for (i=0; i<133; i++) {
            mu = (a[i] * mp) & 0x7fffff;
            sp_3072_mul_add_134(a+i, m, mu);
            a[i+1] += a[i] >> 23;
        }
        mu = (a[i] * mp) & 0x1fffl;
        sp_3072_mul_add_134(a+i, m, mu);
        a[i+1] += a[i] >> 23;
        a[i] &= 0x7fffff;
    }
    else {
        for (i=0; i<133; i++) {
            mu = a[i] & 0x7fffff;
            sp_3072_mul_add_134(a+i, m, mu);
            a[i+1] += a[i] >> 23;
        }
        mu = a[i] & 0x1fffl;
        sp_3072_mul_add_134(a+i, m, mu);
        a[i+1] += a[i] >> 23;
        a[i] &= 0x7fffff;
    }
#else
    for (i=0; i<133; i++) {
        mu = (a[i] * mp) & 0x7fffff;
        sp_3072_mul_add_134(a+i, m, mu);
        a[i+1] += a[i] >> 23;
    }
    mu = (a[i] * mp) & 0x1fffl;
    sp_3072_mul_add_134(a+i, m, mu);
    a[i+1] += a[i] >> 23;
    a[i] &= 0x7fffff;
#endif

    sp_3072_mont_shift_134(a, a);
    sp_3072_cond_sub_134(a, a, m, 0 - ((a[133] >> 13) > 0));
    sp_3072_norm_134(a);
}

/* Multiply two Montogmery form numbers mod the modulus (prime).
 * (r = a * b mod m)
 *
 * r   Result of multiplication.
 * a   First number to multiply in Montogmery form.
 * b   Second number to multiply in Montogmery form.
 * m   Modulus (prime).
 * mp  Montogmery mulitplier.
 */
static void sp_3072_mont_mul_134(sp_digit* r, const sp_digit* a, const sp_digit* b,
        const sp_digit* m, sp_digit mp)
{
    sp_3072_mul_134(r, a, b);
    sp_3072_mont_reduce_134(r, m, mp);
}

/* Square the Montgomery form number. (r = a * a mod m)
 *
 * r   Result of squaring.
 * a   Number to square in Montogmery form.
 * m   Modulus (prime).
 * mp  Montogmery mulitplier.
 */
static void sp_3072_mont_sqr_134(sp_digit* r, const sp_digit* a, const sp_digit* m,
        sp_digit mp)
{
    sp_3072_sqr_134(r, a);
    sp_3072_mont_reduce_134(r, m, mp);
}

/* Multiply a by scalar b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A scalar.
 */
SP_NOINLINE static void sp_3072_mul_d_268(sp_digit* r, const sp_digit* a,
    sp_digit b)
{
#ifdef WOLFSSL_SP_SMALL
    int64_t tb = b;
    int64_t t = 0;
    int i;

    for (i = 0; i < 268; i++) {
        t += tb * a[i];
        r[i] = t & 0x7fffff;
        t >>= 23;
    }
    r[268] = (sp_digit)t;
#else
    int64_t tb = b;
    int64_t t[8];
    int i;

    t[0] = tb * a[0]; r[0] = t[0] & 0x7fffff;
    for (i = 0; i < 264; i += 8) {
        t[1] = tb * a[i+1];
        r[i+1] = (sp_digit)(t[0] >> 23) + (t[1] & 0x7fffff);
        t[2] = tb * a[i+2];
        r[i+2] = (sp_digit)(t[1] >> 23) + (t[2] & 0x7fffff);
        t[3] = tb * a[i+3];
        r[i+3] = (sp_digit)(t[2] >> 23) + (t[3] & 0x7fffff);
        t[4] = tb * a[i+4];
        r[i+4] = (sp_digit)(t[3] >> 23) + (t[4] & 0x7fffff);
        t[5] = tb * a[i+5];
        r[i+5] = (sp_digit)(t[4] >> 23) + (t[5] & 0x7fffff);
        t[6] = tb * a[i+6];
        r[i+6] = (sp_digit)(t[5] >> 23) + (t[6] & 0x7fffff);
        t[7] = tb * a[i+7];
        r[i+7] = (sp_digit)(t[6] >> 23) + (t[7] & 0x7fffff);
        t[0] = tb * a[i+8];
        r[i+8] = (sp_digit)(t[7] >> 23) + (t[0] & 0x7fffff);
    }
    t[1] = tb * a[265];
    r[265] = (sp_digit)(t[0] >> 23) + (t[1] & 0x7fffff);
    t[2] = tb * a[266];
    r[266] = (sp_digit)(t[1] >> 23) + (t[2] & 0x7fffff);
    t[3] = tb * a[267];
    r[267] = (sp_digit)(t[2] >> 23) + (t[3] & 0x7fffff);
    r[268] =  (sp_digit)(t[3] >> 23);
#endif /* WOLFSSL_SP_SMALL */
}

/* Conditionally add a and b using the mask m.
 * m is -1 to add and 0 when not.
 *
 * r  A single precision number representing conditional add result.
 * a  A single precision number to add with.
 * b  A single precision number to add.
 * m  Mask value to apply.
 */
static void sp_3072_cond_add_134(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit m)
{
#ifdef WOLFSSL_SP_SMALL
    int i;

    for (i = 0; i < 134; i++)
        r[i] = a[i] + (b[i] & m);
#else
    int i;

    for (i = 0; i < 128; i += 8) {
        r[i + 0] = a[i + 0] + (b[i + 0] & m);
        r[i + 1] = a[i + 1] + (b[i + 1] & m);
        r[i + 2] = a[i + 2] + (b[i + 2] & m);
        r[i + 3] = a[i + 3] + (b[i + 3] & m);
        r[i + 4] = a[i + 4] + (b[i + 4] & m);
        r[i + 5] = a[i + 5] + (b[i + 5] & m);
        r[i + 6] = a[i + 6] + (b[i + 6] & m);
        r[i + 7] = a[i + 7] + (b[i + 7] & m);
    }
    r[128] = a[128] + (b[128] & m);
    r[129] = a[129] + (b[129] & m);
    r[130] = a[130] + (b[130] & m);
    r[131] = a[131] + (b[131] & m);
    r[132] = a[132] + (b[132] & m);
    r[133] = a[133] + (b[133] & m);
#endif /* WOLFSSL_SP_SMALL */
}

#ifdef WOLFSSL_SMALL
/* Sub b from a into r. (r = a - b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_3072_sub_134(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 134; i++)
        r[i] = a[i] - b[i];

    return 0;
}

#endif
#ifdef WOLFSSL_SMALL
/* Add b to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_3072_add_134(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 134; i++)
        r[i] = a[i] + b[i];

    return 0;
}
#endif
SP_NOINLINE static void sp_3072_rshift_134(sp_digit* r, sp_digit* a, byte n)
{
    int i;

#ifdef WOLFSSL_SP_SMALL
    for (i=0; i<133; i++)
        r[i] = ((a[i] >> n) | (a[i + 1] << (23 - n))) & 0x7fffff;
#else
    for (i=0; i<128; i += 8) {
        r[i+0] = ((a[i+0] >> n) | (a[i+1] << (23 - n))) & 0x7fffff;
        r[i+1] = ((a[i+1] >> n) | (a[i+2] << (23 - n))) & 0x7fffff;
        r[i+2] = ((a[i+2] >> n) | (a[i+3] << (23 - n))) & 0x7fffff;
        r[i+3] = ((a[i+3] >> n) | (a[i+4] << (23 - n))) & 0x7fffff;
        r[i+4] = ((a[i+4] >> n) | (a[i+5] << (23 - n))) & 0x7fffff;
        r[i+5] = ((a[i+5] >> n) | (a[i+6] << (23 - n))) & 0x7fffff;
        r[i+6] = ((a[i+6] >> n) | (a[i+7] << (23 - n))) & 0x7fffff;
        r[i+7] = ((a[i+7] >> n) | (a[i+8] << (23 - n))) & 0x7fffff;
    }
    r[128] = ((a[128] >> n) | (a[129] << (23 - n))) & 0x7fffff;
    r[129] = ((a[129] >> n) | (a[130] << (23 - n))) & 0x7fffff;
    r[130] = ((a[130] >> n) | (a[131] << (23 - n))) & 0x7fffff;
    r[131] = ((a[131] >> n) | (a[132] << (23 - n))) & 0x7fffff;
    r[132] = ((a[132] >> n) | (a[133] << (23 - n))) & 0x7fffff;
#endif
    r[133] = a[133] >> n;
}

#ifdef WOLFSSL_SP_DIV_32
static WC_INLINE sp_digit sp_3072_div_word_134(sp_digit d1, sp_digit d0,
    sp_digit div)
{
    sp_digit d, r, t;

    /* All 23 bits from d1 and top 8 bits from d0. */
    d = (d1 << 8) | (d0 >> 15);
    r = d / div;
    d -= r * div;
    /* Up to 9 bits in r */
    /* Next 8 bits from d0. */
    r <<= 8;
    d <<= 8;
    d |= (d0 >> 7) & ((1 << 8) - 1);
    t = d / div;
    d -= t * div;
    r += t;
    /* Up to 17 bits in r */
    /* Remaining 7 bits from d0. */
    r <<= 7;
    d <<= 7;
    d |= d0 & ((1 << 7) - 1);
    t = d / div;
    r += t;

    return r;
}
#endif /* WOLFSSL_SP_DIV_32 */

/* Divide d in a and put remainder into r (m*d + r = a)
 * m is not calculated as it is not needed at this time.
 *
 * a  Nmber to be divided.
 * d  Number to divide with.
 * m  Multiplier result.
 * r  Remainder from the division.
 * returns MEMORY_E when unable to allocate memory and MP_OKAY otherwise.
 */
static int sp_3072_div_134(const sp_digit* a, const sp_digit* d, sp_digit* m,
        sp_digit* r)
{
    int i;
#ifndef WOLFSSL_SP_DIV_32
    int64_t d1;
#endif
    sp_digit div, r1;
#if !defined(HAVE_DO178) && (defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK))
    sp_digit* td;
#else
    sp_digit t1d[268 + 1], t2d[134 + 1], sdd[134 + 1];
#endif
    sp_digit* t1;
    sp_digit* t2;
    sp_digit* sd;
    int err = MP_OKAY;

#if !defined(HAVE_DO178) && (defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK))
    td = (sp_digit*)XMALLOC(sizeof(sp_digit) * (4 * 134 + 3), NULL,
                                                       DYNAMIC_TYPE_TMP_BUFFER);
    if (td != NULL) {
        t1 = td;
        t2 = td + 268 + 1;
        sd = t2 + 134 + 1;
    }
    else
        err = MEMORY_E;
#else
    t1 = t1d;
    t2 = t2d;
    sd = sdd;
#endif

    (void)m;

    if (err == MP_OKAY) {
        sp_3072_mul_d_134(sd, d, 1 << 10);
        sp_3072_mul_d_268(t1, a, 1 << 10);
        div = sd[133];
        for (i=134; i>=0; i--) {
            t1[134 + i] += t1[134 + i - 1] >> 23;
            t1[134 + i - 1] &= 0x7fffff;
#ifndef WOLFSSL_SP_DIV_32
            d1 = t1[134 + i];
            d1 <<= 23;
            d1 += t1[134 + i - 1];
            r1 = (sp_digit)(d1 / div);
#else
            r1 = sp_3072_div_word_134(t1[134 + i], t1[134 + i - 1], div);
#endif

            sp_3072_mul_d_134(t2, sd, r1);
            sp_3072_sub_134(&t1[i], &t1[i], t2);
            t1[134 + i] -= t2[134];
            t1[134 + i] += t1[134 + i - 1] >> 23;
            t1[134 + i - 1] &= 0x7fffff;
            r1 = (((-t1[134 + i]) << 23) - t1[134 + i - 1]) / div;
            r1 -= t1[134 + i];
            sp_3072_mul_d_134(t2, sd, r1);
            sp_3072_add_134(&t1[i], &t1[i], t2);
            t1[134 + i] += t1[134 + i - 1] >> 23;
            t1[134 + i - 1] &= 0x7fffff;
        }
        t1[134 - 1] += t1[134 - 2] >> 23;
        t1[134 - 2] &= 0x7fffff;
        r1 = t1[134 - 1] / div;

        sp_3072_mul_d_134(t2, sd, r1);
        sp_3072_sub_134(t1, t1, t2);
        XMEMCPY(r, t1, sizeof(*r) * 2 * 134);
        for (i=0; i<132; i++) {
            r[i+1] += r[i] >> 23;
            r[i] &= 0x7fffff;
        }
        sp_3072_cond_add_134(r, r, sd, 0 - (r[133] < 0));
    }

    sp_3072_norm_134(r);
    sp_3072_rshift_134(r, r, 10);

#if !defined(HAVE_DO178) && (defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK))
    if (td != NULL)
        XFREE(td, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return err;
}

/* Reduce a modulo m into r. (r = a mod m)
 *
 * r  A single precision number that is the reduced result.
 * a  A single precision number that is to be reduced.
 * m  A single precision number that is the modulus to reduce with.
 * returns MEMORY_E when unable to allocate memory and MP_OKAY otherwise.
 */
static int sp_3072_mod_134(sp_digit* r, const sp_digit* a, const sp_digit* m)
{
    return sp_3072_div_134(a, m, NULL, r);
}

#if (defined(WOLFSSL_HAVE_SP_RSA) && !defined(WOLFSSL_RSA_PUBLIC_ONLY)) || \
                                                     defined(WOLFSSL_HAVE_SP_DH)
/* Modular exponentiate a to the e mod m. (r = a^e mod m)
 *
 * r     A single precision number that is the result of the operation.
 * a     A single precision number being exponentiated.
 * e     A single precision number that is the exponent.
 * bits  The number of bits in the exponent.
 * m     A single precision number that is the modulus.
 * returns 0 on success and MEMORY_E on dynamic memory allocation failure.
 */
static int sp_3072_mod_exp_134(sp_digit* r, const sp_digit* a, const sp_digit* e, int bits,
    const sp_digit* m, int reduceA)
{
#ifdef WOLFSSL_SP_SMALL
    sp_digit* td;
    sp_digit* t[3];
    sp_digit* norm;
    sp_digit mp = 1;
    sp_digit n;
    int i;
    int c, y;
    int err = MP_OKAY;

    td = (sp_digit*)XMALLOC(sizeof(*td) * 3 * 134 * 2, NULL,
                            DYNAMIC_TYPE_TMP_BUFFER);
    if (td == NULL)
        err = MEMORY_E;

    if (err == MP_OKAY) {
        XMEMSET(td, 0, sizeof(*td) * 3 * 134 * 2);

        norm = t[0] = td;
        t[1] = &td[134 * 2];
        t[2] = &td[2 * 134 * 2];

        sp_3072_mont_setup(m, &mp);
        sp_3072_mont_norm_134(norm, m);

        if (reduceA)
            err = sp_3072_mod_134(t[1], a, m);
        else
            XMEMCPY(t[1], a, sizeof(sp_digit) * 134);
    }
    if (err == MP_OKAY) {
        sp_3072_mul_134(t[1], t[1], norm);
        err = sp_3072_mod_134(t[1], t[1], m);
    }

    if (err == MP_OKAY) {
        i = bits / 23;
        c = bits % 23;
        n = e[i--] << (23 - c);
        for (; ; c--) {
            if (c == 0) {
                if (i == -1)
                    break;

                n = e[i--];
                c = 23;
            }

            y = (n >> 22) & 1;
            n <<= 1;

            sp_3072_mont_mul_134(t[y^1], t[0], t[1], m, mp);

            XMEMCPY(t[2], (void*)(((size_t)t[0] & addr_mask[y^1]) +
                                  ((size_t)t[1] & addr_mask[y])),
                    sizeof(*t[2]) * 134 * 2);
            sp_3072_mont_sqr_134(t[2], t[2], m, mp);
            XMEMCPY((void*)(((size_t)t[0] & addr_mask[y^1]) +
                            ((size_t)t[1] & addr_mask[y])), t[2],
                    sizeof(*t[2]) * 134 * 2);
        }

        sp_3072_mont_reduce_134(t[0], m, mp);
        n = sp_3072_cmp_134(t[0], m);
        sp_3072_cond_sub_134(t[0], t[0], m, (n < 0) - 1);
        XMEMCPY(r, t[0], sizeof(*r) * 134 * 2);

    }

    if (td != NULL)
        XFREE(td, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    return err;
#elif defined(WOLFSSL_SP_CACHE_RESISTANT)
#if defined(HAVE_DO178) || !defined(WOLFSSL_SMALL_STACK)
    sp_digit t[3][268];
#else
    sp_digit* td;
    sp_digit* t[3];
#endif
    sp_digit* norm;
    sp_digit mp = 1;
    sp_digit n;
    int i;
    int c, y;
    int err = MP_OKAY;

#if !defined(HAVE_DO178) && defined(WOLFSSL_SMALL_STACK)
    td = (sp_digit*)XMALLOC(sizeof(*td) * 3 * 134 * 2, NULL,
                            DYNAMIC_TYPE_TMP_BUFFER);
    if (td == NULL)
        err = MEMORY_E;

    if (err == MP_OKAY) {
        t[0] = td;
        t[1] = &td[134 * 2];
        t[2] = &td[2 * 134 * 2];
        norm = t[0];
    }
#else
    norm = t[0];
#endif

    if (err == MP_OKAY) {
        sp_3072_mont_setup(m, &mp);
        sp_3072_mont_norm_134(norm, m);

        if (reduceA) {
            err = sp_3072_mod_134(t[1], a, m);
            if (err == MP_OKAY) {
                sp_3072_mul_134(t[1], t[1], norm);
                err = sp_3072_mod_134(t[1], t[1], m);
            }
        }
        else {
            sp_3072_mul_134(t[1], a, norm);
            err = sp_3072_mod_134(t[1], t[1], m);
        }
    }

    if (err == MP_OKAY) {
        i = bits / 23;
        c = bits % 23;
        n = e[i--] << (23 - c);
        for (; ; c--) {
            if (c == 0) {
                if (i == -1)
                    break;

                n = e[i--];
                c = 23;
            }

            y = (n >> 22) & 1;
            n <<= 1;

            sp_3072_mont_mul_134(t[y^1], t[0], t[1], m, mp);

            XMEMCPY(t[2], (void*)(((size_t)t[0] & addr_mask[y^1]) +
                                 ((size_t)t[1] & addr_mask[y])), sizeof(t[2]));
            sp_3072_mont_sqr_134(t[2], t[2], m, mp);
            XMEMCPY((void*)(((size_t)t[0] & addr_mask[y^1]) +
                           ((size_t)t[1] & addr_mask[y])), t[2], sizeof(t[2]));
        }

        sp_3072_mont_reduce_134(t[0], m, mp);
        n = sp_3072_cmp_134(t[0], m);
        sp_3072_cond_sub_134(t[0], t[0], m, (n < 0) - 1);
        XMEMCPY(r, t[0], sizeof(t[0]));
    }

#if !defined(HAVE_DO178) && defined(WOLFSSL_SMALL_STACK)
    if (td != NULL)
        XFREE(td, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return err;
#else
#if defined(HAVE_DO178) || !defined(WOLFSSL_SMALL_STACK)
    sp_digit t[32][268];
#else
    sp_digit* t[32];
    sp_digit* td;
#endif
    sp_digit* norm;
    sp_digit rt[268];
    sp_digit mp = 1;
    sp_digit n;
    int i;
    int c, y;
    int err = MP_OKAY;

#if !defined(HAVE_DO178) && defined(WOLFSSL_SMALL_STACK)
    td = (sp_digit*)XMALLOC(sizeof(sp_digit) * 32 * 268, NULL,
                            DYNAMIC_TYPE_TMP_BUFFER);
    if (td == NULL)
        err = MEMORY_E;

    if (err == MP_OKAY) {
        for (i=0; i<32; i++)
            t[i] = td + i * 268;
        norm = t[0];
    }
#else
    norm = t[0];
#endif

    if (err == MP_OKAY) {
        sp_3072_mont_setup(m, &mp);
        sp_3072_mont_norm_134(norm, m);

        if (reduceA) {
            err = sp_3072_mod_134(t[1], a, m);
            if (err == MP_OKAY) {
                sp_3072_mul_134(t[1], t[1], norm);
                err = sp_3072_mod_134(t[1], t[1], m);
            }
        }
        else {
            sp_3072_mul_134(t[1], a, norm);
            err = sp_3072_mod_134(t[1], t[1], m);
        }
    }

    if (err == MP_OKAY) {
        sp_3072_mont_sqr_134(t[ 2], t[ 1], m, mp);
        sp_3072_mont_mul_134(t[ 3], t[ 2], t[ 1], m, mp);
        sp_3072_mont_sqr_134(t[ 4], t[ 2], m, mp);
        sp_3072_mont_mul_134(t[ 5], t[ 3], t[ 2], m, mp);
        sp_3072_mont_sqr_134(t[ 6], t[ 3], m, mp);
        sp_3072_mont_mul_134(t[ 7], t[ 4], t[ 3], m, mp);
        sp_3072_mont_sqr_134(t[ 8], t[ 4], m, mp);
        sp_3072_mont_mul_134(t[ 9], t[ 5], t[ 4], m, mp);
        sp_3072_mont_sqr_134(t[10], t[ 5], m, mp);
        sp_3072_mont_mul_134(t[11], t[ 6], t[ 5], m, mp);
        sp_3072_mont_sqr_134(t[12], t[ 6], m, mp);
        sp_3072_mont_mul_134(t[13], t[ 7], t[ 6], m, mp);
        sp_3072_mont_sqr_134(t[14], t[ 7], m, mp);
        sp_3072_mont_mul_134(t[15], t[ 8], t[ 7], m, mp);
        sp_3072_mont_sqr_134(t[16], t[ 8], m, mp);
        sp_3072_mont_mul_134(t[17], t[ 9], t[ 8], m, mp);
        sp_3072_mont_sqr_134(t[18], t[ 9], m, mp);
        sp_3072_mont_mul_134(t[19], t[10], t[ 9], m, mp);
        sp_3072_mont_sqr_134(t[20], t[10], m, mp);
        sp_3072_mont_mul_134(t[21], t[11], t[10], m, mp);
        sp_3072_mont_sqr_134(t[22], t[11], m, mp);
        sp_3072_mont_mul_134(t[23], t[12], t[11], m, mp);
        sp_3072_mont_sqr_134(t[24], t[12], m, mp);
        sp_3072_mont_mul_134(t[25], t[13], t[12], m, mp);
        sp_3072_mont_sqr_134(t[26], t[13], m, mp);
        sp_3072_mont_mul_134(t[27], t[14], t[13], m, mp);
        sp_3072_mont_sqr_134(t[28], t[14], m, mp);
        sp_3072_mont_mul_134(t[29], t[15], t[14], m, mp);
        sp_3072_mont_sqr_134(t[30], t[15], m, mp);
        sp_3072_mont_mul_134(t[31], t[16], t[15], m, mp);

        bits = ((bits + 4) / 5) * 5;
        i = ((bits + 22) / 23) - 1;
        c = bits % 23;
        if (c == 0)
            c = 23;
        if (i < 134)
            n = e[i--] << (32 - c);
        else {
            n = 0;
            i--;
        }
        if (c < 5) {
            n |= e[i--] << (9 - c);
            c += 23;
        }
        y = (n >> 27) & 0x1f;
        n <<= 5;
        c -= 5;
        XMEMCPY(rt, t[y], sizeof(rt));
        for (; i>=0 || c>=5; ) {
            if (c < 5) {
                n |= e[i--] << (9 - c);
                c += 23;
            }
            y = (n >> 27) & 0x1f;
            n <<= 5;
            c -= 5;

            sp_3072_mont_sqr_134(rt, rt, m, mp);
            sp_3072_mont_sqr_134(rt, rt, m, mp);
            sp_3072_mont_sqr_134(rt, rt, m, mp);
            sp_3072_mont_sqr_134(rt, rt, m, mp);
            sp_3072_mont_sqr_134(rt, rt, m, mp);

            sp_3072_mont_mul_134(rt, rt, t[y], m, mp);
        }

        sp_3072_mont_reduce_134(rt, m, mp);
        n = sp_3072_cmp_134(rt, m);
        sp_3072_cond_sub_134(rt, rt, m, (n < 0) - 1);
        XMEMCPY(r, rt, sizeof(rt));
    }
#if !defined(HAVE_DO178) && defined(WOLFSSL_SMALL_STACK)
    if (td != NULL)
        XFREE(td, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return err;
#endif
}
#endif /* (WOLFSSL_HAVE_SP_RSA && !WOLFSSL_RSA_PUBLIC_ONLY) || */
       /* WOLFSSL_HAVE_SP_DH */

#if defined(WOLFSSL_HAVE_SP_RSA) && !defined(SP_RSA_PRIVATE_EXP_D) && \
           !defined(RSA_LOW_MEM) && !defined(WOLFSSL_RSA_PUBLIC_ONLY)
/* AND m into each word of a and store in r.
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * m  Mask to AND against each digit.
 */
static void sp_3072_mask_67(sp_digit* r, const sp_digit* a, sp_digit m)
{
#ifdef WOLFSSL_SP_SMALL
    int i;

    for (i=0; i<67; i++)
        r[i] = a[i] & m;
#else
    int i;

    for (i = 0; i < 64; i += 8) {
        r[i+0] = a[i+0] & m;
        r[i+1] = a[i+1] & m;
        r[i+2] = a[i+2] & m;
        r[i+3] = a[i+3] & m;
        r[i+4] = a[i+4] & m;
        r[i+5] = a[i+5] & m;
        r[i+6] = a[i+6] & m;
        r[i+7] = a[i+7] & m;
    }
    r[64] = a[64] & m;
    r[65] = a[65] & m;
    r[66] = a[66] & m;
#endif
}

#endif
#ifdef WOLFSSL_HAVE_SP_RSA
/* RSA public key operation.
 *
 * in      Array of bytes representing the number to exponentiate, base.
 * inLen   Number of bytes in base.
 * em      Public exponent.
 * mm      Modulus.
 * out     Buffer to hold big-endian bytes of exponentiation result.
 *         Must be at least 384 bytes long.
 * outLen  Number of bytes in result.
 * returns 0 on success, MP_TO_E when the outLen is too small, MP_READ_E when
 * an array is too long and MEMORY_E when dynamic memory allocation fails.
 */
int sp_RsaPublic_3072(const byte* in, word32 inLen, mp_int* em, mp_int* mm,
    byte* out, word32* outLen)
{
#ifdef WOLFSSL_SP_SMALL
    sp_digit* d = NULL;
    sp_digit* a;
    sp_digit* m;
    sp_digit* r;
    sp_digit* norm;
    sp_digit e[1];
    sp_digit mp;
    int i;
    int err = MP_OKAY;

    if (*outLen < 384)
        err = MP_TO_E;
    if (err == MP_OKAY && (mp_count_bits(em) > 23 || inLen > 384 ||
                                                     mp_count_bits(mm) != 3072))
        err = MP_READ_E;

    if (err == MP_OKAY) {
        d = (sp_digit*)XMALLOC(sizeof(sp_digit) * 134 * 5, NULL,
                                                              DYNAMIC_TYPE_RSA);
        if (d == NULL)
            err = MEMORY_E;
    }

    if (err == MP_OKAY) {
        a = d;
        r = a + 134 * 2;
        m = r + 134 * 2;
        norm = r;

        sp_3072_from_bin(a, 134, in, inLen);
#if DIGIT_BIT >= 23
        e[0] = (sp_digit)em->dp[0];
#else
        e[0] = (sp_digit)em->dp[0];
        if (em->used > 1)
            e[0] |= ((sp_digit)em->dp[1]) << DIGIT_BIT;
#endif
        if (e[0] == 0)
            err = MP_EXPTMOD_E;
    }

    if (err == MP_OKAY) {
        sp_3072_from_mp(m, 134, mm);

        sp_3072_mont_setup(m, &mp);
        sp_3072_mont_norm_134(norm, m);
    }
    if (err == MP_OKAY) {
        sp_3072_mul_134(a, a, norm);
        err = sp_3072_mod_134(a, a, m);
    }
    if (err == MP_OKAY) {
        for (i=22; i>=0; i--)
            if (e[0] >> i)
                break;

        XMEMCPY(r, a, sizeof(sp_digit) * 134 * 2);
        for (i--; i>=0; i--) {
            sp_3072_mont_sqr_134(r, r, m, mp);

            if (((e[0] >> i) & 1) == 1)
                sp_3072_mont_mul_134(r, r, a, m, mp);
        }
        sp_3072_mont_reduce_134(r, m, mp);
        mp = sp_3072_cmp_134(r, m);
        sp_3072_cond_sub_134(r, r, m, (mp < 0) - 1);

        sp_3072_to_bin(r, out);
        *outLen = 384;
    }

    if (d != NULL)
        XFREE(d, NULL, DYNAMIC_TYPE_RSA);

    return err;
#else
#if defined(HAVE_DO178) || (!defined(WOLFSSL_SP_SMALL) && !defined(WOLFSSL_SMALL_STACK))
    sp_digit ad[268], md[134], rd[268];
#else
    sp_digit* d = NULL;
#endif
    sp_digit* a;
    sp_digit* m;
    sp_digit* r;
    sp_digit e[1];
    int err = MP_OKAY;

    if (*outLen < 384)
        err = MP_TO_E;
    if (err == MP_OKAY && (mp_count_bits(em) > 23 || inLen > 384 ||
                                                     mp_count_bits(mm) != 3072))
        err = MP_READ_E;

#if !defined(HAVE_DO178) && (defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK))
    if (err == MP_OKAY) {
        d = (sp_digit*)XMALLOC(sizeof(sp_digit) * 134 * 5, NULL,
                                                              DYNAMIC_TYPE_RSA);
        if (d == NULL)
            err = MEMORY_E;
    }

    if (err == MP_OKAY) {
        a = d;
        r = a + 134 * 2;
        m = r + 134 * 2;
    }
#else
    a = ad;
    m = md;
    r = rd;
#endif

    if (err == MP_OKAY) {
        sp_3072_from_bin(a, 134, in, inLen);
#if DIGIT_BIT >= 23
        e[0] = (sp_digit)em->dp[0];
#else
        e[0] = (sp_digit)em->dp[0];
        if (em->used > 1)
            e[0] |= ((sp_digit)em->dp[1]) << DIGIT_BIT;
#endif
        if (e[0] == 0)
            err = MP_EXPTMOD_E;
    }
    if (err == MP_OKAY) {
        sp_3072_from_mp(m, 134, mm);

        if (e[0] == 0x3) {
            if (err == MP_OKAY) {
                sp_3072_sqr_134(r, a);
                err = sp_3072_mod_134(r, r, m);
            }
            if (err == MP_OKAY) {
                sp_3072_mul_134(r, a, r);
                err = sp_3072_mod_134(r, r, m);
            }
        }
        else {
            sp_digit* norm = r;
            int i;
            sp_digit mp;

            sp_3072_mont_setup(m, &mp);
            sp_3072_mont_norm_134(norm, m);

            if (err == MP_OKAY) {
                sp_3072_mul_134(a, a, norm);
                err = sp_3072_mod_134(a, a, m);
            }

            if (err == MP_OKAY) {
                for (i=22; i>=0; i--)
                    if (e[0] >> i)
                        break;

                XMEMCPY(r, a, sizeof(sp_digit) * 268);
                for (i--; i>=0; i--) {
                    sp_3072_mont_sqr_134(r, r, m, mp);

                    if (((e[0] >> i) & 1) == 1)
                        sp_3072_mont_mul_134(r, r, a, m, mp);
                }
                sp_3072_mont_reduce_134(r, m, mp);
                mp = sp_3072_cmp_134(r, m);
                sp_3072_cond_sub_134(r, r, m, (mp < 0) - 1);
            }
        }
    }

    if (err == MP_OKAY) {
        sp_3072_to_bin(r, out);
        *outLen = 384;
    }

#if !defined(HAVE_DO178) && (defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK))
    if (d != NULL)
        XFREE(d, NULL, DYNAMIC_TYPE_RSA);
#endif

    return err;
#endif /* WOLFSSL_SP_SMALL */
}

#ifndef WOLFSSL_RSA_PUBLIC_ONLY
/* RSA private key operation.
 *
 * in      Array of bytes representing the number to exponentiate, base.
 * inLen   Number of bytes in base.
 * dm      Private exponent.
 * pm      First prime.
 * qm      Second prime.
 * dpm     First prime's CRT exponent.
 * dqm     Second prime's CRT exponent.
 * qim     Inverse of second prime mod p.
 * mm      Modulus.
 * out     Buffer to hold big-endian bytes of exponentiation result.
 *         Must be at least 384 bytes long.
 * outLen  Number of bytes in result.
 * returns 0 on success, MP_TO_E when the outLen is too small, MP_READ_E when
 * an array is too long and MEMORY_E when dynamic memory allocation fails.
 */
int sp_RsaPrivate_3072(const byte* in, word32 inLen, mp_int* dm,
    mp_int* pm, mp_int* qm, mp_int* dpm, mp_int* dqm, mp_int* qim, mp_int* mm,
    byte* out, word32* outLen)
{
#if defined(SP_RSA_PRIVATE_EXP_D) || defined(RSA_LOW_MEM)
#if !defined(HAVE_DO178) && \
    (defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK))
    sp_digit* a;
    sp_digit* d = NULL;
    sp_digit* m;
    sp_digit* r;
    int err = MP_OKAY;

    (void)pm;
    (void)qm;
    (void)dpm;
    (void)dqm;
    (void)qim;

    if (*outLen < 384)
        err = MP_TO_E;
    if (err == MP_OKAY && (mp_count_bits(dm) > 3072 || inLen > 384 ||
                                                     mp_count_bits(mm) != 3072))
        err = MP_READ_E;

    if (err == MP_OKAY) {
        d = (sp_digit*)XMALLOC(sizeof(sp_digit) * 134 * 4, NULL,
                                                              DYNAMIC_TYPE_RSA);
        if (d == NULL)
            err = MEMORY_E;
    }
    if (err == MP_OKAY) {
        a = d + 134;
        m = a + 134;
        r = a;

        sp_3072_from_bin(a, 134, in, inLen);
        sp_3072_from_mp(d, 134, dm);
        sp_3072_from_mp(m, 134, mm);
        err = sp_3072_mod_exp_134(r, a, d, 3072, m, 0);
    }
    if (err == MP_OKAY) {
        sp_3072_to_bin(r, out);
        *outLen = 384;
    }

    if (d != NULL) {
        XMEMSET(d, 0, sizeof(sp_digit) * 134);
        XFREE(d, NULL, DYNAMIC_TYPE_RSA);
    }

    return err;
#else
    sp_digit a[268], d[134], m[134];
    sp_digit* r = a;
    int err = MP_OKAY;

    (void)pm;
    (void)qm;
    (void)dpm;
    (void)dqm;
    (void)qim;

    if (*outLen < 384)
        err = MP_TO_E;
    if (err == MP_OKAY && (mp_count_bits(dm) > 3072 || inLen > 384 ||
                                                     mp_count_bits(mm) != 3072))
        err = MP_READ_E;

    if (err == MP_OKAY) {
        sp_3072_from_bin(a, 134, in, inLen);
        sp_3072_from_mp(d, 134, dm);
        sp_3072_from_mp(m, 134, mm);
        err = sp_3072_mod_exp_134(r, a, d, 3072, m, 0);
    }

    if (err == MP_OKAY) {
        sp_3072_to_bin(r, out);
        *outLen = 384;
    }

    XMEMSET(d, 0, sizeof(sp_digit) * 134);

    return err;
#endif /* !HAVE_DO178 && (WOLFSSL_SP_SMALL || defined(WOLFSSL_SMALL_STACK)) */
#else
#if !defined(HAVE_DO178) && \
    (defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK))
    sp_digit* t = NULL;
    sp_digit* a;
    sp_digit* p;
    sp_digit* q;
    sp_digit* dp;
    sp_digit* dq;
    sp_digit* qi;
    sp_digit* tmp;
    sp_digit* tmpa;
    sp_digit* tmpb;
    sp_digit* r;
    int err = MP_OKAY;

    (void)dm;
    (void)mm;

    if (*outLen < 384)
        err = MP_TO_E;
    if (err == MP_OKAY && (inLen > 384 || mp_count_bits(mm) != 3072))
        err = MP_READ_E;

    if (err == MP_OKAY) {
        t = (sp_digit*)XMALLOC(sizeof(sp_digit) * 67 * 11, NULL,
                                                              DYNAMIC_TYPE_RSA);
        if (t == NULL)
            err = MEMORY_E;
    }
    if (err == MP_OKAY) {
        a = t;
        p = a + 134 * 2;
        q = p + 67;
        qi = dq = dp = q + 67;
        tmpa = qi + 67;
        tmpb = tmpa + 134;

        tmp = t;
        r = tmp + 134;

        sp_3072_from_bin(a, 134, in, inLen);
        sp_3072_from_mp(p, 67, pm);
        sp_3072_from_mp(q, 67, qm);
        sp_3072_from_mp(dp, 67, dpm);
        err = sp_3072_mod_exp_67(tmpa, a, dp, 1536, p, 1);
    }
    if (err == MP_OKAY) {
        sp_3072_from_mp(dq, 67, dqm);
        err = sp_3072_mod_exp_67(tmpb, a, dq, 1536, q, 1);
    }
    if (err == MP_OKAY) {
        sp_3072_sub_67(tmpa, tmpa, tmpb);
        sp_3072_mask_67(tmp, p, tmpa[66] >> 31);
        sp_3072_add_67(tmpa, tmpa, tmp);

        sp_3072_from_mp(qi, 67, qim);
        sp_3072_mul_67(tmpa, tmpa, qi);
        err = sp_3072_mod_67(tmpa, tmpa, p);
    }

    if (err == MP_OKAY) {
        sp_3072_mul_67(tmpa, q, tmpa);
        sp_3072_add_134(r, tmpb, tmpa);
        sp_3072_norm_134(r);

        sp_3072_to_bin(r, out);
        *outLen = 384;
    }

    if (t != NULL) {
        XMEMSET(t, 0, sizeof(sp_digit) * 67 * 11);
        XFREE(t, NULL, DYNAMIC_TYPE_RSA);
    }

    return err;
#else
    sp_digit a[134 * 2];
    sp_digit p[67], q[67], dp[67], dq[67], qi[67];
    sp_digit tmp[134], tmpa[134], tmpb[134];
    sp_digit* r = a;
    int err = MP_OKAY;

    (void)dm;
    (void)mm;

    if (*outLen < 384)
        err = MP_TO_E;
    if (err == MP_OKAY && (inLen > 384 || mp_count_bits(mm) != 3072))
        err = MP_READ_E;

    if (err == MP_OKAY) {
        sp_3072_from_bin(a, 134, in, inLen);
        sp_3072_from_mp(p, 67, pm);
        sp_3072_from_mp(q, 67, qm);
        sp_3072_from_mp(dp, 67, dpm);
        sp_3072_from_mp(dq, 67, dqm);
        sp_3072_from_mp(qi, 67, qim);

        err = sp_3072_mod_exp_67(tmpa, a, dp, 1536, p, 1);
    }
    if (err == MP_OKAY)
        err = sp_3072_mod_exp_67(tmpb, a, dq, 1536, q, 1);

    if (err == MP_OKAY) {
        sp_3072_sub_67(tmpa, tmpa, tmpb);
        sp_3072_mask_67(tmp, p, tmpa[66] >> 31);
        sp_3072_add_67(tmpa, tmpa, tmp);
        sp_3072_mul_67(tmpa, tmpa, qi);
        err = sp_3072_mod_67(tmpa, tmpa, p);
    }

    if (err == MP_OKAY) {
        sp_3072_mul_67(tmpa, tmpa, q);
        sp_3072_add_134(r, tmpb, tmpa);
        sp_3072_norm_134(r);

        sp_3072_to_bin(r, out);
        *outLen = 384;
    }

    XMEMSET(tmpa, 0, sizeof(tmpa));
    XMEMSET(tmpb, 0, sizeof(tmpb));
    XMEMSET(p, 0, sizeof(p));
    XMEMSET(q, 0, sizeof(q));
    XMEMSET(dp, 0, sizeof(dp));
    XMEMSET(dq, 0, sizeof(dq));
    XMEMSET(qi, 0, sizeof(qi));

    return err;
#endif /* !HAVE_DO178 && (WOLFSSL_SP_SMALL || defined(WOLFSSL_SMALL_STACK)) */
#endif /* SP_RSA_PRIVATE_EXP_D || RSA_LOW_MEM */
}

#endif /* !WOLFSSL_RSA_PUBLIC_ONLY */
#endif /* WOLFSSL_HAVE_SP_RSA */
#if defined(WOLFSSL_HAVE_SP_DH) || (defined(WOLFSSL_HAVE_SP_RSA) && \
                                              !defined(WOLFSSL_RSA_PUBLIC_ONLY))
/* Convert an array of sp_digit to an mp_int.
 *
 * a  A single precision integer.
 * r  A multi-precision integer.
 */
static int sp_3072_to_mp(const sp_digit* a, mp_int* r)
{
    int err;

    err = mp_grow(r, (3072 + DIGIT_BIT - 1) / DIGIT_BIT);
    if (err == MP_OKAY) {
#if DIGIT_BIT == 23
        XMEMCPY(r->dp, a, sizeof(sp_digit) * 134);
        r->used = 134;
        mp_clamp(r);
#elif DIGIT_BIT < 23
        int i, j = 0, s = 0;

        r->dp[0] = 0;
        for (i = 0; i < 134; i++) {
            r->dp[j] |= a[i] << s;
            r->dp[j] &= (1l << DIGIT_BIT) - 1;
            s = DIGIT_BIT - s;
            r->dp[++j] = a[i] >> s;
            while (s + DIGIT_BIT <= 23) {
                s += DIGIT_BIT;
                r->dp[j++] &= (1l << DIGIT_BIT) - 1;
                if (s == SP_WORD_SIZE)
                    r->dp[j] = 0;
                else
                    r->dp[j] = a[i] >> s;
            }
            s = 23 - s;
        }
        r->used = (3072 + DIGIT_BIT - 1) / DIGIT_BIT;
        mp_clamp(r);
#else
        int i, j = 0, s = 0;

        r->dp[0] = 0;
        for (i = 0; i < 134; i++) {
            r->dp[j] |= ((mp_digit)a[i]) << s;
            if (s + 23 >= DIGIT_BIT) {
    #if DIGIT_BIT != 32 && DIGIT_BIT != 64
                r->dp[j] &= (1l << DIGIT_BIT) - 1;
    #endif
                s = DIGIT_BIT - s;
                r->dp[++j] = a[i] >> s;
                s = 23 - s;
            }
            else
                s += 23;
        }
        r->used = (3072 + DIGIT_BIT - 1) / DIGIT_BIT;
        mp_clamp(r);
#endif
    }

    return err;
}

/* Perform the modular exponentiation for Diffie-Hellman.
 *
 * base  Base. MP integer.
 * exp   Exponent. MP integer.
 * mod   Modulus. MP integer.
 * res   Result. MP integer.
 * returs 0 on success, MP_READ_E if there are too many bytes in an array
 * and MEMORY_E if memory allocation fails.
 */
int sp_ModExp_3072(mp_int* base, mp_int* exp, mp_int* mod, mp_int* res)
{
#ifdef WOLFSSL_SP_SMALL
    int err = MP_OKAY;
    sp_digit* d = NULL;
    sp_digit* b;
    sp_digit* e;
    sp_digit* m;
    sp_digit* r;
    int expBits = mp_count_bits(exp);

    if (mp_count_bits(base) > 3072 || expBits > 3072 ||
                                                   mp_count_bits(mod) != 3072) {
        err = MP_READ_E;
    }

    if (err == MP_OKAY) {
        d = (sp_digit*)XMALLOC(sizeof(*d) * 134 * 4, NULL, DYNAMIC_TYPE_DH);
        if (d == NULL)
            err = MEMORY_E;
    }

    if (err == MP_OKAY) {
        b = d;
        e = b + 134 * 2;
        m = e + 134;
        r = b;

        sp_3072_from_mp(b, 134, base);
        sp_3072_from_mp(e, 134, exp);
        sp_3072_from_mp(m, 134, mod);

        err = sp_3072_mod_exp_134(r, b, e, mp_count_bits(exp), m, 0);
    }

    if (err == MP_OKAY) {
        err = sp_3072_to_mp(r, res);
    }

    if (d != NULL) {
        XMEMSET(e, 0, sizeof(sp_digit) * 134);
        XFREE(d, NULL, DYNAMIC_TYPE_DH);
    }
    return err;
#else
#if defined(HAVE_DO178) || !defined(WOLFSSL_SMALL_STACK)
    sp_digit bd[268], ed[134], md[134];
#else
    sp_digit* d = NULL;
#endif
    sp_digit* b;
    sp_digit* e;
    sp_digit* m;
    sp_digit* r;
    int err = MP_OKAY;
    int expBits = mp_count_bits(exp);

    if (mp_count_bits(base) > 3072 || expBits > 3072 ||
                                                   mp_count_bits(mod) != 3072) {
        err = MP_READ_E;
    }

#if !defined(HAVE_DO178) && defined(WOLFSSL_SMALL_STACK)
    if (err == MP_OKAY) {
        d = (sp_digit*)XMALLOC(sizeof(*d) * 134 * 4, NULL, DYNAMIC_TYPE_DH);
        if (d == NULL)
            err = MEMORY_E;
    }

    if (err == MP_OKAY) {
        b = d;
        e = b + 134 * 2;
        m = e + 134;
        r = b;
    }
#else
    r = b = bd;
    e = ed;
    m = md;
#endif

    if (err == MP_OKAY) {
        sp_3072_from_mp(b, 134, base);
        sp_3072_from_mp(e, 134, exp);
        sp_3072_from_mp(m, 134, mod);

        err = sp_3072_mod_exp_134(r, b, e, expBits, m, 0);
    }

    if (err == MP_OKAY) {
        err = sp_3072_to_mp(r, res);
    }

    XMEMSET(e, 0, sizeof(sp_digit) * 134);

#if !defined(HAVE_DO178) && defined(WOLFSSL_SMALL_STACK)
    if (d != NULL)
        XFREE(d, NULL, DYNAMIC_TYPE_DH);
#endif

    return err;
#endif
}

#endif /* WOLFSSL_HAVE_SP_DH || (WOLFSSL_HAVE_SP_RSA && !WOLFSSL_RSA_PUBLIC_ONLY) */

#endif /* !WOLFSSL_SP_NO_3072 */

#endif /* WOLFSSL_HAVE_SP_RSA || WOLFSSL_HAVE_SP_DH */
#endif /* SP_WORD_SIZE == 32 */
#endif /* !WOLFSSL_SP_ASM */
#endif /* WOLFSSL_HAVE_SP_RSA || WOLFSSL_HAVE_SP_DH || WOLFSSL_HAVE_SP_ECC */
