/* sp.c
 *
 * Copyright (C) 2006-2020 wolfSSL Inc.
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
#if SP_WORD_SIZE == 64
#if ((!defined(WC_NO_CACHE_RESISTANT) && \
      (defined(WOLFSSL_HAVE_SP_RSA) || defined(WOLFSSL_HAVE_SP_DH))) || \
     defined(WOLFSSL_SP_SMALL)) && \
    (defined(WOLFSSL_HAVE_SP_ECC) || !defined(WOLFSSL_RSA_PUBLIC_ONLY))
/* Mask for address to obfuscate which of the two address will be used. */
#ifdef WOLFSSL_SP_SMALL    
static const size_t addr_mask[2] = { 0, (size_t)-1 };
#endif 
#endif

#if defined(WOLFSSL_SP_NONBLOCK) && (!defined(WOLFSSL_SP_NO_MALLOC) || !defined(WOLFSSL_SP_SMALL))
    #error SP non-blocking requires small and no-malloc (WOLFSSL_SP_SMALL and WOLFSSL_SP_NO_MALLOC)
#endif

#if defined(WOLFSSL_HAVE_SP_RSA) || defined(WOLFSSL_HAVE_SP_DH)
#endif /* WOLFSSL_HAVE_SP_RSA || WOLFSSL_HAVE_SP_DH */
#ifdef WOLFSSL_HAVE_SP_ECC
#ifdef WOLFSSL_SP_384

/* Point structure to use. */
typedef struct sp_point_384 {
    sp_digit x[2 * 7];
    sp_digit y[2 * 7];
    sp_digit z[2 * 7];
    int infinity;
} sp_point_384;

/* The modulus (prime) of the curve P384. */
static const sp_digit p384_mod[7] = {
    0x000000ffffffffL,0x7ffe0000000000L,0x7ffffffffbffffL,0x7fffffffffffffL,
    0x7fffffffffffffL,0x7fffffffffffffL,0x3fffffffffffffL
};
/* The Montogmery normalizer for modulus of the curve P384. */
static const sp_digit p384_norm_mod[7] = {
    0x7fffff00000001L,0x0001ffffffffffL,0x00000000040000L,0x00000000000000L,
    0x00000000000000L,0x00000000000000L,0x00000000000000L
};
/* The Montogmery multiplier for modulus of the curve P384. */
static sp_digit p384_mp_mod = 0x0000100000001;
#if defined(WOLFSSL_VALIDATE_ECC_KEYGEN) || defined(HAVE_ECC_SIGN) || \
                                            defined(HAVE_ECC_VERIFY)
/* The order of the curve P384. */
static const sp_digit p384_order[7] = {
    0x6c196accc52973L,0x1b6491614ef5d9L,0x07d0dcb77d6068L,0x7ffffffe3b1a6cL,
    0x7fffffffffffffL,0x7fffffffffffffL,0x3fffffffffffffL
};
#endif
/* The order of the curve P384 minus 2. */
static const sp_digit p384_order2[7] = {
    0x6c196accc52971L,0x1b6491614ef5d9L,0x07d0dcb77d6068L,0x7ffffffe3b1a6cL,
    0x7fffffffffffffL,0x7fffffffffffffL,0x3fffffffffffffL
};
#if defined(HAVE_ECC_SIGN) || defined(HAVE_ECC_VERIFY)
/* The Montogmery normalizer for order of the curve P384. */
static const sp_digit p384_norm_order[7] = {
    0x13e695333ad68dL,0x649b6e9eb10a26L,0x782f2348829f97L,0x00000001c4e593L,
    0x00000000000000L,0x00000000000000L,0x00000000000000L
};
#endif
#if defined(HAVE_ECC_SIGN) || defined(HAVE_ECC_VERIFY)
/* The Montogmery multiplier for order of the curve P384. */
static sp_digit p384_mp_order = 0x546089e88fdc45l;
#endif
/* The base point of curve P384. */
static const sp_point_384 p384_base = {
    /* X ordinate */
    {
        0x545e3872760ab7L,0x64bb7eaa52d874L,0x020950a8e1540bL,
        0x5d3cdcc2cfba0fL,0x0ad746e1d3b628L,0x26f1d638e3de64L,0x2aa1f288afa2c1L,
        0L, 0L, 0L, 0L, 0L, 0L, 0L
    },
    /* Y ordinate */
    {
        0x431d7c90ea0e5fL,0x639c3afd033af4L,0x4ed7c2e3002982L,
        0x44d0a3e74ed188L,0x2dc29f8f41dbd2L,0x0debb3d317f252L,0x0d85f792a5898bL,
        0L, 0L, 0L, 0L, 0L, 0L, 0L
    },
    /* Z ordinate */
    {
        0x00000000000001L,0x00000000000000L,0x00000000000000L,
        0x00000000000000L,0x00000000000000L,0x00000000000000L,0x00000000000000L,
        0L, 0L, 0L, 0L, 0L, 0L, 0L
    },
    /* infinity */
    0
};
#if defined(HAVE_ECC_CHECK_KEY) || defined(HAVE_COMP_KEY)
static const sp_digit p384_b[7] = {
    0x05c8edd3ec2aefL,0x731b145da33a55L,0x3d404e1d6b1958L,0x740a089018a044L,
    0x02d19181d9c6efL,0x7c9311c0ad7c7fL,0x2ccc4be9f88fb9L
};
#endif

static int sp_384_point_new_ex_7(void* heap, sp_point_384* sp, sp_point_384** p)
{
    int ret = MP_OKAY;
    (void)heap;
#if (defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)) && !defined(WOLFSSL_SP_NO_MALLOC)
    (void)sp;
    *p = (sp_point_384*)XMALLOC(sizeof(sp_point_384), heap, DYNAMIC_TYPE_ECC);
#else
    *p = sp;
#endif
    if (*p == NULL) {
        ret = MEMORY_E;
    }
    return ret;
}

#if (defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)) && !defined(WOLFSSL_SP_NO_MALLOC)
/* Allocate memory for point and return error. */
#define sp_384_point_new_7(heap, sp, p) sp_384_point_new_ex_7((heap), NULL, &(p))
#else
/* Set pointer to data and return no error. */
#define sp_384_point_new_7(heap, sp, p) sp_384_point_new_ex_7((heap), &(sp), &(p))
#endif


static void sp_384_point_free_7(sp_point_384* p, int clear, void* heap)
{
#if (defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)) && !defined(WOLFSSL_SP_NO_MALLOC)
/* If valid pointer then clear point data if requested and free data. */
    if (p != NULL) {
        if (clear != 0) {
            XMEMSET(p, 0, sizeof(*p));
        }
        XFREE(p, heap, DYNAMIC_TYPE_ECC);
    }
#else
/* Clear point data if requested. */
    if (clear != 0) {
        XMEMSET(p, 0, sizeof(*p));
    }
#endif
    (void)heap;
}

/* Multiply a number by Montogmery normalizer mod modulus (prime).
 *
 * r  The resulting Montgomery form number.
 * a  The number to convert.
 * m  The modulus (prime).
 * returns MEMORY_E when memory allocation fails and MP_OKAY otherwise.
 */
static int sp_384_mod_mul_norm_7(sp_digit* r, const sp_digit* a, const sp_digit* m)
{
#if (defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)) && !defined(WOLFSSL_SP_NO_MALLOC)
    int64_t* td;
#else
    int64_t td[12];
    int64_t a32d[12];
#endif
    int64_t* t;
    int64_t* a32;
    int64_t o;
    int err = MP_OKAY;

    (void)m;

#if (defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)) && !defined(WOLFSSL_SP_NO_MALLOC)
    td = (int64_t*)XMALLOC(sizeof(int64_t) * 2 * 12, NULL, DYNAMIC_TYPE_ECC);
    if (td == NULL) {
        err = MEMORY_E;
    }
#endif

    if (err == MP_OKAY) {
#if (defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)) && !defined(WOLFSSL_SP_NO_MALLOC)
        t = td;
        a32 = td + 12;
#else
        t = td;
        a32 = a32d;
#endif

        a32[0] = (sp_digit)(a[0]) & 0xffffffffL;
        a32[1] = (sp_digit)(a[0] >> 32U);
        a32[1] |= (sp_digit)(a[1] << 23U);
        a32[1] &= 0xffffffffL;
        a32[2] = (sp_digit)(a[1] >> 9U) & 0xffffffffL;
        a32[3] = (sp_digit)(a[1] >> 41U);
        a32[3] |= (sp_digit)(a[2] << 14U);
        a32[3] &= 0xffffffffL;
        a32[4] = (sp_digit)(a[2] >> 18U) & 0xffffffffL;
        a32[5] = (sp_digit)(a[2] >> 50U);
        a32[5] |= (sp_digit)(a[3] << 5U);
        a32[5] &= 0xffffffffL;
        a32[6] = (sp_digit)(a[3] >> 27U);
        a32[6] |= (sp_digit)(a[4] << 28U);
        a32[6] &= 0xffffffffL;
        a32[7] = (sp_digit)(a[4] >> 4U) & 0xffffffffL;
        a32[8] = (sp_digit)(a[4] >> 36U);
        a32[8] |= (sp_digit)(a[5] << 19U);
        a32[8] &= 0xffffffffL;
        a32[9] = (sp_digit)(a[5] >> 13U) & 0xffffffffL;
        a32[10] = (sp_digit)(a[5] >> 45U);
        a32[10] |= (sp_digit)(a[6] << 10U);
        a32[10] &= 0xffffffffL;
        a32[11] = (sp_digit)(a[6] >> 22U) & 0xffffffffL;

        /*  1  0  0  0  0  0  0  0  1  1  0 -1 */
        t[0] = 0 + a32[0] + a32[8] + a32[9] - a32[11];
        /* -1  1  0  0  0  0  0  0 -1  0  1  1 */
        t[1] = 0 - a32[0] + a32[1] - a32[8] + a32[10] + a32[11];
        /*  0 -1  1  0  0  0  0  0  0 -1  0  1 */
        t[2] = 0 - a32[1] + a32[2] - a32[9] + a32[11];
        /*  1  0 -1  1  0  0  0  0  1  1 -1 -1 */
        t[3] = 0 + a32[0] - a32[2] + a32[3] + a32[8] + a32[9] - a32[10] - a32[11];
        /*  1  1  0 -1  1  0  0  0  1  2  1 -2 */
        t[4] = 0 + a32[0] + a32[1] - a32[3] + a32[4] + a32[8] + 2 * a32[9] + a32[10] -  2 * a32[11];
        /*  0  1  1  0 -1  1  0  0  0  1  2  1 */
        t[5] = 0 + a32[1] + a32[2] - a32[4] + a32[5] + a32[9] + 2 * a32[10] + a32[11];
        /*  0  0  1  1  0 -1  1  0  0  0  1  2 */
        t[6] = 0 + a32[2] + a32[3] - a32[5] + a32[6] + a32[10] + 2 * a32[11];
        /*  0  0  0  1  1  0 -1  1  0  0  0  1 */
        t[7] = 0 + a32[3] + a32[4] - a32[6] + a32[7] + a32[11];
        /*  0  0  0  0  1  1  0 -1  1  0  0  0 */
        t[8] = 0 + a32[4] + a32[5] - a32[7] + a32[8];
        /*  0  0  0  0  0  1  1  0 -1  1  0  0 */
        t[9] = 0 + a32[5] + a32[6] - a32[8] + a32[9];
        /*  0  0  0  0  0  0  1  1  0 -1  1  0 */
        t[10] = 0 + a32[6] + a32[7] - a32[9] + a32[10];
        /*  0  0  0  0  0  0  0  1  1  0 -1  1 */
        t[11] = 0 + a32[7] + a32[8] - a32[10] + a32[11];

        t[1] += t[0] >> 32; t[0] &= 0xffffffff;
        t[2] += t[1] >> 32; t[1] &= 0xffffffff;
        t[3] += t[2] >> 32; t[2] &= 0xffffffff;
        t[4] += t[3] >> 32; t[3] &= 0xffffffff;
        t[5] += t[4] >> 32; t[4] &= 0xffffffff;
        t[6] += t[5] >> 32; t[5] &= 0xffffffff;
        t[7] += t[6] >> 32; t[6] &= 0xffffffff;
        t[8] += t[7] >> 32; t[7] &= 0xffffffff;
        t[9] += t[8] >> 32; t[8] &= 0xffffffff;
        t[10] += t[9] >> 32; t[9] &= 0xffffffff;
        t[11] += t[10] >> 32; t[10] &= 0xffffffff;
        o     = t[11] >> 32; t[11] &= 0xffffffff;
        t[0] += o;
        t[1] -= o;
        t[3] += o;
        t[4] += o;
        t[1] += t[0] >> 32; t[0] &= 0xffffffff;
        t[2] += t[1] >> 32; t[1] &= 0xffffffff;
        t[3] += t[2] >> 32; t[2] &= 0xffffffff;
        t[4] += t[3] >> 32; t[3] &= 0xffffffff;
        t[5] += t[4] >> 32; t[4] &= 0xffffffff;
        t[6] += t[5] >> 32; t[5] &= 0xffffffff;
        t[7] += t[6] >> 32; t[6] &= 0xffffffff;
        t[8] += t[7] >> 32; t[7] &= 0xffffffff;
        t[9] += t[8] >> 32; t[8] &= 0xffffffff;
        t[10] += t[9] >> 32; t[9] &= 0xffffffff;
        t[11] += t[10] >> 32; t[10] &= 0xffffffff;

        r[0] = t[0];
        r[0] |= t[1] << 32U;
        r[0] &= 0x7fffffffffffffLL;
        r[1] = (sp_digit)(t[1] >> 23);
        r[1] |= t[2] << 9U;
        r[1] |= t[3] << 41U;
        r[1] &= 0x7fffffffffffffLL;
        r[2] = (sp_digit)(t[3] >> 14);
        r[2] |= t[4] << 18U;
        r[2] |= t[5] << 50U;
        r[2] &= 0x7fffffffffffffLL;
        r[3] = (sp_digit)(t[5] >> 5);
        r[3] |= t[6] << 27U;
        r[3] &= 0x7fffffffffffffLL;
        r[4] = (sp_digit)(t[6] >> 28);
        r[4] |= t[7] << 4U;
        r[4] |= t[8] << 36U;
        r[4] &= 0x7fffffffffffffLL;
        r[5] = (sp_digit)(t[8] >> 19);
        r[5] |= t[9] << 13U;
        r[5] |= t[10] << 45U;
        r[5] &= 0x7fffffffffffffLL;
        r[6] = (sp_digit)(t[10] >> 10);
        r[6] |= t[11] << 22U;
    }

#if (defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)) && !defined(WOLFSSL_SP_NO_MALLOC)
    if (td != NULL)
        XFREE(td, NULL, DYNAMIC_TYPE_ECC);
#endif

    return err;
}

/* Convert an mp_int to an array of sp_digit.
 *
 * r  A single precision integer.
 * size  Maximum number of bytes to convert
 * a  A multi-precision integer.
 */
static void sp_384_from_mp(sp_digit* r, int size, const mp_int* a)
{
#if DIGIT_BIT == 55
    int j;

    XMEMCPY(r, a->dp, sizeof(sp_digit) * a->used);

    for (j = a->used; j < size; j++) {
        r[j] = 0;
    }
#elif DIGIT_BIT > 55
    int i, j = 0;
    word32 s = 0;

    r[0] = 0;
    for (i = 0; i < a->used && j < size; i++) {
        r[j] |= ((sp_digit)a->dp[i] << s);
        r[j] &= 0x7fffffffffffffL;
        s = 55U - s;
        if (j + 1 >= size) {
            break;
        }
        /* lint allow cast of mismatch word32 and mp_digit */
        r[++j] = (sp_digit)(a->dp[i] >> s); /*lint !e9033*/
        while ((s + 55U) <= (word32)DIGIT_BIT) {
            s += 55U;
            r[j] &= 0x7fffffffffffffL;
            if (j + 1 >= size) {
                break;
            }
            if (s < (word32)DIGIT_BIT) {
                /* lint allow cast of mismatch word32 and mp_digit */
                r[++j] = (sp_digit)(a->dp[i] >> s); /*lint !e9033*/
            }
            else {
                r[++j] = 0L;
            }
        }
        s = (word32)DIGIT_BIT - s;
    }

    for (j++; j < size; j++) {
        r[j] = 0;
    }
#else
    int i, j = 0, s = 0;

    r[0] = 0;
    for (i = 0; i < a->used && j < size; i++) {
        r[j] |= ((sp_digit)a->dp[i]) << s;
        if (s + DIGIT_BIT >= 55) {
            r[j] &= 0x7fffffffffffffL;
            if (j + 1 >= size) {
                break;
            }
            s = 55 - s;
            if (s == DIGIT_BIT) {
                r[++j] = 0;
                s = 0;
            }
            else {
                r[++j] = a->dp[i] >> s;
                s = DIGIT_BIT - s;
            }
        }
        else {
            s += DIGIT_BIT;
        }
    }

    for (j++; j < size; j++) {
        r[j] = 0;
    }
#endif
}

/* Convert a point of type ecc_point to type sp_point_384.
 *
 * p   Point of type sp_point_384 (result).
 * pm  Point of type ecc_point.
 */
static void sp_384_point_from_ecc_point_7(sp_point_384* p, const ecc_point* pm)
{
    XMEMSET(p->x, 0, sizeof(p->x));
    XMEMSET(p->y, 0, sizeof(p->y));
    XMEMSET(p->z, 0, sizeof(p->z));
    sp_384_from_mp(p->x, 7, pm->x);
    sp_384_from_mp(p->y, 7, pm->y);
    sp_384_from_mp(p->z, 7, pm->z);
    p->infinity = 0;
}

/* Convert an array of sp_digit to an mp_int.
 *
 * a  A single precision integer.
 * r  A multi-precision integer.
 */
static int sp_384_to_mp(const sp_digit* a, mp_int* r)
{
    int err;

    err = mp_grow(r, (384 + DIGIT_BIT - 1) / DIGIT_BIT);
    if (err == MP_OKAY) { /*lint !e774 case where err is always MP_OKAY*/
#if DIGIT_BIT == 55
        XMEMCPY(r->dp, a, sizeof(sp_digit) * 7);
        r->used = 7;
        mp_clamp(r);
#elif DIGIT_BIT < 55
        int i, j = 0, s = 0;

        r->dp[0] = 0;
        for (i = 0; i < 7; i++) {
            r->dp[j] |= (mp_digit)(a[i] << s);
            r->dp[j] &= (1L << DIGIT_BIT) - 1;
            s = DIGIT_BIT - s;
            r->dp[++j] = (mp_digit)(a[i] >> s);
            while (s + DIGIT_BIT <= 55) {
                s += DIGIT_BIT;
                r->dp[j++] &= (1L << DIGIT_BIT) - 1;
                if (s == SP_WORD_SIZE) {
                    r->dp[j] = 0;
                }
                else {
                    r->dp[j] = (mp_digit)(a[i] >> s);
                }
            }
            s = 55 - s;
        }
        r->used = (384 + DIGIT_BIT - 1) / DIGIT_BIT;
        mp_clamp(r);
#else
        int i, j = 0, s = 0;

        r->dp[0] = 0;
        for (i = 0; i < 7; i++) {
            r->dp[j] |= ((mp_digit)a[i]) << s;
            if (s + 55 >= DIGIT_BIT) {
    #if DIGIT_BIT != 32 && DIGIT_BIT != 64
                r->dp[j] &= (1L << DIGIT_BIT) - 1;
    #endif
                s = DIGIT_BIT - s;
                r->dp[++j] = a[i] >> s;
                s = 55 - s;
            }
            else {
                s += 55;
            }
        }
        r->used = (384 + DIGIT_BIT - 1) / DIGIT_BIT;
        mp_clamp(r);
#endif
    }

    return err;
}

/* Convert a point of type sp_point_384 to type ecc_point.
 *
 * p   Point of type sp_point_384.
 * pm  Point of type ecc_point (result).
 * returns MEMORY_E when allocation of memory in ecc_point fails otherwise
 * MP_OKAY.
 */
static int sp_384_point_to_ecc_point_7(const sp_point_384* p, ecc_point* pm)
{
    int err;

    err = sp_384_to_mp(p->x, pm->x);
    if (err == MP_OKAY) {
        err = sp_384_to_mp(p->y, pm->y);
    }
    if (err == MP_OKAY) {
        err = sp_384_to_mp(p->z, pm->z);
    }

    return err;
}

#ifdef WOLFSSL_SP_SMALL
/* Multiply a and b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static void sp_384_mul_7(sp_digit* r, const sp_digit* a,
    const sp_digit* b)
{
    int i, j, k;
    int128_t c;

    c = ((int128_t)a[6]) * b[6];
    r[13] = (sp_digit)(c >> 55);
    c = (c & 0x7fffffffffffffL) << 55;
    for (k = 11; k >= 0; k--) {
        for (i = 6; i >= 0; i--) {
            j = k - i;
            if (j >= 7) {
                break;
            }
            if (j < 0) {
                continue;
            }

            c += ((int128_t)a[i]) * b[j];
        }
        r[k + 2] += (sp_digit)(c >> 110);
        r[k + 1] = (sp_digit)((c >> 55) & 0x7fffffffffffffL);
        c = (c & 0x7fffffffffffffL) << 55;
    }
    r[0] = (sp_digit)(c >> 55);
}

#else
/* Multiply a and b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static void sp_384_mul_7(sp_digit* r, const sp_digit* a,
    const sp_digit* b)
{
    int128_t t0   = ((int128_t)a[ 0]) * b[ 0];
    int128_t t1   = ((int128_t)a[ 0]) * b[ 1]
                 + ((int128_t)a[ 1]) * b[ 0];
    int128_t t2   = ((int128_t)a[ 0]) * b[ 2]
                 + ((int128_t)a[ 1]) * b[ 1]
                 + ((int128_t)a[ 2]) * b[ 0];
    int128_t t3   = ((int128_t)a[ 0]) * b[ 3]
                 + ((int128_t)a[ 1]) * b[ 2]
                 + ((int128_t)a[ 2]) * b[ 1]
                 + ((int128_t)a[ 3]) * b[ 0];
    int128_t t4   = ((int128_t)a[ 0]) * b[ 4]
                 + ((int128_t)a[ 1]) * b[ 3]
                 + ((int128_t)a[ 2]) * b[ 2]
                 + ((int128_t)a[ 3]) * b[ 1]
                 + ((int128_t)a[ 4]) * b[ 0];
    int128_t t5   = ((int128_t)a[ 0]) * b[ 5]
                 + ((int128_t)a[ 1]) * b[ 4]
                 + ((int128_t)a[ 2]) * b[ 3]
                 + ((int128_t)a[ 3]) * b[ 2]
                 + ((int128_t)a[ 4]) * b[ 1]
                 + ((int128_t)a[ 5]) * b[ 0];
    int128_t t6   = ((int128_t)a[ 0]) * b[ 6]
                 + ((int128_t)a[ 1]) * b[ 5]
                 + ((int128_t)a[ 2]) * b[ 4]
                 + ((int128_t)a[ 3]) * b[ 3]
                 + ((int128_t)a[ 4]) * b[ 2]
                 + ((int128_t)a[ 5]) * b[ 1]
                 + ((int128_t)a[ 6]) * b[ 0];
    int128_t t7   = ((int128_t)a[ 1]) * b[ 6]
                 + ((int128_t)a[ 2]) * b[ 5]
                 + ((int128_t)a[ 3]) * b[ 4]
                 + ((int128_t)a[ 4]) * b[ 3]
                 + ((int128_t)a[ 5]) * b[ 2]
                 + ((int128_t)a[ 6]) * b[ 1];
    int128_t t8   = ((int128_t)a[ 2]) * b[ 6]
                 + ((int128_t)a[ 3]) * b[ 5]
                 + ((int128_t)a[ 4]) * b[ 4]
                 + ((int128_t)a[ 5]) * b[ 3]
                 + ((int128_t)a[ 6]) * b[ 2];
    int128_t t9   = ((int128_t)a[ 3]) * b[ 6]
                 + ((int128_t)a[ 4]) * b[ 5]
                 + ((int128_t)a[ 5]) * b[ 4]
                 + ((int128_t)a[ 6]) * b[ 3];
    int128_t t10  = ((int128_t)a[ 4]) * b[ 6]
                 + ((int128_t)a[ 5]) * b[ 5]
                 + ((int128_t)a[ 6]) * b[ 4];
    int128_t t11  = ((int128_t)a[ 5]) * b[ 6]
                 + ((int128_t)a[ 6]) * b[ 5];
    int128_t t12  = ((int128_t)a[ 6]) * b[ 6];

    t1   += t0  >> 55; r[ 0] = t0  & 0x7fffffffffffffL;
    t2   += t1  >> 55; r[ 1] = t1  & 0x7fffffffffffffL;
    t3   += t2  >> 55; r[ 2] = t2  & 0x7fffffffffffffL;
    t4   += t3  >> 55; r[ 3] = t3  & 0x7fffffffffffffL;
    t5   += t4  >> 55; r[ 4] = t4  & 0x7fffffffffffffL;
    t6   += t5  >> 55; r[ 5] = t5  & 0x7fffffffffffffL;
    t7   += t6  >> 55; r[ 6] = t6  & 0x7fffffffffffffL;
    t8   += t7  >> 55; r[ 7] = t7  & 0x7fffffffffffffL;
    t9   += t8  >> 55; r[ 8] = t8  & 0x7fffffffffffffL;
    t10  += t9  >> 55; r[ 9] = t9  & 0x7fffffffffffffL;
    t11  += t10 >> 55; r[10] = t10 & 0x7fffffffffffffL;
    t12  += t11 >> 55; r[11] = t11 & 0x7fffffffffffffL;
    r[13] = (sp_digit)(t12 >> 55);
                       r[12] = t12 & 0x7fffffffffffffL;
}

#endif /* WOLFSSL_SP_SMALL */
#define sp_384_mont_reduce_order_7         sp_384_mont_reduce_7

/* Compare a with b in constant time.
 *
 * a  A single precision integer.
 * b  A single precision integer.
 * return -ve, 0 or +ve if a is less than, equal to or greater than b
 * respectively.
 */
static sp_digit sp_384_cmp_7(const sp_digit* a, const sp_digit* b)
{
    sp_digit r = 0;
#ifdef WOLFSSL_SP_SMALL
    int i;

    for (i=6; i>=0; i--) {
        r |= (a[i] - b[i]) & (0 - ((r == 0) ? (sp_digit)1 : (sp_digit)0));
    }
#else
    r |= (a[ 6] - b[ 6]) & (0 - ((r == 0) ? (sp_digit)1 : (sp_digit)0));
    r |= (a[ 5] - b[ 5]) & (0 - ((r == 0) ? (sp_digit)1 : (sp_digit)0));
    r |= (a[ 4] - b[ 4]) & (0 - ((r == 0) ? (sp_digit)1 : (sp_digit)0));
    r |= (a[ 3] - b[ 3]) & (0 - ((r == 0) ? (sp_digit)1 : (sp_digit)0));
    r |= (a[ 2] - b[ 2]) & (0 - ((r == 0) ? (sp_digit)1 : (sp_digit)0));
    r |= (a[ 1] - b[ 1]) & (0 - ((r == 0) ? (sp_digit)1 : (sp_digit)0));
    r |= (a[ 0] - b[ 0]) & (0 - ((r == 0) ? (sp_digit)1 : (sp_digit)0));
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
static void sp_384_cond_sub_7(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit m)
{
#ifdef WOLFSSL_SP_SMALL
    int i;

    for (i = 0; i < 7; i++) {
        r[i] = a[i] - (b[i] & m);
    }
#else
    r[ 0] = a[ 0] - (b[ 0] & m);
    r[ 1] = a[ 1] - (b[ 1] & m);
    r[ 2] = a[ 2] - (b[ 2] & m);
    r[ 3] = a[ 3] - (b[ 3] & m);
    r[ 4] = a[ 4] - (b[ 4] & m);
    r[ 5] = a[ 5] - (b[ 5] & m);
    r[ 6] = a[ 6] - (b[ 6] & m);
#endif /* WOLFSSL_SP_SMALL */
}

/* Mul a by scalar b and add into r. (r += a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A scalar.
 */
SP_NOINLINE static void sp_384_mul_add_7(sp_digit* r, const sp_digit* a,
        const sp_digit b)
{
#ifdef WOLFSSL_SP_SMALL
    int128_t tb = b;
    int128_t t = 0;
    int i;

    for (i = 0; i < 7; i++) {
        t += (tb * a[i]) + r[i];
        r[i] = t & 0x7fffffffffffffL;
        t >>= 55;
    }
    r[7] += (sp_digit)t;
#else
    int128_t tb = b;
    int128_t t[7];

    t[ 0] = tb * a[ 0];
    t[ 1] = tb * a[ 1];
    t[ 2] = tb * a[ 2];
    t[ 3] = tb * a[ 3];
    t[ 4] = tb * a[ 4];
    t[ 5] = tb * a[ 5];
    t[ 6] = tb * a[ 6];
    r[ 0] += (sp_digit)                 (t[ 0] & 0x7fffffffffffffL);
    r[ 1] += (sp_digit)((t[ 0] >> 55) + (t[ 1] & 0x7fffffffffffffL));
    r[ 2] += (sp_digit)((t[ 1] >> 55) + (t[ 2] & 0x7fffffffffffffL));
    r[ 3] += (sp_digit)((t[ 2] >> 55) + (t[ 3] & 0x7fffffffffffffL));
    r[ 4] += (sp_digit)((t[ 3] >> 55) + (t[ 4] & 0x7fffffffffffffL));
    r[ 5] += (sp_digit)((t[ 4] >> 55) + (t[ 5] & 0x7fffffffffffffL));
    r[ 6] += (sp_digit)((t[ 5] >> 55) + (t[ 6] & 0x7fffffffffffffL));
    r[ 7] += (sp_digit) (t[ 6] >> 55);
#endif /* WOLFSSL_SP_SMALL */
}

/* Normalize the values in each word to 55.
 *
 * a  Array of sp_digit to normalize.
 */
static void sp_384_norm_7(sp_digit* a)
{
#ifdef WOLFSSL_SP_SMALL
    int i;
    for (i = 0; i < 6; i++) {
        a[i+1] += a[i] >> 55;
        a[i] &= 0x7fffffffffffffL;
    }
#else
    a[1] += a[0] >> 55; a[0] &= 0x7fffffffffffffL;
    a[2] += a[1] >> 55; a[1] &= 0x7fffffffffffffL;
    a[3] += a[2] >> 55; a[2] &= 0x7fffffffffffffL;
    a[4] += a[3] >> 55; a[3] &= 0x7fffffffffffffL;
    a[5] += a[4] >> 55; a[4] &= 0x7fffffffffffffL;
    a[6] += a[5] >> 55; a[5] &= 0x7fffffffffffffL;
#endif
}

/* Shift the result in the high 384 bits down to the bottom.
 *
 * r  A single precision number.
 * a  A single precision number.
 */
static void sp_384_mont_shift_7(sp_digit* r, const sp_digit* a)
{
#ifdef WOLFSSL_SP_SMALL
    int i;
    word64 n;

    n = a[6] >> 54;
    for (i = 0; i < 6; i++) {
        n += (word64)a[7 + i] << 1;
        r[i] = n & 0x7fffffffffffffL;
        n >>= 55;
    }
    n += (word64)a[13] << 1;
    r[6] = n;
#else
    word64 n;

    n  = a[6] >> 54;
    n += (word64)a[ 7] << 1U; r[ 0] = n & 0x7fffffffffffffUL; n >>= 55U;
    n += (word64)a[ 8] << 1U; r[ 1] = n & 0x7fffffffffffffUL; n >>= 55U;
    n += (word64)a[ 9] << 1U; r[ 2] = n & 0x7fffffffffffffUL; n >>= 55U;
    n += (word64)a[10] << 1U; r[ 3] = n & 0x7fffffffffffffUL; n >>= 55U;
    n += (word64)a[11] << 1U; r[ 4] = n & 0x7fffffffffffffUL; n >>= 55U;
    n += (word64)a[12] << 1U; r[ 5] = n & 0x7fffffffffffffUL; n >>= 55U;
    n += (word64)a[13] << 1U; r[ 6] = n;
#endif /* WOLFSSL_SP_SMALL */
    XMEMSET(&r[7], 0, sizeof(*r) * 7U);
}

/* Reduce the number back to 384 bits using Montgomery reduction.
 *
 * a   A single precision number to reduce in place.
 * m   The single precision number representing the modulus.
 * mp  The digit representing the negative inverse of m mod 2^n.
 */
static void sp_384_mont_reduce_7(sp_digit* a, const sp_digit* m, sp_digit mp)
{
    int i;
    sp_digit mu;

    sp_384_norm_7(a + 7);

    for (i=0; i<6; i++) {
        mu = (a[i] * mp) & 0x7fffffffffffffL;
        sp_384_mul_add_7(a+i, m, mu);
        a[i+1] += a[i] >> 55;
    }
    mu = (a[i] * mp) & 0x3fffffffffffffL;
    sp_384_mul_add_7(a+i, m, mu);
    a[i+1] += a[i] >> 55;
    a[i] &= 0x7fffffffffffffL;

    sp_384_mont_shift_7(a, a);
    sp_384_cond_sub_7(a, a, m, 0 - (((a[6] >> 54) > 0) ?
            (sp_digit)1 : (sp_digit)0));
    sp_384_norm_7(a);
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
static void sp_384_mont_mul_7(sp_digit* r, const sp_digit* a, const sp_digit* b,
        const sp_digit* m, sp_digit mp)
{
    sp_384_mul_7(r, a, b);
    sp_384_mont_reduce_7(r, m, mp);
}

#ifdef WOLFSSL_SP_SMALL
/* Square a and put result in r. (r = a * a)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 */
SP_NOINLINE static void sp_384_sqr_7(sp_digit* r, const sp_digit* a)
{
    int i, j, k;
    int128_t c;

    c = ((int128_t)a[6]) * a[6];
    r[13] = (sp_digit)(c >> 55);
    c = (c & 0x7fffffffffffffL) << 55;
    for (k = 11; k >= 0; k--) {
        for (i = 6; i >= 0; i--) {
            j = k - i;
            if (j >= 7 || i <= j) {
                break;
            }
            if (j < 0) {
                continue;
            }

            c += ((int128_t)a[i]) * a[j] * 2;
        }
        if (i == j) {
           c += ((int128_t)a[i]) * a[i];
        }

        r[k + 2] += (sp_digit)(c >> 110);
        r[k + 1] = (sp_digit)((c >> 55) & 0x7fffffffffffffL);
        c = (c & 0x7fffffffffffffL) << 55;
    }
    r[0] = (sp_digit)(c >> 55);
}

#else
/* Square a and put result in r. (r = a * a)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 */
SP_NOINLINE static void sp_384_sqr_7(sp_digit* r, const sp_digit* a)
{
    int128_t t0   =  ((int128_t)a[ 0]) * a[ 0];
    int128_t t1   = (((int128_t)a[ 0]) * a[ 1]) * 2;
    int128_t t2   = (((int128_t)a[ 0]) * a[ 2]) * 2
                 +  ((int128_t)a[ 1]) * a[ 1];
    int128_t t3   = (((int128_t)a[ 0]) * a[ 3]
                 +  ((int128_t)a[ 1]) * a[ 2]) * 2;
    int128_t t4   = (((int128_t)a[ 0]) * a[ 4]
                 +  ((int128_t)a[ 1]) * a[ 3]) * 2
                 +  ((int128_t)a[ 2]) * a[ 2];
    int128_t t5   = (((int128_t)a[ 0]) * a[ 5]
                 +  ((int128_t)a[ 1]) * a[ 4]
                 +  ((int128_t)a[ 2]) * a[ 3]) * 2;
    int128_t t6   = (((int128_t)a[ 0]) * a[ 6]
                 +  ((int128_t)a[ 1]) * a[ 5]
                 +  ((int128_t)a[ 2]) * a[ 4]) * 2
                 +  ((int128_t)a[ 3]) * a[ 3];
    int128_t t7   = (((int128_t)a[ 1]) * a[ 6]
                 +  ((int128_t)a[ 2]) * a[ 5]
                 +  ((int128_t)a[ 3]) * a[ 4]) * 2;
    int128_t t8   = (((int128_t)a[ 2]) * a[ 6]
                 +  ((int128_t)a[ 3]) * a[ 5]) * 2
                 +  ((int128_t)a[ 4]) * a[ 4];
    int128_t t9   = (((int128_t)a[ 3]) * a[ 6]
                 +  ((int128_t)a[ 4]) * a[ 5]) * 2;
    int128_t t10  = (((int128_t)a[ 4]) * a[ 6]) * 2
                 +  ((int128_t)a[ 5]) * a[ 5];
    int128_t t11  = (((int128_t)a[ 5]) * a[ 6]) * 2;
    int128_t t12  =  ((int128_t)a[ 6]) * a[ 6];

    t1   += t0  >> 55; r[ 0] = t0  & 0x7fffffffffffffL;
    t2   += t1  >> 55; r[ 1] = t1  & 0x7fffffffffffffL;
    t3   += t2  >> 55; r[ 2] = t2  & 0x7fffffffffffffL;
    t4   += t3  >> 55; r[ 3] = t3  & 0x7fffffffffffffL;
    t5   += t4  >> 55; r[ 4] = t4  & 0x7fffffffffffffL;
    t6   += t5  >> 55; r[ 5] = t5  & 0x7fffffffffffffL;
    t7   += t6  >> 55; r[ 6] = t6  & 0x7fffffffffffffL;
    t8   += t7  >> 55; r[ 7] = t7  & 0x7fffffffffffffL;
    t9   += t8  >> 55; r[ 8] = t8  & 0x7fffffffffffffL;
    t10  += t9  >> 55; r[ 9] = t9  & 0x7fffffffffffffL;
    t11  += t10 >> 55; r[10] = t10 & 0x7fffffffffffffL;
    t12  += t11 >> 55; r[11] = t11 & 0x7fffffffffffffL;
    r[13] = (sp_digit)(t12 >> 55);
                       r[12] = t12 & 0x7fffffffffffffL;
}

#endif /* WOLFSSL_SP_SMALL */
/* Square the Montgomery form number. (r = a * a mod m)
 *
 * r   Result of squaring.
 * a   Number to square in Montogmery form.
 * m   Modulus (prime).
 * mp  Montogmery mulitplier.
 */
static void sp_384_mont_sqr_7(sp_digit* r, const sp_digit* a, const sp_digit* m,
        sp_digit mp)
{
    sp_384_sqr_7(r, a);
    sp_384_mont_reduce_7(r, m, mp);
}

#if !defined(WOLFSSL_SP_SMALL) || defined(HAVE_COMP_KEY)
/* Square the Montgomery form number a number of times. (r = a ^ n mod m)
 *
 * r   Result of squaring.
 * a   Number to square in Montogmery form.
 * n   Number of times to square.
 * m   Modulus (prime).
 * mp  Montogmery mulitplier.
 */
static void sp_384_mont_sqr_n_7(sp_digit* r, const sp_digit* a, int n,
        const sp_digit* m, sp_digit mp)
{
    sp_384_mont_sqr_7(r, a, m, mp);
    for (; n > 1; n--) {
        sp_384_mont_sqr_7(r, r, m, mp);
    }
}

#endif /* !WOLFSSL_SP_SMALL || HAVE_COMP_KEY */
#ifdef WOLFSSL_SP_SMALL
/* Mod-2 for the P384 curve. */
static const uint64_t p384_mod_minus_2[6] = {
    0x00000000fffffffdU,0xffffffff00000000U,0xfffffffffffffffeU,
    0xffffffffffffffffU,0xffffffffffffffffU,0xffffffffffffffffU
};
#endif /* !WOLFSSL_SP_SMALL */

/* Invert the number, in Montgomery form, modulo the modulus (prime) of the
 * P384 curve. (r = 1 / a mod m)
 *
 * r   Inverse result.
 * a   Number to invert.
 * td  Temporary data.
 */
static void sp_384_mont_inv_7(sp_digit* r, const sp_digit* a, sp_digit* td)
{
#ifdef WOLFSSL_SP_SMALL
    sp_digit* t = td;
    int i;

    XMEMCPY(t, a, sizeof(sp_digit) * 7);
    for (i=382; i>=0; i--) {
        sp_384_mont_sqr_7(t, t, p384_mod, p384_mp_mod);
        if (p384_mod_minus_2[i / 64] & ((sp_digit)1 << (i % 64)))
            sp_384_mont_mul_7(t, t, a, p384_mod, p384_mp_mod);
    }
    XMEMCPY(r, t, sizeof(sp_digit) * 7);
#else
    sp_digit* t1 = td;
    sp_digit* t2 = td + 2 * 7;
    sp_digit* t3 = td + 4 * 7;
    sp_digit* t4 = td + 6 * 7;
    sp_digit* t5 = td + 8 * 7;

    /* 0x2 */
    sp_384_mont_sqr_7(t1, a, p384_mod, p384_mp_mod);
    /* 0x3 */
    sp_384_mont_mul_7(t5, t1, a, p384_mod, p384_mp_mod);
    /* 0xc */
    sp_384_mont_sqr_n_7(t1, t5, 2, p384_mod, p384_mp_mod);
    /* 0xf */
    sp_384_mont_mul_7(t2, t5, t1, p384_mod, p384_mp_mod);
    /* 0x1e */
    sp_384_mont_sqr_7(t1, t2, p384_mod, p384_mp_mod);
    /* 0x1f */
    sp_384_mont_mul_7(t4, t1, a, p384_mod, p384_mp_mod);
    /* 0x3e0 */
    sp_384_mont_sqr_n_7(t1, t4, 5, p384_mod, p384_mp_mod);
    /* 0x3ff */
    sp_384_mont_mul_7(t2, t4, t1, p384_mod, p384_mp_mod);
    /* 0x7fe0 */
    sp_384_mont_sqr_n_7(t1, t2, 5, p384_mod, p384_mp_mod);
    /* 0x7fff */
    sp_384_mont_mul_7(t4, t4, t1, p384_mod, p384_mp_mod);
    /* 0x3fff8000 */
    sp_384_mont_sqr_n_7(t1, t4, 15, p384_mod, p384_mp_mod);
    /* 0x3fffffff */
    sp_384_mont_mul_7(t2, t4, t1, p384_mod, p384_mp_mod);
    /* 0xfffffffc */
    sp_384_mont_sqr_n_7(t3, t2, 2, p384_mod, p384_mp_mod);
    /* 0xfffffffd */
    sp_384_mont_mul_7(r, t3, a, p384_mod, p384_mp_mod);
    /* 0xffffffff */
    sp_384_mont_mul_7(t3, t5, t3, p384_mod, p384_mp_mod);
    /* 0xfffffffc0000000 */
    sp_384_mont_sqr_n_7(t1, t2, 30, p384_mod, p384_mp_mod);
    /* 0xfffffffffffffff */
    sp_384_mont_mul_7(t2, t2, t1, p384_mod, p384_mp_mod);
    /* 0xfffffffffffffff000000000000000 */
    sp_384_mont_sqr_n_7(t1, t2, 60, p384_mod, p384_mp_mod);
    /* 0xffffffffffffffffffffffffffffff */
    sp_384_mont_mul_7(t2, t2, t1, p384_mod, p384_mp_mod);
    /* 0xffffffffffffffffffffffffffffff000000000000000000000000000000 */
    sp_384_mont_sqr_n_7(t1, t2, 120, p384_mod, p384_mp_mod);
    /* 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff */
    sp_384_mont_mul_7(t2, t2, t1, p384_mod, p384_mp_mod);
    /* 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff8000 */
    sp_384_mont_sqr_n_7(t1, t2, 15, p384_mod, p384_mp_mod);
    /* 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff */
    sp_384_mont_mul_7(t2, t4, t1, p384_mod, p384_mp_mod);
    /* 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe00000000 */
    sp_384_mont_sqr_n_7(t1, t2, 33, p384_mod, p384_mp_mod);
    /* 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff */
    sp_384_mont_mul_7(t2, t3, t1, p384_mod, p384_mp_mod);
    /* 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff000000000000000000000000 */
    sp_384_mont_sqr_n_7(t1, t2, 96, p384_mod, p384_mp_mod);
    /* 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffd */
    sp_384_mont_mul_7(r, r, t1, p384_mod, p384_mp_mod);

#endif /* WOLFSSL_SP_SMALL */
}

/* Map the Montgomery form projective coordinate point to an affine point.
 *
 * r  Resulting affine coordinate point.
 * p  Montgomery form projective coordinate point.
 * t  Temporary ordinate data.
 */
static void sp_384_map_7(sp_point_384* r, const sp_point_384* p, sp_digit* t)
{
    sp_digit* t1 = t;
    sp_digit* t2 = t + 2*7;
    int64_t n;

    sp_384_mont_inv_7(t1, p->z, t + 2*7);

    sp_384_mont_sqr_7(t2, t1, p384_mod, p384_mp_mod);
    sp_384_mont_mul_7(t1, t2, t1, p384_mod, p384_mp_mod);

    /* x /= z^2 */
    sp_384_mont_mul_7(r->x, p->x, t2, p384_mod, p384_mp_mod);
    XMEMSET(r->x + 7, 0, sizeof(r->x) / 2U);
    sp_384_mont_reduce_7(r->x, p384_mod, p384_mp_mod);
    /* Reduce x to less than modulus */
    n = sp_384_cmp_7(r->x, p384_mod);
    sp_384_cond_sub_7(r->x, r->x, p384_mod, 0 - ((n >= 0) ?
                (sp_digit)1 : (sp_digit)0));
    sp_384_norm_7(r->x);

    /* y /= z^3 */
    sp_384_mont_mul_7(r->y, p->y, t1, p384_mod, p384_mp_mod);
    XMEMSET(r->y + 7, 0, sizeof(r->y) / 2U);
    sp_384_mont_reduce_7(r->y, p384_mod, p384_mp_mod);
    /* Reduce y to less than modulus */
    n = sp_384_cmp_7(r->y, p384_mod);
    sp_384_cond_sub_7(r->y, r->y, p384_mod, 0 - ((n >= 0) ?
                (sp_digit)1 : (sp_digit)0));
    sp_384_norm_7(r->y);

    XMEMSET(r->z, 0, sizeof(r->z));
    r->z[0] = 1;

}

#ifdef WOLFSSL_SP_SMALL
/* Add b to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_384_add_7(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 7; i++) {
        r[i] = a[i] + b[i];
    }

    return 0;
}
#else
/* Add b to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_384_add_7(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    r[ 0] = a[ 0] + b[ 0];
    r[ 1] = a[ 1] + b[ 1];
    r[ 2] = a[ 2] + b[ 2];
    r[ 3] = a[ 3] + b[ 3];
    r[ 4] = a[ 4] + b[ 4];
    r[ 5] = a[ 5] + b[ 5];
    r[ 6] = a[ 6] + b[ 6];

    return 0;
}

#endif /* WOLFSSL_SP_SMALL */
/* Add two Montgomery form numbers (r = a + b % m).
 *
 * r   Result of addition.
 * a   First number to add in Montogmery form.
 * b   Second number to add in Montogmery form.
 * m   Modulus (prime).
 */
static void sp_384_mont_add_7(sp_digit* r, const sp_digit* a, const sp_digit* b,
        const sp_digit* m)
{
    (void)sp_384_add_7(r, a, b);
    sp_384_norm_7(r);
    sp_384_cond_sub_7(r, r, m, 0 - (((r[6] >> 54) > 0) ?
                (sp_digit)1 : (sp_digit)0));
    sp_384_norm_7(r);
}

/* Double a Montgomery form number (r = a + a % m).
 *
 * r   Result of doubling.
 * a   Number to double in Montogmery form.
 * m   Modulus (prime).
 */
static void sp_384_mont_dbl_7(sp_digit* r, const sp_digit* a, const sp_digit* m)
{
    (void)sp_384_add_7(r, a, a);
    sp_384_norm_7(r);
    sp_384_cond_sub_7(r, r, m, 0 - (((r[6] >> 54) > 0) ?
                (sp_digit)1 : (sp_digit)0));
    sp_384_norm_7(r);
}

/* Triple a Montgomery form number (r = a + a + a % m).
 *
 * r   Result of Tripling.
 * a   Number to triple in Montogmery form.
 * m   Modulus (prime).
 */
static void sp_384_mont_tpl_7(sp_digit* r, const sp_digit* a, const sp_digit* m)
{
    (void)sp_384_add_7(r, a, a);
    sp_384_norm_7(r);
    sp_384_cond_sub_7(r, r, m, 0 - (((r[6] >> 54) > 0) ?
                (sp_digit)1 : (sp_digit)0));
    sp_384_norm_7(r);
    (void)sp_384_add_7(r, r, a);
    sp_384_norm_7(r);
    sp_384_cond_sub_7(r, r, m, 0 - (((r[6] >> 54) > 0) ?
                (sp_digit)1 : (sp_digit)0));
    sp_384_norm_7(r);
}

#ifdef WOLFSSL_SP_SMALL
/* Sub b from a into r. (r = a - b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_384_sub_7(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    int i;

    for (i = 0; i < 7; i++) {
        r[i] = a[i] - b[i];
    }

    return 0;
}

#else
/* Sub b from a into r. (r = a - b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
SP_NOINLINE static int sp_384_sub_7(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    r[ 0] = a[ 0] - b[ 0];
    r[ 1] = a[ 1] - b[ 1];
    r[ 2] = a[ 2] - b[ 2];
    r[ 3] = a[ 3] - b[ 3];
    r[ 4] = a[ 4] - b[ 4];
    r[ 5] = a[ 5] - b[ 5];
    r[ 6] = a[ 6] - b[ 6];

    return 0;
}

#endif /* WOLFSSL_SP_SMALL */
/* Conditionally add a and b using the mask m.
 * m is -1 to add and 0 when not.
 *
 * r  A single precision number representing conditional add result.
 * a  A single precision number to add with.
 * b  A single precision number to add.
 * m  Mask value to apply.
 */
static void sp_384_cond_add_7(sp_digit* r, const sp_digit* a,
        const sp_digit* b, const sp_digit m)
{
#ifdef WOLFSSL_SP_SMALL
    int i;

    for (i = 0; i < 7; i++) {
        r[i] = a[i] + (b[i] & m);
    }
#else
    r[ 0] = a[ 0] + (b[ 0] & m);
    r[ 1] = a[ 1] + (b[ 1] & m);
    r[ 2] = a[ 2] + (b[ 2] & m);
    r[ 3] = a[ 3] + (b[ 3] & m);
    r[ 4] = a[ 4] + (b[ 4] & m);
    r[ 5] = a[ 5] + (b[ 5] & m);
    r[ 6] = a[ 6] + (b[ 6] & m);
#endif /* WOLFSSL_SP_SMALL */
}

/* Subtract two Montgomery form numbers (r = a - b % m).
 *
 * r   Result of subtration.
 * a   Number to subtract from in Montogmery form.
 * b   Number to subtract with in Montogmery form.
 * m   Modulus (prime).
 */
static void sp_384_mont_sub_7(sp_digit* r, const sp_digit* a, const sp_digit* b,
        const sp_digit* m)
{
    (void)sp_384_sub_7(r, a, b);
    sp_384_cond_add_7(r, r, m, r[6] >> 54);
    sp_384_norm_7(r);
}

/* Shift number left one bit.
 * Bottom bit is lost.
 *
 * r  Result of shift.
 * a  Number to shift.
 */
SP_NOINLINE static void sp_384_rshift1_7(sp_digit* r, sp_digit* a)
{
#ifdef WOLFSSL_SP_SMALL
    int i;

    for (i=0; i<6; i++) {
        r[i] = ((a[i] >> 1) + (a[i + 1] << 54)) & 0x7fffffffffffffL;
    }
#else
    r[0] = (a[0] >> 1) + ((a[1] << 54) & 0x7fffffffffffffL);
    r[1] = (a[1] >> 1) + ((a[2] << 54) & 0x7fffffffffffffL);
    r[2] = (a[2] >> 1) + ((a[3] << 54) & 0x7fffffffffffffL);
    r[3] = (a[3] >> 1) + ((a[4] << 54) & 0x7fffffffffffffL);
    r[4] = (a[4] >> 1) + ((a[5] << 54) & 0x7fffffffffffffL);
    r[5] = (a[5] >> 1) + ((a[6] << 54) & 0x7fffffffffffffL);
#endif
    r[6] = a[6] >> 1;
}

/* Divide the number by 2 mod the modulus (prime). (r = a / 2 % m)
 *
 * r  Result of division by 2.
 * a  Number to divide.
 * m  Modulus (prime).
 */
static void sp_384_div2_7(sp_digit* r, const sp_digit* a, const sp_digit* m)
{
    sp_384_cond_add_7(r, a, m, 0 - (a[0] & 1));
    sp_384_norm_7(r);
    sp_384_rshift1_7(r, r);
}

/* Double the Montgomery form projective point p.
 *
 * r  Result of doubling point.
 * p  Point to double.
 * t  Temporary ordinate data.
 */

static void sp_384_proj_point_dbl_7(sp_point_384* r, const sp_point_384* p, sp_digit* t)
{
    sp_digit* t1 = t;
    sp_digit* t2 = t + 2*7;
    sp_digit* x;
    sp_digit* y;
    sp_digit* z;

    x = r->x;
    y = r->y;
    z = r->z;
    /* Put infinity into result. */
    if (r != p) {
        r->infinity = p->infinity;
    }

    /* T1 = Z * Z */
    sp_384_mont_sqr_7(t1, p->z, p384_mod, p384_mp_mod);
    /* Z = Y * Z */
    sp_384_mont_mul_7(z, p->y, p->z, p384_mod, p384_mp_mod);
    /* Z = 2Z */
    sp_384_mont_dbl_7(z, z, p384_mod);
    /* T2 = X - T1 */
    sp_384_mont_sub_7(t2, p->x, t1, p384_mod);
    /* T1 = X + T1 */
    sp_384_mont_add_7(t1, p->x, t1, p384_mod);
    /* T2 = T1 * T2 */
    sp_384_mont_mul_7(t2, t1, t2, p384_mod, p384_mp_mod);
    /* T1 = 3T2 */
    sp_384_mont_tpl_7(t1, t2, p384_mod);
    /* Y = 2Y */
    sp_384_mont_dbl_7(y, p->y, p384_mod);
    /* Y = Y * Y */
    sp_384_mont_sqr_7(y, y, p384_mod, p384_mp_mod);
    /* T2 = Y * Y */
    sp_384_mont_sqr_7(t2, y, p384_mod, p384_mp_mod);
    /* T2 = T2/2 */
    sp_384_div2_7(t2, t2, p384_mod);
    /* Y = Y * X */
    sp_384_mont_mul_7(y, y, p->x, p384_mod, p384_mp_mod);
    /* X = T1 * T1 */
    sp_384_mont_sqr_7(x, t1, p384_mod, p384_mp_mod);
    /* X = X - Y */
    sp_384_mont_sub_7(x, x, y, p384_mod);
    /* X = X - Y */
    sp_384_mont_sub_7(x, x, y, p384_mod);
    /* Y = Y - X */
    sp_384_mont_sub_7(y, y, x, p384_mod);
    /* Y = Y * T1 */
    sp_384_mont_mul_7(y, y, t1, p384_mod, p384_mp_mod);
    /* Y = Y - T2 */
    sp_384_mont_sub_7(y, y, t2, p384_mod);
}

/* Compare two numbers to determine if they are equal.
 * Constant time implementation.
 *
 * a  First number to compare.
 * b  Second number to compare.
 * returns 1 when equal and 0 otherwise.
 */
static int sp_384_cmp_equal_7(const sp_digit* a, const sp_digit* b)
{
    return ((a[0] ^ b[0]) | (a[1] ^ b[1]) | (a[2] ^ b[2]) | (a[3] ^ b[3]) |
            (a[4] ^ b[4]) | (a[5] ^ b[5]) | (a[6] ^ b[6])) == 0;
}

/* Add two Montgomery form projective points.
 *
 * r  Result of addition.
 * p  First point to add.
 * q  Second point to add.
 * t  Temporary ordinate data.
 */


static void sp_384_proj_point_add_7(sp_point_384* r, const sp_point_384* p, const sp_point_384* q,
        sp_digit* t)
{
    const sp_point_384* ap[2];
    sp_point_384* rp[2];
    sp_digit* t1 = t;
    sp_digit* t2 = t + 2*7;
    sp_digit* t3 = t + 4*7;
    sp_digit* t4 = t + 6*7;
    sp_digit* t5 = t + 8*7;
    sp_digit* x;
    sp_digit* y;
    sp_digit* z;
    int i;

    /* Ensure only the first point is the same as the result. */
    if (q == r) {
        const sp_point_384* a = p;
        p = q;
        q = a;
    }

    /* Check double */
    (void)sp_384_sub_7(t1, p384_mod, q->y);
    sp_384_norm_7(t1);
    if ((sp_384_cmp_equal_7(p->x, q->x) & sp_384_cmp_equal_7(p->z, q->z) &
        (sp_384_cmp_equal_7(p->y, q->y) | sp_384_cmp_equal_7(p->y, t1))) != 0) {
        sp_384_proj_point_dbl_7(r, p, t);
    }
    else {
        rp[0] = r;

        /*lint allow cast to different type of pointer*/
        rp[1] = (sp_point_384*)t; /*lint !e9087 !e740*/
        XMEMSET(rp[1], 0, sizeof(sp_point_384));
        x = rp[p->infinity | q->infinity]->x;
        y = rp[p->infinity | q->infinity]->y;
        z = rp[p->infinity | q->infinity]->z;

        ap[0] = p;
        ap[1] = q;
        for (i=0; i<7; i++) {
            r->x[i] = ap[p->infinity]->x[i];
        }
        for (i=0; i<7; i++) {
            r->y[i] = ap[p->infinity]->y[i];
        }
        for (i=0; i<7; i++) {
            r->z[i] = ap[p->infinity]->z[i];
        }
        r->infinity = ap[p->infinity]->infinity;

        /* U1 = X1*Z2^2 */
        sp_384_mont_sqr_7(t1, q->z, p384_mod, p384_mp_mod);
        sp_384_mont_mul_7(t3, t1, q->z, p384_mod, p384_mp_mod);
        sp_384_mont_mul_7(t1, t1, x, p384_mod, p384_mp_mod);
        /* U2 = X2*Z1^2 */
        sp_384_mont_sqr_7(t2, z, p384_mod, p384_mp_mod);
        sp_384_mont_mul_7(t4, t2, z, p384_mod, p384_mp_mod);
        sp_384_mont_mul_7(t2, t2, q->x, p384_mod, p384_mp_mod);
        /* S1 = Y1*Z2^3 */
        sp_384_mont_mul_7(t3, t3, y, p384_mod, p384_mp_mod);
        /* S2 = Y2*Z1^3 */
        sp_384_mont_mul_7(t4, t4, q->y, p384_mod, p384_mp_mod);
        /* H = U2 - U1 */
        sp_384_mont_sub_7(t2, t2, t1, p384_mod);
        /* R = S2 - S1 */
        sp_384_mont_sub_7(t4, t4, t3, p384_mod);
        /* Z3 = H*Z1*Z2 */
        sp_384_mont_mul_7(z, z, q->z, p384_mod, p384_mp_mod);
        sp_384_mont_mul_7(z, z, t2, p384_mod, p384_mp_mod);
        /* X3 = R^2 - H^3 - 2*U1*H^2 */
        sp_384_mont_sqr_7(x, t4, p384_mod, p384_mp_mod);
        sp_384_mont_sqr_7(t5, t2, p384_mod, p384_mp_mod);
        sp_384_mont_mul_7(y, t1, t5, p384_mod, p384_mp_mod);
        sp_384_mont_mul_7(t5, t5, t2, p384_mod, p384_mp_mod);
        sp_384_mont_sub_7(x, x, t5, p384_mod);
        sp_384_mont_dbl_7(t1, y, p384_mod);
        sp_384_mont_sub_7(x, x, t1, p384_mod);
        /* Y3 = R*(U1*H^2 - X3) - S1*H^3 */
        sp_384_mont_sub_7(y, y, x, p384_mod);
        sp_384_mont_mul_7(y, y, t4, p384_mod, p384_mp_mod);
        sp_384_mont_mul_7(t5, t5, t3, p384_mod, p384_mp_mod);
        sp_384_mont_sub_7(y, y, t5, p384_mod);
    }
}

#ifdef WOLFSSL_SP_SMALL
/* Multiply the point by the scalar and return the result.
 * If map is true then convert result to affine coordinates.
 *
 * r     Resulting point.
 * g     Point to multiply.
 * k     Scalar to multiply by.
 * map   Indicates whether to convert result to affine.
 * ct    Constant time required.
 * heap  Heap to use for allocation.
 * returns MEMORY_E when memory allocation fails and MP_OKAY on success.
 */



static int sp_384_ecc_mulmod_7(sp_point_384* r, const sp_point_384* g, const sp_digit* k,
        int map, int ct, void* heap)
{
#ifdef WOLFSSL_SP_NO_MALLOC
    sp_point_384 t[3];
    sp_digit tmp[2 * 7 * 6];
#else
    sp_point_384* t;
    sp_digit* tmp;
#endif
    sp_digit n;
    int i;
    int c, y;
    int err = MP_OKAY;

    /* Implementatio is constant time. */
    (void)ct;
    (void)heap;

#ifndef WOLFSSL_SP_NO_MALLOC
    t = (sp_point_384*)XMALLOC(sizeof(sp_point_384) * 3, heap, DYNAMIC_TYPE_ECC);
    if (t == NULL)
        err = MEMORY_E;
    tmp = (sp_digit*)XMALLOC(sizeof(sp_digit) * 2 * 7 * 6, heap,
                                                              DYNAMIC_TYPE_ECC);
    if (tmp == NULL)
        err = MEMORY_E;
#endif

    if (err == MP_OKAY) {
        XMEMSET(t, 0, sizeof(sp_point_384) * 3);

        /* t[0] = {0, 0, 1} * norm */
        t[0].infinity = 1;
        /* t[1] = {g->x, g->y, g->z} * norm */
        err = sp_384_mod_mul_norm_7(t[1].x, g->x, p384_mod);
    }
    if (err == MP_OKAY)
        err = sp_384_mod_mul_norm_7(t[1].y, g->y, p384_mod);
    if (err == MP_OKAY)
        err = sp_384_mod_mul_norm_7(t[1].z, g->z, p384_mod);

    if (err == MP_OKAY) {
        i = 6;
        c = 54;
        n = k[i--] << (55 - c);
        for (; ; c--) {
            if (c == 0) {
                if (i == -1)
                    break;

                n = k[i--];
                c = 55;
            }

            y = (n >> 54) & 1;
            n <<= 1;

            sp_384_proj_point_add_7(&t[y^1], &t[0], &t[1], tmp);

            XMEMCPY(&t[2], (void*)(((size_t)&t[0] & addr_mask[y^1]) +
                                   ((size_t)&t[1] & addr_mask[y])),
                    sizeof(sp_point_384));
            sp_384_proj_point_dbl_7(&t[2], &t[2], tmp);
            XMEMCPY((void*)(((size_t)&t[0] & addr_mask[y^1]) +
                            ((size_t)&t[1] & addr_mask[y])), &t[2],
                    sizeof(sp_point_384));
        }

        if (map != 0) {
            sp_384_map_7(r, &t[0], tmp);
        }
        else {
            XMEMCPY(r, &t[0], sizeof(sp_point_384));
        }
    }

#ifndef WOLFSSL_SP_NO_MALLOC
    if (tmp != NULL) {
        XMEMSET(tmp, 0, sizeof(sp_digit) * 2 * 7 * 6);
        XFREE(tmp, NULL, DYNAMIC_TYPE_ECC);
    }
    if (t != NULL) {
        XMEMSET(t, 0, sizeof(sp_point_384) * 3);
        XFREE(t, NULL, DYNAMIC_TYPE_ECC);
    }
#else
    ForceZero(tmp, sizeof(tmp));
    ForceZero(t, sizeof(t));
#endif

    return err;
}

#else
/* A table entry for pre-computed points. */
typedef struct sp_table_entry_384 {
    sp_digit x[7];
    sp_digit y[7];
} sp_table_entry_384;

/* Conditionally copy a into r using the mask m.
 * m is -1 to copy and 0 when not.
 *
 * r  A single precision number to copy over.
 * a  A single precision number to copy.
 * m  Mask value to apply.
 */
static void sp_384_cond_copy_7(sp_digit* r, const sp_digit* a, const sp_digit m)
{
    sp_digit t[7];
#ifdef WOLFSSL_SP_SMALL
    int i;

    for (i = 0; i < 7; i++) {
        t[i] = r[i] ^ a[i];
    }
    for (i = 0; i < 7; i++) {
        r[i] ^= t[i] & m;
    }
#else
    t[ 0] = r[ 0] ^ a[ 0];
    t[ 1] = r[ 1] ^ a[ 1];
    t[ 2] = r[ 2] ^ a[ 2];
    t[ 3] = r[ 3] ^ a[ 3];
    t[ 4] = r[ 4] ^ a[ 4];
    t[ 5] = r[ 5] ^ a[ 5];
    t[ 6] = r[ 6] ^ a[ 6];
    r[ 0] ^= t[ 0] & m;
    r[ 1] ^= t[ 1] & m;
    r[ 2] ^= t[ 2] & m;
    r[ 3] ^= t[ 3] & m;
    r[ 4] ^= t[ 4] & m;
    r[ 5] ^= t[ 5] & m;
    r[ 6] ^= t[ 6] & m;
#endif /* WOLFSSL_SP_SMALL */
}

/* Double the Montgomery form projective point p a number of times.
 *
 * r  Result of repeated doubling of point.
 * p  Point to double.
 * n  Number of times to double
 * t  Temporary ordinate data.
 */
static void sp_384_proj_point_dbl_n_7(sp_point_384* p, int n, sp_digit* t)
{
    sp_digit* w = t;
    sp_digit* a = t + 2*7;
    sp_digit* b = t + 4*7;
    sp_digit* t1 = t + 6*7;
    sp_digit* t2 = t + 8*7;
    sp_digit* x;
    sp_digit* y;
    sp_digit* z;

    x = p->x;
    y = p->y;
    z = p->z;

    /* Y = 2*Y */
    sp_384_mont_dbl_7(y, y, p384_mod);
    /* W = Z^4 */
    sp_384_mont_sqr_7(w, z, p384_mod, p384_mp_mod);
    sp_384_mont_sqr_7(w, w, p384_mod, p384_mp_mod);

#ifndef WOLFSSL_SP_SMALL
    while (--n > 0)
#else
    while (--n >= 0)
#endif
    {
        /* A = 3*(X^2 - W) */
        sp_384_mont_sqr_7(t1, x, p384_mod, p384_mp_mod);
        sp_384_mont_sub_7(t1, t1, w, p384_mod);
        sp_384_mont_tpl_7(a, t1, p384_mod);
        /* B = X*Y^2 */
        sp_384_mont_sqr_7(t1, y, p384_mod, p384_mp_mod);
        sp_384_mont_mul_7(b, t1, x, p384_mod, p384_mp_mod);
        /* X = A^2 - 2B */
        sp_384_mont_sqr_7(x, a, p384_mod, p384_mp_mod);
        sp_384_mont_dbl_7(t2, b, p384_mod);
        sp_384_mont_sub_7(x, x, t2, p384_mod);
        /* Z = Z*Y */
        sp_384_mont_mul_7(z, z, y, p384_mod, p384_mp_mod);
        /* t2 = Y^4 */
        sp_384_mont_sqr_7(t1, t1, p384_mod, p384_mp_mod);
#ifdef WOLFSSL_SP_SMALL
        if (n != 0)
#endif
        {
            /* W = W*Y^4 */
            sp_384_mont_mul_7(w, w, t1, p384_mod, p384_mp_mod);
        }
        /* y = 2*A*(B - X) - Y^4 */
        sp_384_mont_sub_7(y, b, x, p384_mod);
        sp_384_mont_mul_7(y, y, a, p384_mod, p384_mp_mod);
        sp_384_mont_dbl_7(y, y, p384_mod);
        sp_384_mont_sub_7(y, y, t1, p384_mod);
    }
#ifndef WOLFSSL_SP_SMALL
    /* A = 3*(X^2 - W) */
    sp_384_mont_sqr_7(t1, x, p384_mod, p384_mp_mod);
    sp_384_mont_sub_7(t1, t1, w, p384_mod);
    sp_384_mont_tpl_7(a, t1, p384_mod);
    /* B = X*Y^2 */
    sp_384_mont_sqr_7(t1, y, p384_mod, p384_mp_mod);
    sp_384_mont_mul_7(b, t1, x, p384_mod, p384_mp_mod);
    /* X = A^2 - 2B */
    sp_384_mont_sqr_7(x, a, p384_mod, p384_mp_mod);
    sp_384_mont_dbl_7(t2, b, p384_mod);
    sp_384_mont_sub_7(x, x, t2, p384_mod);
    /* Z = Z*Y */
    sp_384_mont_mul_7(z, z, y, p384_mod, p384_mp_mod);
    /* t2 = Y^4 */
    sp_384_mont_sqr_7(t1, t1, p384_mod, p384_mp_mod);
    /* y = 2*A*(B - X) - Y^4 */
    sp_384_mont_sub_7(y, b, x, p384_mod);
    sp_384_mont_mul_7(y, y, a, p384_mod, p384_mp_mod);
    sp_384_mont_dbl_7(y, y, p384_mod);
    sp_384_mont_sub_7(y, y, t1, p384_mod);
#endif
    /* Y = Y/2 */
    sp_384_div2_7(y, y, p384_mod);
}

/* Double the Montgomery form projective point p a number of times.
 *
 * r  Result of repeated doubling of point.
 * p  Point to double.
 * n  Number of times to double
 * t  Temporary ordinate data.
 */
static void sp_384_proj_point_dbl_n_store_7(sp_point_384* r, const sp_point_384* p,
        int n, int m, sp_digit* t)
{
    sp_digit* w = t;
    sp_digit* a = t + 2*7;
    sp_digit* b = t + 4*7;
    sp_digit* t1 = t + 6*7;
    sp_digit* t2 = t + 8*7;
    sp_digit* x = r[2*m].x;
    sp_digit* y = r[(1<<n)*m].y;
    sp_digit* z = r[2*m].z;
    int i;

    for (i=0; i<7; i++) {
        x[i] = p->x[i];
    }
    for (i=0; i<7; i++) {
        y[i] = p->y[i];
    }
    for (i=0; i<7; i++) {
        z[i] = p->z[i];
    }

    /* Y = 2*Y */
    sp_384_mont_dbl_7(y, y, p384_mod);
    /* W = Z^4 */
    sp_384_mont_sqr_7(w, z, p384_mod, p384_mp_mod);
    sp_384_mont_sqr_7(w, w, p384_mod, p384_mp_mod);
    for (i=1; i<=n; i++) {
        /* A = 3*(X^2 - W) */
        sp_384_mont_sqr_7(t1, x, p384_mod, p384_mp_mod);
        sp_384_mont_sub_7(t1, t1, w, p384_mod);
        sp_384_mont_tpl_7(a, t1, p384_mod);
        /* B = X*Y^2 */
        sp_384_mont_sqr_7(t2, y, p384_mod, p384_mp_mod);
        sp_384_mont_mul_7(b, t2, x, p384_mod, p384_mp_mod);
        x = r[(1<<i)*m].x;
        /* X = A^2 - 2B */
        sp_384_mont_sqr_7(x, a, p384_mod, p384_mp_mod);
        sp_384_mont_dbl_7(t1, b, p384_mod);
        sp_384_mont_sub_7(x, x, t1, p384_mod);
        /* Z = Z*Y */
        sp_384_mont_mul_7(r[(1<<i)*m].z, z, y, p384_mod, p384_mp_mod);
        z = r[(1<<i)*m].z;
        /* t2 = Y^4 */
        sp_384_mont_sqr_7(t2, t2, p384_mod, p384_mp_mod);
        if (i != n) {
            /* W = W*Y^4 */
            sp_384_mont_mul_7(w, w, t2, p384_mod, p384_mp_mod);
        }
        /* y = 2*A*(B - X) - Y^4 */
        sp_384_mont_sub_7(y, b, x, p384_mod);
        sp_384_mont_mul_7(y, y, a, p384_mod, p384_mp_mod);
        sp_384_mont_dbl_7(y, y, p384_mod);
        sp_384_mont_sub_7(y, y, t2, p384_mod);

        /* Y = Y/2 */
        sp_384_div2_7(r[(1<<i)*m].y, y, p384_mod);
        r[(1<<i)*m].infinity = 0;
    }
}

/* Add two Montgomery form projective points.
 *
 * ra  Result of addition.
 * rs  Result of subtraction.
 * p   First point to add.
 * q   Second point to add.
 * t   Temporary ordinate data.
 */
static void sp_384_proj_point_add_sub_7(sp_point_384* ra, sp_point_384* rs,
        const sp_point_384* p, const sp_point_384* q, sp_digit* t)
{
    sp_digit* t1 = t;
    sp_digit* t2 = t + 2*7;
    sp_digit* t3 = t + 4*7;
    sp_digit* t4 = t + 6*7;
    sp_digit* t5 = t + 8*7;
    sp_digit* t6 = t + 10*7;
    sp_digit* x = ra->x;
    sp_digit* y = ra->y;
    sp_digit* z = ra->z;
    sp_digit* xs = rs->x;
    sp_digit* ys = rs->y;
    sp_digit* zs = rs->z;


    XMEMCPY(x, p->x, sizeof(p->x) / 2);
    XMEMCPY(y, p->y, sizeof(p->y) / 2);
    XMEMCPY(z, p->z, sizeof(p->z) / 2);
    ra->infinity = 0;
    rs->infinity = 0;

    /* U1 = X1*Z2^2 */
    sp_384_mont_sqr_7(t1, q->z, p384_mod, p384_mp_mod);
    sp_384_mont_mul_7(t3, t1, q->z, p384_mod, p384_mp_mod);
    sp_384_mont_mul_7(t1, t1, x, p384_mod, p384_mp_mod);
    /* U2 = X2*Z1^2 */
    sp_384_mont_sqr_7(t2, z, p384_mod, p384_mp_mod);
    sp_384_mont_mul_7(t4, t2, z, p384_mod, p384_mp_mod);
    sp_384_mont_mul_7(t2, t2, q->x, p384_mod, p384_mp_mod);
    /* S1 = Y1*Z2^3 */
    sp_384_mont_mul_7(t3, t3, y, p384_mod, p384_mp_mod);
    /* S2 = Y2*Z1^3 */
    sp_384_mont_mul_7(t4, t4, q->y, p384_mod, p384_mp_mod);
    /* H = U2 - U1 */
    sp_384_mont_sub_7(t2, t2, t1, p384_mod);
    /* RS = S2 + S1 */
    sp_384_mont_add_7(t6, t4, t3, p384_mod);
    /* R = S2 - S1 */
    sp_384_mont_sub_7(t4, t4, t3, p384_mod);
    /* Z3 = H*Z1*Z2 */
    /* ZS = H*Z1*Z2 */
    sp_384_mont_mul_7(z, z, q->z, p384_mod, p384_mp_mod);
    sp_384_mont_mul_7(z, z, t2, p384_mod, p384_mp_mod);
    XMEMCPY(zs, z, sizeof(p->z)/2);
    /* X3 = R^2 - H^3 - 2*U1*H^2 */
    /* XS = RS^2 - H^3 - 2*U1*H^2 */
    sp_384_mont_sqr_7(x, t4, p384_mod, p384_mp_mod);
    sp_384_mont_sqr_7(xs, t6, p384_mod, p384_mp_mod);
    sp_384_mont_sqr_7(t5, t2, p384_mod, p384_mp_mod);
    sp_384_mont_mul_7(y, t1, t5, p384_mod, p384_mp_mod);
    sp_384_mont_mul_7(t5, t5, t2, p384_mod, p384_mp_mod);
    sp_384_mont_sub_7(x, x, t5, p384_mod);
    sp_384_mont_sub_7(xs, xs, t5, p384_mod);
    sp_384_mont_dbl_7(t1, y, p384_mod);
    sp_384_mont_sub_7(x, x, t1, p384_mod);
    sp_384_mont_sub_7(xs, xs, t1, p384_mod);
    /* Y3 = R*(U1*H^2 - X3) - S1*H^3 */
    /* YS = -RS*(U1*H^2 - XS) - S1*H^3 */
    sp_384_mont_sub_7(ys, y, xs, p384_mod);
    sp_384_mont_sub_7(y, y, x, p384_mod);
    sp_384_mont_mul_7(y, y, t4, p384_mod, p384_mp_mod);
    sp_384_sub_7(t6, p384_mod, t6);
    sp_384_mont_mul_7(ys, ys, t6, p384_mod, p384_mp_mod);
    sp_384_mont_mul_7(t5, t5, t3, p384_mod, p384_mp_mod);
    sp_384_mont_sub_7(y, y, t5, p384_mod);
    sp_384_mont_sub_7(ys, ys, t5, p384_mod);
}

/* Structure used to describe recoding of scalar multiplication. */
typedef struct ecc_recode_384 {
    /* Index into pre-computation table. */
    uint8_t i;
    /* Use the negative of the point. */
    uint8_t neg;
} ecc_recode_384;

/* The index into pre-computation table to use. */
static const uint8_t recode_index_7_6[66] = {
     0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
    16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
    32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17,
    16, 15, 14, 13, 12, 11, 10,  9,  8,  7,  6,  5,  4,  3,  2,  1,
     0,  1,
};

/* Whether to negate y-ordinate. */
static const uint8_t recode_neg_7_6[66] = {
     0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
     0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
     1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,
     1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,
     0,  0,
};

/* Recode the scalar for multiplication using pre-computed values and
 * subtraction.
 *
 * k  Scalar to multiply by.
 * v  Vector of operations to perform.
 */
static void sp_384_ecc_recode_6_7(const sp_digit* k, ecc_recode_384* v)
{
    int i, j;
    uint8_t y;
    int carry = 0;
    int o;
    sp_digit n;

    j = 0;
    n = k[j];
    o = 0;
    for (i=0; i<65; i++) {
        y = (int8_t)n;
        if (o + 6 < 55) {
            y &= 0x3f;
            n >>= 6;
            o += 6;
        }
        else if (o + 6 == 55) {
            n >>= 6;
            if (++j < 7)
                n = k[j];
            o = 0;
        }
        else if (++j < 7) {
            n = k[j];
            y |= (uint8_t)((n << (55 - o)) & 0x3f);
            o -= 49;
            n >>= o;
        }

        y += (uint8_t)carry;
        v[i].i = recode_index_7_6[y];
        v[i].neg = recode_neg_7_6[y];
        carry = (y >> 6) + v[i].neg;
    }
}

#ifndef WC_NO_CACHE_RESISTANT
/* Touch each possible point that could be being copied.
 *
 * r      Point to copy into.
 * table  Table - start of the entires to access
 * idx    Index of entry to retrieve.
 */
static void sp_384_get_point_33_7(sp_point_384* r, const sp_point_384* table,
    int idx)
{
    int i;
    sp_digit mask;

    r->x[0] = 0;
    r->x[1] = 0;
    r->x[2] = 0;
    r->x[3] = 0;
    r->x[4] = 0;
    r->x[5] = 0;
    r->x[6] = 0;
    r->y[0] = 0;
    r->y[1] = 0;
    r->y[2] = 0;
    r->y[3] = 0;
    r->y[4] = 0;
    r->y[5] = 0;
    r->y[6] = 0;
    r->z[0] = 0;
    r->z[1] = 0;
    r->z[2] = 0;
    r->z[3] = 0;
    r->z[4] = 0;
    r->z[5] = 0;
    r->z[6] = 0;
    for (i = 1; i < 33; i++) {
        mask = 0 - (i == idx);
        r->x[0] |= mask & table[i].x[0];
        r->x[1] |= mask & table[i].x[1];
        r->x[2] |= mask & table[i].x[2];
        r->x[3] |= mask & table[i].x[3];
        r->x[4] |= mask & table[i].x[4];
        r->x[5] |= mask & table[i].x[5];
        r->x[6] |= mask & table[i].x[6];
        r->y[0] |= mask & table[i].y[0];
        r->y[1] |= mask & table[i].y[1];
        r->y[2] |= mask & table[i].y[2];
        r->y[3] |= mask & table[i].y[3];
        r->y[4] |= mask & table[i].y[4];
        r->y[5] |= mask & table[i].y[5];
        r->y[6] |= mask & table[i].y[6];
        r->z[0] |= mask & table[i].z[0];
        r->z[1] |= mask & table[i].z[1];
        r->z[2] |= mask & table[i].z[2];
        r->z[3] |= mask & table[i].z[3];
        r->z[4] |= mask & table[i].z[4];
        r->z[5] |= mask & table[i].z[5];
        r->z[6] |= mask & table[i].z[6];
    }
}
#endif /* !WC_NO_CACHE_RESISTANT */
/* Multiply the point by the scalar and return the result.
 * If map is true then convert result to affine coordinates.
 *
 * Window technique of 6 bits. (Add-Sub variation.)
 * Calculate 0..32 times the point. Use function that adds and
 * subtracts the same two points.
 * Recode to add or subtract one of the computed points.
 * Double to push up.
 * NOT a sliding window.
 *
 * r     Resulting point.
 * g     Point to multiply.
 * k     Scalar to multiply by.
 * map   Indicates whether to convert result to affine.
 * ct    Constant time required.
 * heap  Heap to use for allocation.
 * returns MEMORY_E when memory allocation fails and MP_OKAY on success.
 */
static int sp_384_ecc_mulmod_win_add_sub_7(sp_point_384* r, const sp_point_384* g,
        const sp_digit* k, int map, int ct, void* heap)
{
#if (!defined(WOLFSSL_SP_SMALL) && !defined(WOLFSSL_SMALL_STACK)) || defined(WOLFSSL_SP_NO_MALLOC)
    sp_point_384 td[33];
    sp_point_384 rtd, pd;
    sp_digit tmpd[2 * 7 * 6];
#endif
    sp_point_384* t;
    sp_point_384* rt;
    sp_point_384* p = NULL;
    sp_digit* tmp;
    sp_digit* negy;
    int i;
    ecc_recode_384 v[65];
    int err;

    /* Constant time used for cache attack resistance implementation. */
    (void)ct;
    (void)heap;

    err = sp_384_point_new_7(heap, rtd, rt);
    if (err == MP_OKAY)
        err = sp_384_point_new_7(heap, pd, p);
#if (defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)) && !defined(WOLFSSL_SP_NO_MALLOC)
    t = (sp_point_384*)XMALLOC(sizeof(sp_point_384) * 33, heap, DYNAMIC_TYPE_ECC);
    if (t == NULL)
        err = MEMORY_E;
    tmp = (sp_digit*)XMALLOC(sizeof(sp_digit) * 2 * 7 * 6, heap,
                             DYNAMIC_TYPE_ECC);
    if (tmp == NULL)
        err = MEMORY_E;
#else
    t = td;
    tmp = tmpd;
#endif


    if (err == MP_OKAY) {
        /* t[0] = {0, 0, 1} * norm */
        XMEMSET(&t[0], 0, sizeof(t[0]));
        t[0].infinity = 1;
        /* t[1] = {g->x, g->y, g->z} * norm */
        err = sp_384_mod_mul_norm_7(t[1].x, g->x, p384_mod);
    }
    if (err == MP_OKAY) {
        err = sp_384_mod_mul_norm_7(t[1].y, g->y, p384_mod);
    }
    if (err == MP_OKAY) {
        err = sp_384_mod_mul_norm_7(t[1].z, g->z, p384_mod);
    }

    if (err == MP_OKAY) {
        t[1].infinity = 0;
        /* t[2] ... t[32]  */
        sp_384_proj_point_dbl_n_store_7(t, &t[ 1], 5, 1, tmp);
        sp_384_proj_point_add_7(&t[ 3], &t[ 2], &t[ 1], tmp);
        sp_384_proj_point_dbl_7(&t[ 6], &t[ 3], tmp);
        sp_384_proj_point_add_sub_7(&t[ 7], &t[ 5], &t[ 6], &t[ 1], tmp);
        sp_384_proj_point_dbl_7(&t[10], &t[ 5], tmp);
        sp_384_proj_point_add_sub_7(&t[11], &t[ 9], &t[10], &t[ 1], tmp);
        sp_384_proj_point_dbl_7(&t[12], &t[ 6], tmp);
        sp_384_proj_point_dbl_7(&t[14], &t[ 7], tmp);
        sp_384_proj_point_add_sub_7(&t[15], &t[13], &t[14], &t[ 1], tmp);
        sp_384_proj_point_dbl_7(&t[18], &t[ 9], tmp);
        sp_384_proj_point_add_sub_7(&t[19], &t[17], &t[18], &t[ 1], tmp);
        sp_384_proj_point_dbl_7(&t[20], &t[10], tmp);
        sp_384_proj_point_dbl_7(&t[22], &t[11], tmp);
        sp_384_proj_point_add_sub_7(&t[23], &t[21], &t[22], &t[ 1], tmp);
        sp_384_proj_point_dbl_7(&t[24], &t[12], tmp);
        sp_384_proj_point_dbl_7(&t[26], &t[13], tmp);
        sp_384_proj_point_add_sub_7(&t[27], &t[25], &t[26], &t[ 1], tmp);
        sp_384_proj_point_dbl_7(&t[28], &t[14], tmp);
        sp_384_proj_point_dbl_7(&t[30], &t[15], tmp);
        sp_384_proj_point_add_sub_7(&t[31], &t[29], &t[30], &t[ 1], tmp);

        negy = t[0].y;

        sp_384_ecc_recode_6_7(k, v);

        i = 64;
    #ifndef WC_NO_CACHE_RESISTANT
        if (ct) {
            sp_384_get_point_33_7(rt, t, v[i].i);
            rt->infinity = !v[i].i;
        }
        else
    #endif
        {
            XMEMCPY(rt, &t[v[i].i], sizeof(sp_point_384));
        }
        for (--i; i>=0; i--) {
            sp_384_proj_point_dbl_n_7(rt, 6, tmp);

        #ifndef WC_NO_CACHE_RESISTANT
            if (ct) {
                sp_384_get_point_33_7(p, t, v[i].i);
                p->infinity = !v[i].i;
            }
            else
        #endif
            {
                XMEMCPY(p, &t[v[i].i], sizeof(sp_point_384));
            }
            sp_384_sub_7(negy, p384_mod, p->y);
            sp_384_cond_copy_7(p->y, negy, (sp_digit)0 - v[i].neg);
            sp_384_proj_point_add_7(rt, rt, p, tmp);
        }

        if (map != 0) {
            sp_384_map_7(r, rt, tmp);
        }
        else {
            XMEMCPY(r, rt, sizeof(sp_point_384));
        }
    }

#if (defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)) && !defined(WOLFSSL_SP_NO_MALLOC)
    if (t != NULL)
        XFREE(t, heap, DYNAMIC_TYPE_ECC);
    if (tmp != NULL)
        XFREE(tmp, heap, DYNAMIC_TYPE_ECC);
#endif
    sp_384_point_free_7(p, 0, heap);
    sp_384_point_free_7(rt, 0, heap);

    return err;
}

#ifdef FP_ECC
#endif /* FP_ECC */
/* Add two Montgomery form projective points. The second point has a q value of
 * one.
 * Only the first point can be the same pointer as the result point.
 *
 * r  Result of addition.
 * p  First point to add.
 * q  Second point to add.
 * t  Temporary ordinate data.
 */
static void sp_384_proj_point_add_qz1_7(sp_point_384* r, const sp_point_384* p,
        const sp_point_384* q, sp_digit* t)
{
    const sp_point_384* ap[2];
    sp_point_384* rp[2];
    sp_digit* t1 = t;
    sp_digit* t2 = t + 2*7;
    sp_digit* t3 = t + 4*7;
    sp_digit* t4 = t + 6*7;
    sp_digit* t5 = t + 8*7;
    sp_digit* x;
    sp_digit* y;
    sp_digit* z;
    int i;

    /* Check double */
    (void)sp_384_sub_7(t1, p384_mod, q->y);
    sp_384_norm_7(t1);
    if ((sp_384_cmp_equal_7(p->x, q->x) & sp_384_cmp_equal_7(p->z, q->z) &
        (sp_384_cmp_equal_7(p->y, q->y) | sp_384_cmp_equal_7(p->y, t1))) != 0) {
        sp_384_proj_point_dbl_7(r, p, t);
    }
    else {
        rp[0] = r;

        /*lint allow cast to different type of pointer*/
        rp[1] = (sp_point_384*)t; /*lint !e9087 !e740*/
        XMEMSET(rp[1], 0, sizeof(sp_point_384));
        x = rp[p->infinity | q->infinity]->x;
        y = rp[p->infinity | q->infinity]->y;
        z = rp[p->infinity | q->infinity]->z;

        ap[0] = p;
        ap[1] = q;
        for (i=0; i<7; i++) {
            r->x[i] = ap[p->infinity]->x[i];
        }
        for (i=0; i<7; i++) {
            r->y[i] = ap[p->infinity]->y[i];
        }
        for (i=0; i<7; i++) {
            r->z[i] = ap[p->infinity]->z[i];
        }
        r->infinity = ap[p->infinity]->infinity;

        /* U2 = X2*Z1^2 */
        sp_384_mont_sqr_7(t2, z, p384_mod, p384_mp_mod);
        sp_384_mont_mul_7(t4, t2, z, p384_mod, p384_mp_mod);
        sp_384_mont_mul_7(t2, t2, q->x, p384_mod, p384_mp_mod);
        /* S2 = Y2*Z1^3 */
        sp_384_mont_mul_7(t4, t4, q->y, p384_mod, p384_mp_mod);
        /* H = U2 - X1 */
        sp_384_mont_sub_7(t2, t2, x, p384_mod);
        /* R = S2 - Y1 */
        sp_384_mont_sub_7(t4, t4, y, p384_mod);
        /* Z3 = H*Z1 */
        sp_384_mont_mul_7(z, z, t2, p384_mod, p384_mp_mod);
        /* X3 = R^2 - H^3 - 2*X1*H^2 */
        sp_384_mont_sqr_7(t1, t4, p384_mod, p384_mp_mod);
        sp_384_mont_sqr_7(t5, t2, p384_mod, p384_mp_mod);
        sp_384_mont_mul_7(t3, x, t5, p384_mod, p384_mp_mod);
        sp_384_mont_mul_7(t5, t5, t2, p384_mod, p384_mp_mod);
        sp_384_mont_sub_7(x, t1, t5, p384_mod);
        sp_384_mont_dbl_7(t1, t3, p384_mod);
        sp_384_mont_sub_7(x, x, t1, p384_mod);
        /* Y3 = R*(X1*H^2 - X3) - Y1*H^3 */
        sp_384_mont_sub_7(t3, t3, x, p384_mod);
        sp_384_mont_mul_7(t3, t3, t4, p384_mod, p384_mp_mod);
        sp_384_mont_mul_7(t5, t5, y, p384_mod, p384_mp_mod);
        sp_384_mont_sub_7(y, t3, t5, p384_mod);
    }
}

#ifdef FP_ECC
/* Convert the projective point to affine.
 * Ordinates are in Montgomery form.
 *
 * a  Point to convert.
 * t  Temporary data.
 */
static void sp_384_proj_to_affine_7(sp_point_384* a, sp_digit* t)
{
    sp_digit* t1 = t;
    sp_digit* t2 = t + 2 * 7;
    sp_digit* tmp = t + 4 * 7;

    sp_384_mont_inv_7(t1, a->z, tmp);

    sp_384_mont_sqr_7(t2, t1, p384_mod, p384_mp_mod);
    sp_384_mont_mul_7(t1, t2, t1, p384_mod, p384_mp_mod);

    sp_384_mont_mul_7(a->x, a->x, t2, p384_mod, p384_mp_mod);
    sp_384_mont_mul_7(a->y, a->y, t1, p384_mod, p384_mp_mod);
    XMEMCPY(a->z, p384_norm_mod, sizeof(p384_norm_mod));
}

/* Generate the pre-computed table of points for the base point.
 *
 * a      The base point.
 * table  Place to store generated point data.
 * tmp    Temporary data.
 * heap  Heap to use for allocation.
 */
static int sp_384_gen_stripe_table_7(const sp_point_384* a,
        sp_table_entry_384* table, sp_digit* tmp, void* heap)
{
#if (!defined(WOLFSSL_SP_SMALL) && !defined(WOLFSSL_SMALL_STACK)) || defined(WOLFSSL_SP_NO_MALLOC)
    sp_point_384 td, s1d, s2d;
#endif
    sp_point_384* t;
    sp_point_384* s1 = NULL;
    sp_point_384* s2 = NULL;
    int i, j;
    int err;

    (void)heap;

    err = sp_384_point_new_7(heap, td, t);
    if (err == MP_OKAY) {
        err = sp_384_point_new_7(heap, s1d, s1);
    }
    if (err == MP_OKAY) {
        err = sp_384_point_new_7(heap, s2d, s2);
    }

    if (err == MP_OKAY) {
        err = sp_384_mod_mul_norm_7(t->x, a->x, p384_mod);
    }
    if (err == MP_OKAY) {
        err = sp_384_mod_mul_norm_7(t->y, a->y, p384_mod);
    }
    if (err == MP_OKAY) {
        err = sp_384_mod_mul_norm_7(t->z, a->z, p384_mod);
    }
    if (err == MP_OKAY) {
        t->infinity = 0;
        sp_384_proj_to_affine_7(t, tmp);

        XMEMCPY(s1->z, p384_norm_mod, sizeof(p384_norm_mod));
        s1->infinity = 0;
        XMEMCPY(s2->z, p384_norm_mod, sizeof(p384_norm_mod));
        s2->infinity = 0;

        /* table[0] = {0, 0, infinity} */
        XMEMSET(&table[0], 0, sizeof(sp_table_entry_384));
        /* table[1] = Affine version of 'a' in Montgomery form */
        XMEMCPY(table[1].x, t->x, sizeof(table->x));
        XMEMCPY(table[1].y, t->y, sizeof(table->y));

        for (i=1; i<8; i++) {
            sp_384_proj_point_dbl_n_7(t, 48, tmp);
            sp_384_proj_to_affine_7(t, tmp);
            XMEMCPY(table[1<<i].x, t->x, sizeof(table->x));
            XMEMCPY(table[1<<i].y, t->y, sizeof(table->y));
        }

        for (i=1; i<8; i++) {
            XMEMCPY(s1->x, table[1<<i].x, sizeof(table->x));
            XMEMCPY(s1->y, table[1<<i].y, sizeof(table->y));
            for (j=(1<<i)+1; j<(1<<(i+1)); j++) {
                XMEMCPY(s2->x, table[j-(1<<i)].x, sizeof(table->x));
                XMEMCPY(s2->y, table[j-(1<<i)].y, sizeof(table->y));
                sp_384_proj_point_add_qz1_7(t, s1, s2, tmp);
                sp_384_proj_to_affine_7(t, tmp);
                XMEMCPY(table[j].x, t->x, sizeof(table->x));
                XMEMCPY(table[j].y, t->y, sizeof(table->y));
            }
        }
    }

    sp_384_point_free_7(s2, 0, heap);
    sp_384_point_free_7(s1, 0, heap);
    sp_384_point_free_7( t, 0, heap);

    return err;
}

#endif /* FP_ECC */
#ifndef WC_NO_CACHE_RESISTANT
/* Touch each possible entry that could be being copied.
 *
 * r      Point to copy into.
 * table  Table - start of the entires to access
 * idx    Index of entry to retrieve.
 */
static void sp_384_get_entry_256_7(sp_point_384* r,
    const sp_table_entry_384* table, int idx)
{
    int i;
    sp_digit mask;

    r->x[0] = 0;
    r->x[1] = 0;
    r->x[2] = 0;
    r->x[3] = 0;
    r->x[4] = 0;
    r->x[5] = 0;
    r->x[6] = 0;
    r->y[0] = 0;
    r->y[1] = 0;
    r->y[2] = 0;
    r->y[3] = 0;
    r->y[4] = 0;
    r->y[5] = 0;
    r->y[6] = 0;
    for (i = 1; i < 256; i++) {
        mask = 0 - (i == idx);
        r->x[0] |= mask & table[i].x[0];
        r->x[1] |= mask & table[i].x[1];
        r->x[2] |= mask & table[i].x[2];
        r->x[3] |= mask & table[i].x[3];
        r->x[4] |= mask & table[i].x[4];
        r->x[5] |= mask & table[i].x[5];
        r->x[6] |= mask & table[i].x[6];
        r->y[0] |= mask & table[i].y[0];
        r->y[1] |= mask & table[i].y[1];
        r->y[2] |= mask & table[i].y[2];
        r->y[3] |= mask & table[i].y[3];
        r->y[4] |= mask & table[i].y[4];
        r->y[5] |= mask & table[i].y[5];
        r->y[6] |= mask & table[i].y[6];
    }
}
#endif /* !WC_NO_CACHE_RESISTANT */
/* Multiply the point by the scalar and return the result.
 * If map is true then convert result to affine coordinates.
 *
 * Implementation uses striping of bits.
 * Choose bits 8 bits apart.
 *
 * r      Resulting point.
 * k      Scalar to multiply by.
 * table  Pre-computed table.
 * map    Indicates whether to convert result to affine.
 * ct     Constant time required.
 * heap   Heap to use for allocation.
 * returns MEMORY_E when memory allocation fails and MP_OKAY on success.
 */
static int sp_384_ecc_mulmod_stripe_7(sp_point_384* r, const sp_point_384* g,
        const sp_table_entry_384* table, const sp_digit* k, int map,
        int ct, void* heap)
{
#if (!defined(WOLFSSL_SP_SMALL) && !defined(WOLFSSL_SMALL_STACK)) || defined(WOLFSSL_SP_NO_MALLOC)
    sp_point_384 rtd;
    sp_point_384 pd;
    sp_digit td[2 * 7 * 6];
#endif
    sp_point_384* rt;
    sp_point_384* p = NULL;
    sp_digit* t;
    int i, j;
    int y, x;
    int err;

    (void)g;
    /* Constant time used for cache attack resistance implementation. */
    (void)ct;
    (void)heap;


    err = sp_384_point_new_7(heap, rtd, rt);
    if (err == MP_OKAY) {
        err = sp_384_point_new_7(heap, pd, p);
    }
#if (defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)) && !defined(WOLFSSL_SP_NO_MALLOC)
    t = (sp_digit*)XMALLOC(sizeof(sp_digit) * 2 * 7 * 6, heap,
                           DYNAMIC_TYPE_ECC);
    if (t == NULL) {
        err = MEMORY_E;
    }
#else
    t = td;
#endif

    if (err == MP_OKAY) {
        XMEMCPY(p->z, p384_norm_mod, sizeof(p384_norm_mod));
        XMEMCPY(rt->z, p384_norm_mod, sizeof(p384_norm_mod));

        y = 0;
        for (j=0,x=47; j<8; j++,x+=48) {
            y |= (int)(((k[x / 55] >> (x % 55)) & 1) << j);
        }
    #ifndef WC_NO_CACHE_RESISTANT
        if (ct) {
            sp_384_get_entry_256_7(rt, table, y);
        } else
    #endif
        {
            XMEMCPY(rt->x, table[y].x, sizeof(table[y].x));
            XMEMCPY(rt->y, table[y].y, sizeof(table[y].y));
        }
        rt->infinity = !y;
        for (i=46; i>=0; i--) {
            y = 0;
            for (j=0,x=i; j<8; j++,x+=48) {
                y |= (int)(((k[x / 55] >> (x % 55)) & 1) << j);
            }

            sp_384_proj_point_dbl_7(rt, rt, t);
        #ifndef WC_NO_CACHE_RESISTANT
            if (ct) {
                sp_384_get_entry_256_7(p, table, y);
            }
            else
        #endif
            {
                XMEMCPY(p->x, table[y].x, sizeof(table[y].x));
                XMEMCPY(p->y, table[y].y, sizeof(table[y].y));
            }
            p->infinity = !y;
            sp_384_proj_point_add_qz1_7(rt, rt, p, t);
        }

        if (map != 0) {
            sp_384_map_7(r, rt, t);
        }
        else {
            XMEMCPY(r, rt, sizeof(sp_point_384));
        }
    }

#if (defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)) && !defined(WOLFSSL_SP_NO_MALLOC)
    if (t != NULL) {
        XFREE(t, heap, DYNAMIC_TYPE_ECC);
    }
#endif
    sp_384_point_free_7(p, 0, heap);
    sp_384_point_free_7(rt, 0, heap);

    return err;
}

/* Multiply the base point of P384 by the scalar and return the result.
 * If map is true then convert result to affine coordinates.
 *
 * r     Resulting point.
 * g     Point to multiply.
 * k     Scalar to multiply by.
 * map   Indicates whether to convert result to affine.
 * ct    Constant time required.
 * heap  Heap to use for allocation.
 * returns MEMORY_E when memory allocation fails and MP_OKAY on success.
 */
static int sp_384_ecc_mulmod_7(sp_point_384* r, const sp_point_384* g, const sp_digit* k,
        int map, int ct, void* heap)
{
#ifndef FP_ECC
    return sp_384_ecc_mulmod_win_add_sub_7(r, g, k, map, ct, heap);
#else
    sp_digit tmp[2 * 7 * 7];
    sp_cache_384_t* cache;
    int err = MP_OKAY;

#ifndef HAVE_THREAD_LS
    if (initCacheMutex_384 == 0) {
         wc_InitMutex(&sp_cache_384_lock);
         initCacheMutex_384 = 1;
    }
    if (wc_LockMutex(&sp_cache_384_lock) != 0)
       err = BAD_MUTEX_E;
#endif /* HAVE_THREAD_LS */

    if (err == MP_OKAY) {
        sp_ecc_get_cache_384(g, &cache);
        if (cache->cnt == 2)
            sp_384_gen_stripe_table_7(g, cache->table, tmp, heap);

#ifndef HAVE_THREAD_LS
        wc_UnLockMutex(&sp_cache_384_lock);
#endif /* HAVE_THREAD_LS */

        if (cache->cnt < 2) {
            err = sp_384_ecc_mulmod_win_add_sub_7(r, g, k, map, ct, heap);
        }
        else {
            err = sp_384_ecc_mulmod_stripe_7(r, g, cache->table, k,
                    map, ct, heap);
        }
    }

    return err;
#endif
}

#endif
/* Multiply the point by the scalar and return the result.
 * If map is true then convert result to affine coordinates.
 *
 * km    Scalar to multiply by.
 * p     Point to multiply.
 * r     Resulting point.
 * map   Indicates whether to convert result to affine.
 * heap  Heap to use for allocation.
 * returns MEMORY_E when memory allocation fails and MP_OKAY on success.
 */
int sp_ecc_mulmod_384(mp_int* km, ecc_point* gm, ecc_point* r, int map,
        void* heap)
{
#if (!defined(WOLFSSL_SP_SMALL) && !defined(WOLFSSL_SMALL_STACK)) || defined(WOLFSSL_SP_NO_MALLOC)
    sp_point_384 p;
    sp_digit kd[7];
#endif
    sp_point_384* point;
    sp_digit* k = NULL;
    int err = MP_OKAY;

    err = sp_384_point_new_7(heap, p, point);
#if (defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)) && !defined(WOLFSSL_SP_NO_MALLOC)
    if (err == MP_OKAY) {
        k = (sp_digit*)XMALLOC(sizeof(sp_digit) * 7, heap,
                                                              DYNAMIC_TYPE_ECC);
        if (k == NULL)
            err = MEMORY_E;
    }
#else
    k = kd;
#endif
    if (err == MP_OKAY) {
        sp_384_from_mp(k, 7, km);
        sp_384_point_from_ecc_point_7(point, gm);

            err = sp_384_ecc_mulmod_7(point, point, k, map, 1, heap);
    }
    if (err == MP_OKAY) {
        err = sp_384_point_to_ecc_point_7(point, r);
    }

#if (defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)) && !defined(WOLFSSL_SP_NO_MALLOC)
    if (k != NULL) {
        XFREE(k, heap, DYNAMIC_TYPE_ECC);
    }
#endif
    sp_384_point_free_7(point, 0, heap);

    return err;
}

#ifdef WOLFSSL_SP_SMALL
/* Multiply the base point of P384 by the scalar and return the result.
 * If map is true then convert result to affine coordinates.
 *
 * r     Resulting point.
 * k     Scalar to multiply by.
 * map   Indicates whether to convert result to affine.
 * heap  Heap to use for allocation.
 * returns MEMORY_E when memory allocation fails and MP_OKAY on success.
 */
static int sp_384_ecc_mulmod_base_7(sp_point_384* r, const sp_digit* k,
        int map, int ct, void* heap)
{
    /* No pre-computed values. */
    return sp_384_ecc_mulmod_7(r, &p384_base, k, map, ct, heap);
}

#else
static const sp_table_entry_384 p384_table[256] = {
    /* 0 */
    { { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
      { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } },
    /* 1 */
    { { 0x50756649c0b528L,0x71c541ad9c707bL,0x71506d35b8838dL,
        0x4d1877fc3ce1d7L,0x6de2b645486845L,0x227025fee46c29L,
        0x134eab708a6785L },
      { 0x043dad4b03a4feL,0x517ef769535846L,0x58ba0ec14286feL,
        0x47a7fecc5d6f3aL,0x1a840c6c352196L,0x3d3bb00044c72dL,
        0x0ade2af0968571L } },
    /* 2 */
    { { 0x0647532b0c535bL,0x52a6e0a0c52c53L,0x5085aae6b24375L,
        0x7096bb501c66b5L,0x47bdb3df9b7b7bL,0x11227e9b2f0be6L,
        0x088b172704fa51L },
      { 0x0e796f2680dc64L,0x796eb06a482ebfL,0x2b441d02e04839L,
        0x19bef7312a5aecL,0x02247c38b8efb5L,0x099ed1185c329eL,
        0x1ed71d7cdb096fL } },
    /* 3 */
    { { 0x6a3cc39edffea5L,0x7a386fafd3f9c4L,0x366f78fbd8d6efL,
        0x529c7ad7873b80L,0x79eb30380eb471L,0x07c5d3b51760b7L,
        0x36ee4f1cc69183L },
      { 0x5ba260f526b605L,0x2f1dfaf0aa6e6fL,0x6bb5ca812a5752L,
        0x3002d8d1276bc9L,0x01f82269483777L,0x1df33eaaf733cdL,
        0x2b97e555f59255L } },
    /* 4 */
    { { 0x480c57f26feef9L,0x4d28741c248048L,0x0c9cf8af1f0c68L,
        0x778f6a639a8016L,0x148e88c42e9c53L,0x464051757ecfe9L,
        0x1a940bd0e2a5e1L },
      { 0x713a46b74536feL,0x1757b153e1d7ebL,0x30dc8c9da07486L,
        0x3b7460c1879b5eL,0x4b766c5317b315L,0x1b9de3aaf4d377L,
        0x245f124c2cf8f5L } },
    /* 5 */
    { { 0x426e2ee349ddd0L,0x7df3365f84a022L,0x03b005d29a7c45L,
        0x422c2337f9b5a4L,0x060494f4bde761L,0x5245e5db6da0b0L,
        0x22b71d744677f2L },
      { 0x19d097b7d5a7ceL,0x6bcb468823d34cL,0x1c3692d3be1d09L,
        0x3c80ec7aa01f02L,0x7170f2ebaafd97L,0x06cbcc7d79d4e8L,
        0x04a8da511fe760L } },
    /* 6 */
    { { 0x79c07a4fc52870L,0x6e9034a752c251L,0x603860a367382cL,
        0x56d912d6aa87d0L,0x0a348a24abaf76L,0x6c5a23da14adcbL,
        0x3cf60479a522b2L },
      { 0x18dd774c61ed22L,0x0ff30168f93b0cL,0x3f79ae15642eddL,
        0x40510f4915fbcbL,0x2c9ddfdfd1c6d6L,0x67b81b62aee55eL,
        0x2824de79b07a43L } },
    /* 7 */
    { { 0x6c66efe085c629L,0x48c212b7913470L,0x4480fd2d057f0aL,
        0x725ec7a89a9eb1L,0x78ce97ca1972b7L,0x54760ee70154fbL,
        0x362a40e27b9f93L },
      { 0x474dc7e7b14461L,0x602819389ef037L,0x1a13bc284370b2L,
        0x0193ff1295a59dL,0x79615bde6ea5d2L,0x2e76e3d886acc1L,
        0x3bb796812e2b60L } },
    /* 8 */
    { { 0x04cbb3893b9a2dL,0x4c16010a18baabL,0x19f7cb50f60831L,
        0x084f400a0936c1L,0x72f1cdd5bbbf00L,0x1b30b725dc6702L,
        0x182753e4fcc50cL },
      { 0x059a07eadaf9d6L,0x26d81e24bf603cL,0x45583c839dc399L,
        0x5579d4d6b1103aL,0x2e14ea59489ae7L,0x492f6e1c5ecc97L,
        0x03740dc05db420L } },
    /* 9 */
    { { 0x413be88510521fL,0x3753ee49982e99L,0x6cd4f7098e1cc5L,
        0x613c92bda4ec1dL,0x495378b677efe0L,0x132a2143839927L,
        0x0cf8c336291c0bL },
      { 0x7fc89d2208353fL,0x751b9da85657e1L,0x349b8a97d405c3L,
        0x65a964b048428fL,0x1adf481276455eL,0x5560c8d89c2ffcL,
        0x144fc11fac21a3L } },
    /* 10 */
    { { 0x7611f4df5bdf53L,0x634eb16234db80L,0x3c713b8e51174cL,
        0x52c3c68ac4b2edL,0x53025ba8bebe75L,0x7175d98143105bL,
        0x33ca8e266a48faL },
      { 0x0c9281d24fd048L,0x76b3177604bbf3L,0x3b26ae754e106fL,
        0x7f782275c6efc6L,0x36662538a4cb67L,0x0ca1255843e464L,
        0x2a4674e142d9bcL } },
    /* 11 */
    { { 0x303b4085d480d8L,0x68f23650f4fa7bL,0x552a3ceeba3367L,
        0x6da0c4947926e3L,0x6e0f5482eb8003L,0x0de717f3d6738aL,
        0x22e5dcc826a477L },
      { 0x1b05b27209cfc2L,0x7f0a0b65b6e146L,0x63586549ed3126L,
        0x7d628dd2b23124L,0x383423fe510391L,0x57ff609eabd569L,
        0x301f04370131baL } },
    /* 12 */
    { { 0x22fe4cdb32f048L,0x7f228ebdadbf5aL,0x02a99adb2d7c8eL,
        0x01a02e05286706L,0x62d6adf627a89fL,0x49c6ce906fbf2bL,
        0x0207256dae90b9L },
      { 0x23e036e71d6cebL,0x199ed8d604e3d7L,0x0c1a11c076d16fL,
        0x389291fb3da3f3L,0x47adc60f8f942eL,0x177048468e4b9aL,
        0x20c09f5e61d927L } },
    /* 13 */
    { { 0x129ea63615b0b8L,0x03fb4a9b588367L,0x5ad6da8da2d051L,
        0x33f782f44caeaaL,0x5a27fa80d45291L,0x6d1ed796942da4L,
        0x08435a931ef556L },
      { 0x004abb25351130L,0x6d33207c6fd7e7L,0x702130972074b7L,
        0x0e34748af900f7L,0x762a531a28c87aL,0x3a903b5a4a6ac7L,
        0x1775b79c35b105L } },
    /* 14 */
    { { 0x7470fd846612ceL,0x7dd9b431b32e53L,0x04bcd2be1a61bcL,
        0x36ed7c5b5c260bL,0x6795f5ef0a4084L,0x46e2880b401c93L,
        0x17d246c5aa8bdeL },
      { 0x707ae4db41b38dL,0x233c31f7f9558fL,0x585110ec67bdf4L,
        0x4d0cc931d0c703L,0x26fbe4356841a7L,0x64323e95239c44L,
        0x371dc9230f3221L } },
    /* 15 */
    { { 0x70ff1ae4b1ec9dL,0x7c1dcfddee0daaL,0x53286782188748L,
        0x6a5d9381e6f207L,0x3aa6c7d6523c4cL,0x6c02d83e0d97e2L,
        0x16a9c916b45312L },
      { 0x78146744b74de8L,0x742ec415269c6fL,0x237a2c6a860e79L,
        0x186baf17ba68a7L,0x4261e8789fa51fL,0x3dc136480a5903L,
        0x1953899e0cf159L } },
    /* 16 */
    { { 0x0205de2f9fbe67L,0x1706fee51c886fL,0x31a0b803c712bfL,
        0x0a6aa11ede7603L,0x2463ef2a145c31L,0x615403b30e8f4aL,
        0x3f024d6c5f5c5eL },
      { 0x53bc4fd4d01f95L,0x7d512ac15a692cL,0x72be38fcfe6aa0L,
        0x437f0b77bbca1eL,0x7fdcf70774a10eL,0x392d6c5cde37f3L,
        0x229cbce79621d1L } },
    /* 17 */
    { { 0x2de4da2341c342L,0x5ca9d4e08844e7L,0x60dd073bcf74c9L,
        0x4f30aa499b63ecL,0x23efd1eafa00d5L,0x7c99a7db1257b3L,
        0x00febc9b3171b1L },
      { 0x7e2fcf3045f8acL,0x2a642e9e3ce610L,0x23f82be69c5299L,
        0x66e49ad967c279L,0x1c895ddfd7a842L,0x798981e22f6d25L,
        0x0d595cb59322f3L } },
    /* 18 */
    { { 0x4bac017d8c1bbaL,0x73872161e7aafdL,0x0fd865f43d8163L,
        0x019d89457708b7L,0x1b983c4dd70684L,0x095e109b74d841L,
        0x25f1f0b3e0c76fL },
      { 0x4e61ddf96010e8L,0x1c40a53f542e5eL,0x01a74dfc8365f9L,
        0x69b36b92773333L,0x08e0fccc139ed3L,0x266d216ddc4269L,
        0x1f2b47717ce9b5L } },
    /* 19 */
    { { 0x0a9a81da57a41fL,0x0825d800736cccL,0x2d7876b4579d28L,
        0x3340ea6211a1e3L,0x49e89284f3ff54L,0x6276a210fe2c6eL,
        0x01c3c8f31be7cbL },
      { 0x2211da5d186e14L,0x1e6ffbb61bfea8L,0x536c7d060211d2L,
        0x320168720d1d55L,0x5835525ed667baL,0x5125e52495205eL,
        0x16113b9f3e9129L } },
    /* 20 */
    { { 0x3086073f3b236fL,0x283b03c443b5f5L,0x78e49ed0a067a7L,
        0x2a878fb79fb2b8L,0x662f04348a9337L,0x57ee2cf732d50bL,
        0x18b50dd65fd514L },
      { 0x5feb9ef2955926L,0x2c3edbef06a7b0L,0x32728dad651029L,
        0x116d00b1c4b347L,0x13254052bf1a1aL,0x3e77bf7fee5ec1L,
        0x253943ca388882L } },
    /* 21 */
    { { 0x32e5b33062e8afL,0x46ebd147a6d321L,0x2c8076dec6a15cL,
        0x7328d511ff0d80L,0x10ad7e926def0eL,0x4e8ca85937d736L,
        0x02638c26e8bf2fL },
      { 0x1deeb3fff1d63fL,0x5014417fa6e8efL,0x6e1da3de5c8f43L,
        0x7ca942b42295d9L,0x23faacf75bb4d1L,0x4a71fcd680053dL,
        0x04af4f90204dceL } },
    /* 22 */
    { { 0x23780d104cbba5L,0x4e8ff46bba9980L,0x2072a6da8d881fL,
        0x3cc3d881ae11c9L,0x2eee84ff19be89L,0x69b708ed77f004L,
        0x2a82928534eef9L },
      { 0x794331187d4543L,0x70e0f3edc0cc41L,0x3ab1fa0b84c854L,
        0x1478355c1d87baL,0x6f35fa7748ba28L,0x37b8be0531584dL,
        0x03c3141c23a69fL } },
    /* 23 */
    { { 0x5c244cdef029ddL,0x0d0f0a0cc37018L,0x17f8476604f6afL,
        0x13a6dd6ccc95c3L,0x5a242e9801b8f6L,0x211ca9cc632131L,
        0x264a6a46a4694fL },
      { 0x3ffd7235285887L,0x284be28302046fL,0x57f4b9b882f1d6L,
        0x5e21772c940661L,0x7619a735c600cfL,0x2f76f5a50c9106L,
        0x28d89c8c69de31L } },
    /* 24 */
    { { 0x799b5c91361ed8L,0x36ead8c66cd95cL,0x046c9969a91f5cL,
        0x46bbdba2a66ea9L,0x29db0e0215a599L,0x26c8849b36f756L,
        0x22c3feb31ff679L },
      { 0x585d1237b5d9efL,0x5ac57f522e8e8dL,0x617e66e8b56c41L,
        0x68826f276823cfL,0x0983f0e6f39231L,0x4e1075099084bdL,
        0x2a541f82be0416L } },
    /* 25 */
    { { 0x468a6e14cf381cL,0x4f7b845c6399edL,0x36aa29732ebe74L,
        0x19c726911ab46aL,0x2ad1fe431eec0eL,0x301e35051fd1eaL,
        0x36da815e7a1ab3L },
      { 0x05672e4507832aL,0x4ebf10fca51251L,0x6015843421cff0L,
        0x3affad832fc013L,0x712b58d9b45540L,0x1e4751d1f6213eL,
        0x0e7c2b218bafa7L } },
    /* 26 */
    { { 0x7abf784c52edf5L,0x6fcb4b135ca7b1L,0x435e46ac5f735cL,
        0x67f8364ca48c5fL,0x46d45b5fbd956bL,0x10deda6065db94L,
        0x0b37fdf85068f9L },
      { 0x74b3ba61f47ec8L,0x42c7ddf08c10ccL,0x1531a1fe422a20L,
        0x366f913d12be38L,0x6a846e30cb2edfL,0x2785898c994fedL,
        0x061be85f331af3L } },
    /* 27 */
    { { 0x23f5361dfcb91eL,0x3c26c8da6b1491L,0x6e444a1e620d65L,
        0x0c3babd5e8ac13L,0x573723ce612b82L,0x2d10e62a142c37L,
        0x3d1a114c2d98bdL },
      { 0x33950b401896f6L,0x7134efe7c12110L,0x31239fd2978472L,
        0x30333bf5978965L,0x79f93313dd769fL,0x457fb9e11662caL,
        0x190a73b251ae3cL } },
    /* 28 */
    { { 0x04dd54bb75f9a4L,0x0d7253a76ae093L,0x08f5b930792bbcL,
        0x041f79adafc265L,0x4a9ff24c61c11bL,0x0019c94e724725L,
        0x21975945d9cc2aL },
      { 0x3dfe76722b4a2bL,0x17f2f6107c1d94L,0x546e1ae2944b01L,
        0x53f1f06401e72dL,0x2dbe43fc7632d6L,0x5639132e185903L,
        0x0f2f34eb448385L } },
    /* 29 */
    { { 0x7b4cc7ec30ce93L,0x58fb6e4e4145f7L,0x5d1ed5540043b5L,
        0x19ffbe1f633adfL,0x5bfc0907259033L,0x6378f872e7ca0eL,
        0x2c127b2c01eb3cL },
      { 0x076eaf4f58839cL,0x2db54560bc9f68L,0x42ad0319b84062L,
        0x46c325d1fb019dL,0x76d2a19ee9eebcL,0x6fbd6d9e2aa8f7L,
        0x2396a598fe0991L } },
    /* 30 */
    { { 0x662fddf7fbd5e1L,0x7ca8ed22563ad3L,0x5b4768efece3b3L,
        0x643786a422d1eaL,0x36ce80494950e1L,0x1a30795b7f2778L,
        0x107f395c93f332L },
      { 0x7939c28332c144L,0x491610e3c8dc0bL,0x099ba2bfdac5fcL,
        0x5c2e3149ec29a7L,0x31b731d06f1dc3L,0x1cbb60d465d462L,
        0x3ca5461362cfd9L } },
    /* 31 */
    { { 0x653ff736ddc103L,0x7c6f2bdec0dfb2L,0x73f81b73a097d0L,
        0x05b775f84f180fL,0x56b2085af23413L,0x0d6f36256a61feL,
        0x26d3ed267fa68fL },
      { 0x54f89251d27ac2L,0x4fc6ad94a71202L,0x7ebf01969b4cc5L,
        0x7ba364dbc14760L,0x4f8370959a2587L,0x7b7631e37c6188L,
        0x29e51845f104cbL } },
    /* 32 */
    { { 0x426b775e3c647bL,0x327319e0a69180L,0x0c5cb034f6ff2fL,
        0x73aa39b98e9897L,0x7ee615f49fde6eL,0x3f712aa61e0db4L,
        0x33ca06c2ba2ce9L },
      { 0x14973541b8a543L,0x4b4e6101ba61faL,0x1d94e4233d0698L,
        0x501513c715d570L,0x1b8f8c3d01436bL,0x52f41a0445cf64L,
        0x3f709c3a75fb04L } },
    /* 33 */
    { { 0x073c0cbc7f41d6L,0x227c36f5ac8201L,0x508e110fef65d8L,
        0x0f317229529b7fL,0x45fc6030d00e24L,0x118a65d30cebeaL,
        0x3340cc4223a448L },
      { 0x204c999797612cL,0x7c05dd4ce9c5a3L,0x7b865d0a8750e4L,
        0x2f82c876ab7d34L,0x2243ddd2ab4808L,0x6834b9df8a4914L,
        0x123319ed950e0fL } },
    /* 34 */
    { { 0x50430efc14ab48L,0x7e9e4ce0d4e89cL,0x2332207fd8656dL,
        0x4a2809e97f4511L,0x2162bb1b968e2dL,0x29526d54af2972L,
        0x13edd9adcd939dL },
      { 0x793bca31e1ff7fL,0x6b959c9e4d2227L,0x628ac27809a5baL,
        0x2c71ffc7fbaa5fL,0x0c0b058f13c9ceL,0x5676eae68de2cfL,
        0x35508036ea19a4L } },
    /* 35 */
    { { 0x030bbd6dda1265L,0x67f9d12e31bb34L,0x7e4d8196e3ded3L,
        0x7b9120e5352498L,0x75857bce72d875L,0x4ead976a396caeL,
        0x31c5860553a64dL },
      { 0x1a0f792ee32189L,0x564c4efb8165d0L,0x7adc7d1a7fbcbeL,
        0x7ed7c2ccf327b7L,0x35df1b448ce33dL,0x6f67eb838997cdL,
        0x3ee37ec0077917L } },
    /* 36 */
    { { 0x345fa74d5bb921L,0x097c9a56ccfd8eL,0x00a0b5e8f971f8L,
        0x723d95223f69d4L,0x08e2e5c2777f87L,0x68b13676200109L,
        0x26ab5df0acbad6L },
      { 0x01bca7daac34aeL,0x49ca4d5f664dadL,0x110687b850914bL,
        0x1203d6f06443c9L,0x7a2ac743b04d4cL,0x40d96bd3337f82L,
        0x13728be0929c06L } },
    /* 37 */
    { { 0x631ca61127bc1aL,0x2b362fd5a77cd1L,0x17897d68568fb7L,
        0x21070af33db5b2L,0x6872e76221794aL,0x436f29fb076963L,
        0x1f2acfc0ecb7b3L },
      { 0x19bf15ca9b3586L,0x32489a4a17aee2L,0x2b31af3c929551L,
        0x0db7c420b9b19fL,0x538c39bd308c2bL,0x438775c0dea88fL,
        0x1537304d7cd07fL } },
    /* 38 */
    { { 0x53598d943caf0dL,0x1d5244bfe266adL,0x7158feb7ab3811L,
        0x1f46e13cf6fb53L,0x0dcab632eb9447L,0x46302968cfc632L,
        0x0b53d3cc5b6ec7L },
      { 0x69811ca143b7caL,0x5865bcf9f2a11aL,0x74ded7fa093b06L,
        0x1c878ec911d5afL,0x04610e82616e49L,0x1e157fe9640eb0L,
        0x046e6f8561d6c2L } },
    /* 39 */
    { { 0x631a3d3bbe682cL,0x3a4ce9dde5ba95L,0x28f11f7502f1f1L,
        0x0a55cf0c957e88L,0x495e4ec7e0a3bcL,0x30ad4d87ba365cL,
        0x0217b97a4c26f3L },
      { 0x01a9088c2e67fdL,0x7501c4c3d5e5e7L,0x265b7bb854c820L,
        0x729263c87e6b52L,0x308b9e3b8fb035L,0x33f1b86c1b23abL,
        0x0e81b8b21fc99cL } },
    /* 40 */
    { { 0x59f5a87237cac0L,0x6b3a86b0cf28b9L,0x13a53db13a4fc2L,
        0x313c169a1c253bL,0x060158304ed2bbL,0x21e171b71679bcL,
        0x10cdb754d76f86L },
      { 0x44355392ab473aL,0x64eb7cbda08caeL,0x3086426a900c71L,
        0x49016ed9f3c33cL,0x7e6354ab7e04f9L,0x17c4c91a40cd2eL,
        0x3509f461024c66L } },
    /* 41 */
    { { 0x2848f50f9b5a31L,0x68d1755b6c5504L,0x48cd5d5672ec00L,
        0x4d77421919d023L,0x1e1e349ef68807L,0x4ab5130cf415d7L,
        0x305464c6c7dbe6L },
      { 0x64eb0bad74251eL,0x64c6957e52bda4L,0x6c12583440dee6L,
        0x6d3bee05b00490L,0x186970de53dbc4L,0x3be03b37567a56L,
        0x2b553b1ebdc55bL } },
    /* 42 */
    { { 0x74dc3579efdc58L,0x26d29fed1bb71cL,0x334c825a9515afL,
        0x433c1e839273a6L,0x0d8a4e41cff423L,0x3454098fe42f8eL,
        0x1046674bf98686L },
      { 0x09a3e029c05dd2L,0x54d7cfc7fb53a7L,0x35f0ad37e14d7cL,
        0x73a294a13767b9L,0x3f519678275f4fL,0x788c63393993a4L,
        0x0781680b620123L } },
    /* 43 */
    { { 0x4c8e2ed4d5ffe8L,0x112db7d42fe4ebL,0x433b8f2d2be2edL,
        0x23e30b29a82cbcL,0x35d2f4c06ee85aL,0x78ff31ffe4b252L,
        0x0d31295c8cbff5L },
      { 0x314806ea0376a2L,0x4ea09e22bc0589L,0x0879575f00ba97L,
        0x188226d2996bb7L,0x7799368dc9411fL,0x7ab24e5c8cae36L,
        0x2b6a8e2ee4ea33L } },
    /* 44 */
    { { 0x70c7127d4ed72aL,0x24c9743ef34697L,0x2fd30e7a93683aL,
        0x538a89c246012cL,0x6c660a5394ed82L,0x79a95ea239d7e0L,
        0x3f3af3bbfb170dL },
      { 0x3b75aa779ae8c1L,0x33995a3cc0dde4L,0x7489d5720b7bfdL,
        0x599677ef9fa937L,0x3defd64c5ab44bL,0x27d52dc234522bL,
        0x2ac65d1a8450e0L } },
    /* 45 */
    { { 0x478585ec837d7dL,0x5f7971dc174887L,0x67576ed7bb296dL,
        0x5a78e529a74926L,0x640f73f4fa104bL,0x7d42a8b16e4730L,
        0x108c7eaa75fd01L },
      { 0x60661ef96e6896L,0x18d3a0761f3aa7L,0x6e71e163455539L,
        0x165827d6a7e583L,0x4e7f77e9527935L,0x790bebe2ae912eL,
        0x0b8fe9561adb55L } },
    /* 46 */
    { { 0x4d48036a9951a8L,0x371084f255a085L,0x66aeca69cea2c5L,
        0x04c99f40c745e7L,0x08dc4bfd9a0924L,0x0b0ec146b29df7L,
        0x05106218d01c91L },
      { 0x2a56ee99caedc7L,0x5d9b23a203922cL,0x1ce4c80b6a3ec4L,
        0x2666bcb75338cbL,0x185a81aac8c4aaL,0x2b4fb60a06c39eL,
        0x0327e1b3633f42L } },
    /* 47 */
    { { 0x72814710b2a556L,0x52c864f6e16534L,0x4978de66ddd9f2L,
        0x151f5950276cf0L,0x450ac6781d2dc2L,0x114b7a22dd61b2L,
        0x3b32b07f29faf8L },
      { 0x68444fdc2d6e94L,0x68526bd9e437bcL,0x0ca780e8b0d887L,
        0x69f3f850a716aaL,0x500b953e42cd57L,0x4e57744d812e7dL,
        0x000a5f0e715f48L } },
    /* 48 */
    { { 0x2aab10b8243a7dL,0x727d1f4b18b675L,0x0e6b9fdd91bbbbL,
        0x0d58269fc337e5L,0x45d6664105a266L,0x11946af1b14072L,
        0x2c2334f91e46e1L },
      { 0x6dc5f8756d2411L,0x21b34eaa25188bL,0x0d2797da83529eL,
        0x324df55616784bL,0x7039ec66d267dfL,0x2de79cdb2d108cL,
        0x14011b1ad0bde0L } },
    /* 49 */
    { { 0x2e160266425043L,0x55fbe11b712125L,0x7e3c58b3947fd9L,
        0x67aacc79c37ad3L,0x4a18e18d2dea0fL,0x5eef06e5674351L,
        0x37c3483ae33439L },
      { 0x5d5e1d75bb4045L,0x0f9d72db296efdL,0x60b1899dd894a9L,
        0x06e8818ded949aL,0x747fd853c39434L,0x0953b937d9efabL,
        0x09f08c0beeb901L } },
    /* 50 */
    { { 0x1d208a8f2d49ceL,0x54042c5be1445aL,0x1c2681fd943646L,
        0x219c8094e2e674L,0x442cddf07238b8L,0x574a051c590832L,
        0x0b72f4d61c818aL },
      { 0x7bc3cbe4680967L,0x0c8b3f25ae596bL,0x0445b0da74a9efL,
        0x0bbf46c40363b7L,0x1df575c50677a3L,0x016ea6e73d68adL,
        0x0b5207bd8db0fdL } },
    /* 51 */
    { { 0x2d39fdfea1103eL,0x2b252bf0362e34L,0x63d66c992baab9L,
        0x5ac97706de8550L,0x0cca390c39c1acL,0x0d9bec5f01b2eaL,
        0x369360a0f7e5f3L },
      { 0x6dd3461e201067L,0x70b2d3f63ed614L,0x487580487c54c7L,
        0x6020e48a44af2aL,0x1ccf80b21aab04L,0x3cf3b12d88d798L,
        0x349368eccc506fL } },
    /* 52 */
    { { 0x5a053753b0a354L,0x65e818dbb9b0aeL,0x7d5855ee50e4bfL,
        0x58dc06885c7467L,0x5ee15073e57bd3L,0x63254ebc1e07fdL,
        0x1d48e0392aa39bL },
      { 0x4e227c6558ffe9L,0x0c3033d8a82a3eL,0x7bde65c214e8d2L,
        0x6e23561559c16aL,0x5094c5e6deaffdL,0x78dca2880f1f91L,
        0x3d9d3f947d838dL } },
    /* 53 */
    { { 0x387ae5af63408fL,0x6d539aeb4e6edfL,0x7f3d3186368e70L,
        0x01a6446bc19989L,0x35288fbcd4482fL,0x39288d34ec2736L,
        0x1de9c47159ad76L },
      { 0x695dc7944f8d65L,0x3eca2c35575094L,0x0c918059a79b69L,
        0x4573a48c32a74eL,0x580d8bc8b93f52L,0x190be3a3d071eaL,
        0x2333e686b3a8cbL } },
    /* 54 */
    { { 0x2b110c7196fee2L,0x3ac70e99128a51L,0x20a6bb6b75d5e6L,
        0x5f447fa513149aL,0x560d69714cc7b2L,0x1d3ee25279fab1L,
        0x369adb2ccca959L },
      { 0x3fddb13dd821c2L,0x70bf21ba647be8L,0x64121227e3cbc9L,
        0x12633a4c892320L,0x3c15c61660f26dL,0x1932c3b3d19900L,
        0x18c718563eab71L } },
    /* 55 */
    { { 0x72ebe0fd752366L,0x681c2737d11759L,0x143c805e7ae4f0L,
        0x78ed3c2cc7b324L,0x5c16e14820254fL,0x226a4f1c4ec9f0L,
        0x2891bb915eaac6L },
      { 0x061eb453763b33L,0x07f88b81781a87L,0x72b5ac7a87127cL,
        0x7ea4e4cd7ff8b5L,0x5e8c3ce33908b6L,0x0bcb8a3d37feffL,
        0x01da9e8e7fc50bL } },
    /* 56 */
    { { 0x639dfe9e338d10L,0x32dfe856823608L,0x46a1d73bca3b9aL,
        0x2da685d4b0230eL,0x6e0bc1057b6d69L,0x7144ec724a5520L,
        0x0b067c26b87083L },
      { 0x0fc3f0eef4c43dL,0x63500f509552b7L,0x220d74af6f8b86L,
        0x038996eafa2aa9L,0x7f6750f4aee4d2L,0x3e1d3f06718720L,
        0x1ea1d37243814cL } },
    /* 57 */
    { { 0x322d4597c27050L,0x1beeb3ce17f109L,0x15e5ce2e6ef42eL,
        0x6c8be27da6b3a0L,0x66e3347f4d5f5cL,0x7172133899c279L,
        0x250aff4e548743L },
      { 0x28f0f6a43b566dL,0x0cd2437fefbca0L,0x5b1108cb36bdbaL,
        0x48a834d41fb7c2L,0x6cb8565680579fL,0x42da2412b45d9fL,
        0x33dfc1abb6c06eL } },
    /* 58 */
    { { 0x56e3c48ef96c80L,0x65667bb6c1381eL,0x09f70514375487L,
        0x1548ff115f4a08L,0x237de2d21a0710L,0x1425cdee9f43dfL,
        0x26a6a42e055b0aL },
      { 0x4ea9ea9dc7dfcbL,0x4df858583ac58aL,0x1d274f819f1d39L,
        0x26e9c56cf91fcbL,0x6cee31c7c3a465L,0x0bb8e00b108b28L,
        0x226158da117301L } },
    /* 59 */
    { { 0x5a7cd4fce73946L,0x7b6a462d0ac653L,0x732ea4bb1a3da5L,
        0x7c8e9f54711af4L,0x0a6cd55d4655f9L,0x341e6d13e4754aL,
        0x373c87098879a8L },
      { 0x7bc82e61b818bfL,0x5f2db48f44879fL,0x2a2f06833f1d28L,
        0x494e5b691a74c0L,0x17d6cf35fd6b57L,0x5f7028d1c25dfcL,
        0x377a9ab9562cb6L } },
    /* 60 */
    { { 0x4de8877e787b2eL,0x183e7352621a52L,0x2ab0509974962bL,
        0x045a450496cb8aL,0x3bf7118b5591c7L,0x7724f98d761c35L,
        0x301607e8d5a0c1L },
      { 0x0f58a3f24d4d58L,0x3771c19c464f3cL,0x06746f9c0bfafaL,
        0x56564c9c8feb52L,0x0d66d9a7d8a45fL,0x403578141193caL,
        0x00b0d0bdc19260L } },
    /* 61 */
    { { 0x571407157bdbc2L,0x138d5a1c2c0b99L,0x2ee4a8057dcbeaL,
        0x051ff2b58e9ed1L,0x067378ad9e7cdaL,0x7cc2c1db97a49eL,
        0x1e7536ccd849d6L },
      { 0x531fd95f3497c4L,0x55dc08325f61a7L,0x144e942bce32bfL,
        0x642d572f09e53aL,0x556ff188261678L,0x3e79c0d9d513d6L,
        0x0bbbc6656f6d52L } },
    /* 62 */
    { { 0x57d3eb50596edcL,0x26c520a487451dL,0x0a92db40aea8d6L,
        0x27df6345109616L,0x7733d611fd727cL,0x61d14171fef709L,
        0x36169ae417c36bL },
      { 0x6899f5d4091cf7L,0x56ce5dfe4ed0c1L,0x2c430ce5913fbcL,
        0x1b13547e0f8caeL,0x4840a8275d3699L,0x59b8ef209e81adL,
        0x22362dff5ea1a2L } },
    /* 63 */
    { { 0x7237237bd98425L,0x73258e162a9d0bL,0x0a59a1e8bb5118L,
        0x4190a7ee5d8077L,0x13684905fdbf7cL,0x31c4033a52626bL,
        0x010a30e4fbd448L },
      { 0x47623f981e909aL,0x670af7c325b481L,0x3d004241fa4944L,
        0x0905a2ca47f240L,0x58f3cdd7a187c3L,0x78b93aee05b43fL,
        0x19b91d4ef8d63bL } },
    /* 64 */
    { { 0x0d34e116973cf4L,0x4116fc9e69ee0eL,0x657ae2b4a482bbL,
        0x3522eed134d7cdL,0x741e0dde0a036aL,0x6554316a51cc7bL,
        0x00f31c6ca89837L },
      { 0x26770aa06b1dd7L,0x38233a4ceba649L,0x065a1110c96feaL,
        0x18d367839e0f15L,0x794543660558d1L,0x39b605139065dcL,
        0x29abbec071b637L } },
    /* 65 */
    { { 0x1464b401ab5245L,0x16db891b27ff74L,0x724eb49cb26e34L,
        0x74fee3bc9cc33eL,0x6a8bdbebe085eaL,0x5c2e75ca207129L,
        0x1d03f2268e6b08L },
      { 0x28b0a328e23b23L,0x645dc26209a0bcL,0x62c28990348d49L,
        0x4dd9be1fa333d0L,0x6183aac74a72e4L,0x1d6f3ee69e1d03L,
        0x2fff96db0ff670L } },
    /* 66 */
    { { 0x2358f5c6a2123fL,0x5b2bfc51bedb63L,0x4fc6674be649ecL,
        0x51fc16e44b813aL,0x2ffe10a73754c1L,0x69a0c7a053aeefL,
        0x150e605fb6b9b4L },
      { 0x179eef6b8b83c4L,0x64293b28ad05efL,0x331795fab98572L,
        0x09823eec78727dL,0x36508042b89b81L,0x65f1106adb927eL,
        0x2fc0234617f47cL } },
    /* 67 */
    { { 0x12aa244e8068dbL,0x0c834ae5348f00L,0x310fc1a4771cb3L,
        0x6c90a2f9e19ef9L,0x77946fa0573471L,0x37f5df81e5f72fL,
        0x204f5d72cbe048L },
      { 0x613c724383bba6L,0x1ce14844967e0aL,0x797c85e69aa493L,
        0x4fb15b0f2ce765L,0x5807978e2e8aa7L,0x52c75859876a75L,
        0x1554635c763d3eL } },
    /* 68 */
    { { 0x4f292200623f3bL,0x6222be53d7fe07L,0x1e02a9a08c2571L,
        0x22c6058216b912L,0x1ec20044c7ba17L,0x53f94c5efde12bL,
        0x102b8aadfe32a4L },
      { 0x45377aa927b102L,0x0d41b8062ee371L,0x77085a9018e62aL,
        0x0c69980024847cL,0x14739b423a73a9L,0x52ec6961fe3c17L,
        0x38a779c94b5a7dL } },
    /* 69 */
    { { 0x4d14008435af04L,0x363bfd8325b4e8L,0x48cdb715097c95L,
        0x1b534540f8bee0L,0x4ca1e5c90c2a76L,0x4b52c193d6eee0L,
        0x277a33c79becf5L },
      { 0x0fee0d511d3d06L,0x4627f3d6a58f8cL,0x7c81ac245119b8L,
        0x0c8d526ba1e07aL,0x3dbc242f55bac2L,0x2399df8f91fffdL,
        0x353e982079ba3bL } },
    /* 70 */
    { { 0x6405d3b0ab9645L,0x7f31abe3ee236bL,0x456170a9babbb1L,
        0x09634a2456a118L,0x5b1c6045acb9e5L,0x2c75c20d89d521L,
        0x2e27ccf5626399L },
      { 0x307cd97fed2ce4L,0x1c2fbb02b64087L,0x542a068d27e64dL,
        0x148c030b3bc6a6L,0x671129e616ade5L,0x123f40db60dafcL,
        0x07688f3c621220L } },
    /* 71 */
    { { 0x1c46b342f2c4b5L,0x27decc0b3c8f04L,0x0d9bd433464c54L,
        0x1f3d893b818572L,0x2536043b536c94L,0x57e00c4b19ebf9L,
        0x3938fb9e5ad55eL },
      { 0x6b390024c8b22fL,0x4583f97e20a976L,0x2559d24abcbad7L,
        0x67a9cabc9bd8c6L,0x73a56f09432e4aL,0x79eb0beb53a3b7L,
        0x3e19d47f6f8221L } },
    /* 72 */
    { { 0x7399cb9d10e0b2L,0x32acc1b8a36e2aL,0x287d60c2407035L,
        0x42c82420ea4b5cL,0x13f286658bc268L,0x3c91181156e064L,
        0x234b83dcdeb963L },
      { 0x79bc95486cfee6L,0x4d8fd3cb78af36L,0x07362ba5e80da8L,
        0x79d024a0d681b0L,0x6b58406907f87fL,0x4b40f1e977e58fL,
        0x38dcc6fd5fa342L } },
    /* 73 */
    { { 0x72282be1cd0abeL,0x02bd0fdfdf44e5L,0x19b0e0d2f753e4L,
        0x4514e76ce8c4c0L,0x02ebc9c8cdcc1bL,0x6ac0c0373e9fddL,
        0x0dc414af1c81a9L },
      { 0x7a109246f32562L,0x26982e6a3768edL,0x5ecd8daed76ab5L,
        0x2eaa70061eb261L,0x09e7c038a8c514L,0x2a2603cc300658L,
        0x25d93ab9e55cd4L } },
    /* 74 */
    { { 0x11b19fcbd5256aL,0x41e4d94274770fL,0x0133c1a411001fL,
        0x360bac481dbca3L,0x45908b18a9c22bL,0x1e34396fafb03aL,
        0x1b84fea7486edaL },
      { 0x183c62a71e6e16L,0x5f1dc30e93da8eL,0x6cb97b502573c3L,
        0x3708bf0964e3fcL,0x35a7f042eeacceL,0x56370da902c27fL,
        0x3a873c3b72797fL } },
    /* 75 */
    { { 0x6573c9cea4cc9bL,0x2c3b5f9d91e6dcL,0x2a90e2dbd9505eL,
        0x66a75444025f81L,0x1571fb894b03cdL,0x5d1a1f00fd26f3L,
        0x0d19a9fd618855L },
      { 0x659acd56515664L,0x7279478bd616a3L,0x09a909e76d56c3L,
        0x2fd70474250358L,0x3a1a25c850579cL,0x11b9e0f71b74ccL,
        0x1268daef3d1bffL } },
    /* 76 */
    { { 0x7f5acc46d93106L,0x5bc15512f939c8L,0x504b5f92f996deL,
        0x25965549be7a64L,0x357a3a2ae9b80dL,0x3f2bcf9c139cc0L,
        0x0a7ddd99f23b35L },
      { 0x6868f5a8a0b1c5L,0x319ec52f15b1beL,0x0770000a849021L,
        0x7f4d50287bd608L,0x62c971d28a9d7fL,0x164e89309acb72L,
        0x2a29f002cf4a32L } },
    /* 77 */
    { { 0x58a852ae11a338L,0x27e3a35f2dcef8L,0x494d5731ce9e18L,
        0x49516f33f4bb3eL,0x386b26ba370097L,0x4e8fac1ec30248L,
        0x2ac26d4c44455dL },
      { 0x20484198eb9dd0L,0x75982a0e06512bL,0x152271b9279b05L,
        0x5908a9857e36d2L,0x6a933ab45a60abL,0x58d8b1acb24fafL,
        0x28fbcf19425590L } },
    /* 78 */
    { { 0x5420e9df010879L,0x4aba72aec2f313L,0x438e544eda7494L,
        0x2e8e189ce6f7eaL,0x2f771e4efe45bdL,0x0d780293bce7efL,
        0x1569ad3d0d02acL },
      { 0x325251ebeaf771L,0x02510f1a8511e2L,0x3863816bf8aad1L,
        0x60fdb15fe6ac19L,0x4792aef52a348cL,0x38e57a104e9838L,
        0x0d171611a1df1bL } },
    /* 79 */
    { { 0x15ceb0bea65e90L,0x6e56482db339bcL,0x37f618f7b0261fL,
        0x6351abc226dabcL,0x0e999f617b74baL,0x37d3cc57af5b69L,
        0x21df2b987aac68L },
      { 0x2dddaa3a358610L,0x2da264bc560e47L,0x545615d538bf13L,
        0x1c95ac244b8cc7L,0x77de1f741852cbL,0x75d324f00996abL,
        0x3a79b13b46aa3bL } },
    /* 80 */
    { { 0x7db63998683186L,0x6849bb989d530cL,0x7b53c39ef7ed73L,
        0x53bcfbf664d3ffL,0x25ef27c57f71c7L,0x50120ee80f3ad6L,
        0x243aba40ed0205L },
      { 0x2aae5e0ee1fcebL,0x3449d0d8343fbeL,0x5b2864fb7cffc7L,
        0x64dceb5407ac3eL,0x20303a5695523dL,0x3def70812010b2L,
        0x07be937f2e9b6fL } },
    /* 81 */
    { { 0x5838f9e0540015L,0x728d8720efb9f7L,0x1ab5864490b0c8L,
        0x6531754458fdcfL,0x600ff9612440c0L,0x48735b36a585b7L,
        0x3d4aaea86b865dL },
      { 0x6898942cac32adL,0x3c84c5531f23a1L,0x3c9dbd572f7edeL,
        0x5691f0932a2976L,0x186f0db1ac0d27L,0x4fbed18bed5bc9L,
        0x0e26b0dee0b38cL } },
    /* 82 */
    { { 0x1188b4f8e60f5bL,0x602a915455b4a2L,0x60e06af289ff99L,
        0x579fe4bed999e5L,0x2bc03b15e6d9ddL,0x1689649edd66d5L,
        0x3165e277dca9d2L },
      { 0x7cb8a529cf5279L,0x57f8035b34d84dL,0x352e2eb26de8f1L,
        0x6406820c3367c4L,0x5d148f4c899899L,0x483e1408482e15L,
        0x1680bd1e517606L } },
    /* 83 */
    { { 0x5c877cc1c90202L,0x2881f158eae1f4L,0x6f45e207df4267L,
        0x59280eba1452d8L,0x4465b61e267db5L,0x171f1137e09e5cL,
        0x1368eb821daa93L },
      { 0x70fe26e3e66861L,0x52a6663170da7dL,0x71d1ce5b7d79dcL,
        0x1cffe9be1e1afdL,0x703745115a29c4L,0x73b7f897b2f65aL,
        0x02218c3a95891aL } },
    /* 84 */
    { { 0x16866db8a9e8c9L,0x4770b770123d9bL,0x4c116cf34a8465L,
        0x079b28263fc86aL,0x3751c755a72b58L,0x7bc8df1673243aL,
        0x12fff72454f064L },
      { 0x15c049b89554e7L,0x4ea9ef44d7cd9aL,0x42f50765c0d4f1L,
        0x158bb603cb011bL,0x0809dde16470b1L,0x63cad7422ea819L,
        0x38b6cd70f90d7eL } },
    /* 85 */
    { { 0x1e4aab6328e33fL,0x70575f026da3aeL,0x7e1b55c8c55219L,
        0x328d4b403d24caL,0x03b6df1f0a5bd1L,0x26b4bb8b648ed0L,
        0x17161f2f10b76aL },
      { 0x6cdb32bae8b4c0L,0x33176266227056L,0x4975fa58519b45L,
        0x254602ea511d96L,0x4e82e93e402a67L,0x0ca8b5929cdb4fL,
        0x3ae7e0a07918f5L } },
    /* 86 */
    { { 0x60f9d1fecf5b9bL,0x6257e40d2cd469L,0x6c7aa814d28456L,
        0x58aac7caac8e79L,0x703a55f0293cbfL,0x702390a0f48378L,
        0x24b9ae07218b07L },
      { 0x1ebc66cdaf24e3L,0x7d9ae5f9f8e199L,0x42055ee921a245L,
        0x035595936e4d49L,0x129c45d425c08bL,0x6486c5f19ce6ddL,
        0x027dbd5f18ba24L } },
    /* 87 */
    { { 0x7d6b78d29375fbL,0x0a3dc6ba22ae38L,0x35090fa91feaf6L,
        0x7f18587fb7b16eL,0x6e7091dd924608L,0x54e102cdbf5ff8L,
        0x31b131a4c22079L },
      { 0x368f87d6a53fb0L,0x1d3f3d69a3f240L,0x36bf5f9e40e1c6L,
        0x17f150e01f8456L,0x76e5d0835eb447L,0x662fc0a1207100L,
        0x14e3dd97a98e39L } },
    /* 88 */
    { { 0x0249d9c2663b4bL,0x56b68f9a71ba1cL,0x74b119567f9c02L,
        0x5e6f336d8c92acL,0x2ced58f9f74a84L,0x4b75a2c2a467c5L,
        0x30557011cf740eL },
      { 0x6a87993be454ebL,0x29b7076fb99a68L,0x62ae74aaf99bbaL,
        0x399f9aa8fb6c1bL,0x553c24a396dd27L,0x2868337a815ea6L,
        0x343ab6635cc776L } },
    /* 89 */
    { { 0x0e0b0eec142408L,0x79728229662121L,0x605d0ac75e6250L,
        0x49a097a01edfbeL,0x1e20cd270df6b6L,0x7438a0ca9291edL,
        0x29daa430da5f90L },
      { 0x7a33844624825aL,0x181715986985c1L,0x53a6853cae0b92L,
        0x6d98401bd925e8L,0x5a0a34f5dd5e24L,0x7b818ef53cf265L,
        0x0836e43c9d3194L } },
    /* 90 */
    { { 0x1179b70e6c5fd9L,0x0246d9305dd44cL,0x635255edfbe2fbL,
        0x5397b3523b4199L,0x59350cc47e6640L,0x2b57aa97ed4375L,
        0x37efd31abd153aL },
      { 0x7a7afa6907f4faL,0x75c10cb94e6a7eL,0x60a925ab69cc47L,
        0x2ff5bcd9239bd5L,0x13c2113e425f11L,0x56bd3d2f8a1437L,
        0x2c9adbab13774fL } },
    /* 91 */
    { { 0x4ab9f52a2e5f2bL,0x5e537e70b58903L,0x0f242658ebe4f2L,
        0x2648a1e7a5f9aeL,0x1b4c5081e73007L,0x6827d4aff51850L,
        0x3925e41726cd01L },
      { 0x56dd8a55ab3cfbL,0x72d6a31b6d5beaL,0x697bd2e5575112L,
        0x66935519a7aa12L,0x55e97dda7a3aceL,0x0e16afb4237b4cL,
        0x00b68fbff08093L } },
    /* 92 */
    { { 0x4b00366481d0d9L,0x37cb031fbfc5c4L,0x14643f6800dd03L,
        0x6793fef60fe0faL,0x4f43e329c92803L,0x1fce86b96a6d26L,
        0x0ad416975e213aL },
      { 0x7cc6a6711adcc9L,0x64b8a63c43c2d9L,0x1e6caa2a67c0d0L,
        0x610deffd17a54bL,0x57d669d5f38423L,0x77364b8f022636L,
        0x36d4d13602e024L } },
    /* 93 */
    { { 0x72e667ae50a2f5L,0x1b15c950c3a21aL,0x3ccc37c72e6dfeL,
        0x027f7e1d094fb8L,0x43ae1e90aa5d7eL,0x3f5feac3d97ce5L,
        0x0363ed0a336e55L },
      { 0x235f73d7663784L,0x5d8cfc588ad5a4L,0x10ab6ff333016eL,
        0x7d8886af2e1497L,0x549f34fd17988eL,0x3fc4fcaee69a33L,
        0x0622b133a13d9eL } },
    /* 94 */
    { { 0x6344cfa796c53eL,0x0e9a10d00136fdL,0x5d1d284a56efd8L,
        0x608b1968f8aca7L,0x2fa5a66776edcaL,0x13430c44f1609cL,
        0x1499973cb2152aL },
      { 0x3764648104ab58L,0x3226e409fadafcL,0x1513a8466459ddL,
        0x649206ec365035L,0x46149aa3f765b1L,0x3aebf0a035248eL,
        0x1ee60b8c373494L } },
    /* 95 */
    { { 0x4e9efcc15f3060L,0x5e5d50fd77cdc8L,0x071e5403516b58L,
        0x1b7d4e89b24ceaL,0x53b1fa66d6dc03L,0x457f15f892ab5fL,
        0x076332c9397260L },
      { 0x31422b79d7584bL,0x0b01d47e41ba80L,0x3e5611a3171528L,
        0x5f53b9a9fc1be4L,0x7e2fc3d82f110fL,0x006cf350ef0fbfL,
        0x123ae98ec81c12L } },
    /* 96 */
    { { 0x310d41df46e2f6L,0x2ff032a286cf13L,0x64751a721c4eadL,
        0x7b62bcc0339b95L,0x49acf0c195afa4L,0x359d48742544e5L,
        0x276b7632d9e2afL },
      { 0x656c6be182579aL,0x75b65a4d85b199L,0x04a911d1721bfaL,
        0x46e023d0e33477L,0x1ec2d580acd869L,0x540b456f398a37L,
        0x001f698210153dL } },
    /* 97 */
    { { 0x3ca35217b00dd0L,0x73961d034f4d3cL,0x4f520b61c4119dL,
        0x4919fde5cccff7L,0x4d0e0e6f38134dL,0x55c22586003e91L,
        0x24d39d5d8f1b19L },
      { 0x4d4fc3d73234dcL,0x40c50c9d5f8368L,0x149afbc86bf2b8L,
        0x1dbafefc21d7f1L,0x42e6b61355107fL,0x6e506cf4b54f29L,
        0x0f498a6c615228L } },
    /* 98 */
    { { 0x30618f437cfaf8L,0x059640658532c4L,0x1c8a4d90e96e1dL,
        0x4a327bcca4fb92L,0x54143b8040f1a0L,0x4ec0928c5a49e4L,
        0x2af5ad488d9b1fL },
      { 0x1b392bd5338f55L,0x539c0292b41823L,0x1fe35d4df86a02L,
        0x5fa5bb17988c65L,0x02b6cb715adc26L,0x09a48a0c2cb509L,
        0x365635f1a5a9f2L } },
    /* 99 */
    { { 0x58aa87bdc21f31L,0x156900c7cb1935L,0x0ec1f75ee2b6cfL,
        0x5f3e35a77ec314L,0x582dec7b9b7621L,0x3e65deb0e8202aL,
        0x325c314b8a66b7L },
      { 0x702e2a22f24d66L,0x3a20e9982014f1L,0x6424c5b86bbfb0L,
        0x424eea4d795351L,0x7fc4cce7c22055L,0x581383fceb92d7L,
        0x32b663f49ee81bL } },
    /* 100 */
    { { 0x76e2d0b648b73eL,0x59ca39fa50bddaL,0x18bb44f786a7e4L,
        0x28c8d49d464360L,0x1b8bf1d3a574eaL,0x7c670b9bf1635aL,
        0x2efb30a291f4b3L },
      { 0x5326c069cec548L,0x03bbe481416531L,0x08a415c8d93d6fL,
        0x3414a52120d383L,0x1f17a0fc6e9c5cL,0x0de9a090717463L,
        0x22d84b3c67ff07L } },
    /* 101 */
    { { 0x30b5014c3830ebL,0x70791dc1a18b37L,0x09e6ea4e24f423L,
        0x65e148a5253132L,0x446f05d5d40449L,0x7ad5d3d707c0e9L,
        0x18eedd63dd3ab5L },
      { 0x40d2eac6bb29e0L,0x5b0e9605e83c38L,0x554f2c666a56a8L,
        0x0ac27b6c94c48bL,0x1aaecdd91bafe5L,0x73c6e2bdf72634L,
        0x306dab96d19e03L } },
    /* 102 */
    { { 0x6d3e4b42772f41L,0x1aba7796f3a39bL,0x3a03fbb980e9c0L,
        0x2f2ea5da2186a8L,0x358ff444ef1fcfL,0x0798cc0329fcdcL,
        0x39a28bcc9aa46dL },
      { 0x42775c977fe4d2L,0x5eb8fc5483d6b0L,0x0bfe37c039e3f7L,
        0x429292eaf9df60L,0x188bdf4b840cd5L,0x06e10e090749cdL,
        0x0e52678e73192eL } },
    /* 103 */
    { { 0x05de80b08df5feL,0x2af8c77406c5f8L,0x53573c50a0304aL,
        0x277b10b751bca0L,0x65cf8c559132a5L,0x4c667abe25f73cL,
        0x0271809e05a575L },
      { 0x41ced461f7a2fbL,0x0889a9ebdd7075L,0x320c63f2b7760eL,
        0x4f8d4324151c63L,0x5af47315be2e5eL,0x73c62f6aee2885L,
        0x206d6412a56a97L } },
    /* 104 */
    { { 0x6b1c508b21d232L,0x3781185974ead6L,0x1aba7c3ebe1fcfL,
        0x5bdc03cd3f3a5aL,0x74a25036a0985bL,0x5929e30b7211b2L,
        0x16a9f3bc366bd7L },
      { 0x566a7057dcfffcL,0x23b5708a644bc0L,0x348cda2aa5ba8cL,
        0x466aa96b9750d4L,0x6a435ed9b20834L,0x2e7730f2cf9901L,
        0x2b5cd71d5b0410L } },
    /* 105 */
    { { 0x285ab3cee76ef4L,0x68895e3a57275dL,0x6fab2e48fd1265L,
        0x0f1de060428c94L,0x668a2b080b5905L,0x1b589dc3b0cb37L,
        0x3c037886592c9bL },
      { 0x7fb5c0f2e90d4dL,0x334eefb3d8c91aL,0x75747124700388L,
        0x547a2c2e2737f5L,0x2af9c080e37541L,0x0a295370d9091aL,
        0x0bb5c36dad99e6L } },
    /* 106 */
    { { 0x644116586f25cbL,0x0c3f41f9ee1f5dL,0x00628d43a3dedaL,
        0x16e1437aae9669L,0x6aba7861bf3e59L,0x60735631ff4c44L,
        0x345609efaa615eL },
      { 0x41f54792e6acefL,0x4791583f75864dL,0x37f2ff5c7508b1L,
        0x1288912516c3b0L,0x51a2135f6a539bL,0x3b775511f42091L,
        0x127c6afa7afe66L } },
    /* 107 */
    { { 0x79f4f4f7492b73L,0x583d967256342dL,0x51a729bff33ca3L,
        0x3977d2c22d8986L,0x066f528ba8d40bL,0x5d759d30f8eb94L,
        0x0f8e649192b408L },
      { 0x22d84e752555bbL,0x76953855c728c7L,0x3b2254e72aaaa4L,
        0x508cd4ce6c0212L,0x726296d6b5a6daL,0x7a77aa066986f3L,
        0x2267a497bbcf31L } },
    /* 108 */
    { { 0x7f3651bf825dc4L,0x3988817388c56fL,0x257313ed6c3dd0L,
        0x3feab7f3b8ffadL,0x6c0d3cb9e9c9b4L,0x1317be0a7b6ac4L,
        0x2a5f399d7df850L },
      { 0x2fe5a36c934f5eL,0x429199df88ded1L,0x435ea21619b357L,
        0x6aac6a063bac2bL,0x600c149978f5edL,0x76543aa1114c95L,
        0x163ca9c83c7596L } },
    /* 109 */
    { { 0x7dda4a3e4daedbL,0x1824cba360a4cdL,0x09312efd70e0c6L,
        0x454e68a146c885L,0x40aee762fe5c47L,0x29811cbd755a59L,
        0x34b37c95f28319L },
      { 0x77c58b08b717d2L,0x309470d9a0f491L,0x1ab9f40448e01cL,
        0x21c8bd819207b1L,0x6a01803e9361bcL,0x6e5e4c350ec415L,
        0x14fd55a91f8798L } },
    /* 110 */
    { { 0x4cee562f512a90L,0x0008361d53e390L,0x3789b307a892cfL,
        0x064f7be8770ae9L,0x41435d848762cfL,0x662204dd38baa6L,
        0x23d6dcf73f6c5aL },
      { 0x69bef2d2c75d95L,0x2b037c0c9bb43eL,0x495fb4d79a34cfL,
        0x184e140c601260L,0x60193f8d435f9cL,0x283fa52a0c3ad2L,
        0x1998635e3a7925L } },
    /* 111 */
    { { 0x1cfd458ce382deL,0x0dddbd201bbcaeL,0x14d2ae8ed45d60L,
        0x73d764ab0c24cbL,0x2a97fe899778adL,0x0dbd1e01eddfe9L,
        0x2ba5c72d4042c3L },
      { 0x27eebc3af788f1L,0x53ffc827fc5a30L,0x6d1d0726d35188L,
        0x4721275c50aa2aL,0x077125f02e690fL,0x6da8142405db5dL,
        0x126cef68992513L } },
    /* 112 */
    { { 0x3c6067035b2d69L,0x2a1ad7db2361acL,0x3debece6cad41cL,
        0x30095b30f9afc1L,0x25f50b9bd9c011L,0x79201b2f2c1da1L,
        0x3b5c151449c5bdL },
      { 0x76eff4127abdb4L,0x2d31e03ce0382aL,0x24ff21f8bda143L,
        0x0671f244fd3ebaL,0x0c1c00b6bcc6fbL,0x18de9f7c3ebefbL,
        0x33dd48c3809c67L } },
    /* 113 */
    { { 0x61d6c2722d94edL,0x7e426e31041cceL,0x4097439f1b47b0L,
        0x579e798b2d205bL,0x6a430d67f830ebL,0x0d2c676700f727L,
        0x05fea83a82f25bL },
      { 0x3f3482df866b98L,0x3dd353b6a5a9cdL,0x77fe6ae1a48170L,
        0x2f75cc2a8f7cddL,0x7442a3863dad17L,0x643de42d877a79L,
        0x0fec8a38fe7238L } },
    /* 114 */
    { { 0x79b70c0760ac07L,0x195d3af37e9b29L,0x1317ff20f7cf27L,
        0x624e1c739e7504L,0x67330ef50f943dL,0x775e8cf455d793L,
        0x17b94d2d913a9fL },
      { 0x4b627203609e7fL,0x06aac5fb93e041L,0x603c515fdc2611L,
        0x2592ca0d7ae472L,0x02395d1f50a6cbL,0x466ef9648f85d9L,
        0x297cf879768f72L } },
    /* 115 */
    { { 0x3489d67d85fa94L,0x0a6e5b739c8e04L,0x7ebb5eab442e90L,
        0x52665a007efbd0L,0x0967ca57b0d739L,0x24891f9d932b63L,
        0x3cc2d6dbadc9d3L },
      { 0x4b4773c81c5338L,0x73cd47dad7a0f9L,0x7c755bab6ae158L,
        0x50b03d6becefcaL,0x574d6e256d57f0L,0x188db4fffb92aeL,
        0x197e10118071eaL } },
    /* 116 */
    { { 0x45d0cbcba1e7f1L,0x1180056abec91aL,0x6c5f86624bbc28L,
        0x442c83f3b8e518L,0x4e16ae1843ecb4L,0x670cef2fd786c9L,
        0x205b4acb637d2cL },
      { 0x70b0e539aa8671L,0x67c982056bebd0L,0x645c831a5e7c36L,
        0x09e06951a14b32L,0x5dd610ad4c89e6L,0x41c35f20164831L,
        0x3821f29cb4cdb8L } },
    /* 117 */
    { { 0x2831ffaba10079L,0x70f6dac9ffe444L,0x1cfa32ccc03717L,
        0x01519fda22a3c8L,0x23215e815aaa27L,0x390671ad65cbf7L,
        0x03dd4d72de7d52L },
      { 0x1ecd972ee95923L,0x166f8da3813e8eL,0x33199bbd387a1aL,
        0x04525fe15e3dc7L,0x44d2ef54165898L,0x4b7e47d3dc47f7L,
        0x10d5c8db0b5d44L } },
    /* 118 */
    { { 0x176d95ba9cdb1bL,0x14025f04f23dfcL,0x49379332891687L,
        0x6625e5ccbb2a57L,0x7ac0abdbf9d0e5L,0x7aded4fbea15b2L,
        0x314844ac184d67L },
      { 0x6d9ce34f05eae3L,0x3805d2875856d2L,0x1c2122f85e40ebL,
        0x51cb9f2d483a9aL,0x367e91e20f1702L,0x573c3559838dfdL,
        0x0b282b0cb85af1L } },
    /* 119 */
    { { 0x6a12e4ef871eb5L,0x64bb517e14f5ffL,0x29e04d3aaa530bL,
        0x1b07d88268f261L,0x411be11ed16fb0L,0x1f480536db70bfL,
        0x17a7deadfd34e4L },
      { 0x76d72f30646612L,0x5a3bbb43a1b0a0L,0x5e1687440e82bfL,
        0x713b5e69481112L,0x46c3dcb499e174L,0x0862da3b4e2a24L,
        0x31cb55b4d62681L } },
    /* 120 */
    { { 0x5ffc74dae5bb45L,0x18944c37adb9beL,0x6aaa63b1ee641aL,
        0x090f4b6ee057d3L,0x4045cedd2ee00fL,0x21c2c798f7c282L,
        0x2c2c6ef38cd6bdL },
      { 0x40d78501a06293L,0x56f8caa5cc89a8L,0x7231d5f91b37aeL,
        0x655f1e5a465c6dL,0x3f59a81f9cf783L,0x09bbba04c23624L,
        0x0f71ee23bbacdeL } },
    /* 121 */
    { { 0x38d398c4741456L,0x5204c0654243c3L,0x34498c916ea77eL,
        0x12238c60e5fe43L,0x0fc54f411c7625L,0x30b2ca43aa80b6L,
        0x06bead1bb6ea92L },
      { 0x5902ba8674b4adL,0x075ab5b0fa254eL,0x58db83426521adL,
        0x5b66b6b3958e39L,0x2ce4e39890e07bL,0x46702513338b37L,
        0x363690c2ded4d7L } },
    /* 122 */
    { { 0x765642c6b75791L,0x0f4c4300d7f673L,0x404d8bbe101425L,
        0x61e91c88651f1bL,0x61ddc9bc60aed8L,0x0ef36910ce2e65L,
        0x04b44367aa63b8L },
      { 0x72822d3651b7dcL,0x4b750157a2716dL,0x091cb4f2118d16L,
        0x662ba93b101993L,0x447cbd54a1d40aL,0x12cdd48d674848L,
        0x16f10415cbec69L } },
    /* 123 */
    { { 0x0c57a3a751cd0eL,0x0833d7478fadceL,0x1e751f55686436L,
        0x489636c58e1df7L,0x26ad6da941266fL,0x22225d3559880fL,
        0x35b397c45ba0e2L },
      { 0x3ca97b70e1f2ceL,0x78e50427a8680cL,0x06137e042a8f91L,
        0x7ec40d2500b712L,0x3f0ad688ad7b0dL,0x24746fb33f9513L,
        0x3638fcce688f0bL } },
    /* 124 */
    { { 0x753163750bed6fL,0x786507cd16157bL,0x1d6ec228ce022aL,
        0x587255f42d1b31L,0x0c6adf72a3a0f6L,0x4bfeee2da33f5eL,
        0x08b7300814de6cL },
      { 0x00bf8df9a56e11L,0x75aead48fe42e8L,0x3de9bad911b2e2L,
        0x0fadb233e4b8bbL,0x5b054e8fd84f7dL,0x5eb3064152889bL,
        0x01c1c6e8c777a1L } },
    /* 125 */
    { { 0x5fa0e598f8fcb9L,0x11c129a1ae18dfL,0x5c41b482a2273bL,
        0x545664e5044c9cL,0x7e01c915bfb9abL,0x7f626e19296aa0L,
        0x20c91a9822a087L },
      { 0x273a9fbe3c378fL,0x0f126b44b7d350L,0x493764a75df951L,
        0x32dec3c367d24bL,0x1a7ae987fed9d3L,0x58a93055928b85L,
        0x11626975d7775fL } },
    /* 126 */
    { { 0x2bb174a95540a9L,0x10de02c58b613fL,0x2fa8f7b861f3eeL,
        0x44731260bdf3b3L,0x19c38ff7da41feL,0x3535a16e3d7172L,
        0x21a948b83cc7feL },
      { 0x0e6f72868bc259L,0x0c70799df3c979L,0x526919955584c3L,
        0x4d95fda04f8fa2L,0x7bb228e6c0f091L,0x4f728b88d92194L,
        0x2b361c5a136bedL } },
    /* 127 */
    { { 0x0c72ca10c53841L,0x4036ab49f9da12L,0x578408d2b7082bL,
        0x2c4903201fbf5eL,0x14722b3f42a6a8L,0x1997b786181694L,
        0x25c6f10de32849L },
      { 0x79f46d517ff2ffL,0x2dc5d97528f6deL,0x518a494489aa72L,
        0x52748f8af3cf97L,0x472da30a96bb16L,0x1be228f92465a9L,
        0x196f0c47d60479L } },
    /* 128 */
    { { 0x47dd7d139b3239L,0x049c9b06775d0fL,0x627ffc00562d5eL,
        0x04f578d5e5e243L,0x43a788ffcef8b9L,0x7db320be9dde28L,
        0x00837528b8572fL },
      { 0x2969eca306d695L,0x195b72795ec194L,0x5e1fa9b8e77e50L,
        0x4c627f2b3fbfd5L,0x4b91e0d0ee10ffL,0x5698c8d0f35833L,
        0x12d3a9431f475eL } },
    /* 129 */
    { { 0x6409457a0db57eL,0x795b35192e0433L,0x146f973fe79805L,
        0x3d49c516dfb9cfL,0x50dfc3646b3cdaL,0x16a08a2210ad06L,
        0x2b4ef5bcd5b826L },
      { 0x5ebabfee2e3e3eL,0x2e048e724d9726L,0x0a7a7ed6abef40L,
        0x71ff7f83e39ad8L,0x3405ac52a1b852L,0x2e3233357a608dL,
        0x38c1bf3b0e40e6L } },
    /* 130 */
    { { 0x59aec823e4712cL,0x6ed9878331ddadL,0x1cc6faf629f2a0L,
        0x445ff79f36c18cL,0x4edc7ed57aff3dL,0x22ee54c8bdd9e8L,
        0x35398f42d72ec5L },
      { 0x4e7a1cceee0ecfL,0x4c66a707dd1d31L,0x629ad157a23c04L,
        0x3b2c6031dc3c83L,0x3336acbcd3d96cL,0x26ce43adfce0f0L,
        0x3c869c98d699dcL } },
    /* 131 */
    { { 0x58b3cd9586ba11L,0x5d6514b8090033L,0x7c88c3bd736782L,
        0x1735f84f2130edL,0x47784095a9dee0L,0x76312c6e47901bL,
        0x1725f6ebc51455L },
      { 0x6744344bc4503eL,0x16630b4d66e12fL,0x7b3481752c3ec7L,
        0x47bb2ed1f46f95L,0x08a1a497dd1bcfL,0x1f525df2b8ed93L,
        0x0fe492ea993713L } },
    /* 132 */
    { { 0x71b8dd7268b448L,0x1743dfaf3728d7L,0x23938d547f530aL,
        0x648c3d497d0fc6L,0x26c0d769e3ad45L,0x4d25108769a806L,
        0x3fbf2025143575L },
      { 0x485bfd90339366L,0x2de2b99ed87461L,0x24a33347713badL,
        0x1674bc7073958aL,0x5bb2373ee85b5fL,0x57f9bd657e662cL,
        0x2041b248d39042L } },
    /* 133 */
    { { 0x5f01617d02f4eeL,0x2a8e31c4244b91L,0x2dab3e790229e0L,
        0x72d319ea7544afL,0x01ffb8b000cb56L,0x065e63b0daafd3L,
        0x3d7200a7111d6fL },
      { 0x4561ce1b568973L,0x37034c532dd8ecL,0x1368215020be02L,
        0x30e7184cf289ebL,0x199e0c27d815deL,0x7ee1b4dff324e5L,
        0x2f4a11de7fab5cL } },
    /* 134 */
    { { 0x33c2f99b1cdf2bL,0x1e0d78bf42a2c0L,0x64485dececaa67L,
        0x2242a41be93e92L,0x62297b1f15273cL,0x16ebfaafb02205L,
        0x0f50f805f1fdabL },
      { 0x28bb0b3a70eb28L,0x5b1c7d0160d683L,0x05c30a37959f78L,
        0x3d9301184922d2L,0x46c1ead7dbcb1aL,0x03ee161146a597L,
        0x2d413ed9a6ccc1L } },
    /* 135 */
    { { 0x685ab5f97a27c2L,0x59178214023751L,0x4ffef3c585ab17L,
        0x2bc85302aba2a9L,0x675b001780e856L,0x103c8a37f0b33dL,
        0x2241e98ece70a6L },
      { 0x546738260189edL,0x086c8f7a6b96edL,0x00832ad878a129L,
        0x0b679056ba7462L,0x020ce6264bf8c4L,0x3f9f4b4d92abfbL,
        0x3e9c55343c92edL } },
    /* 136 */
    { { 0x482cec9b3f5034L,0x08b59b3cd1fa30L,0x5a55d1bc8e58b5L,
        0x464a5259337d8eL,0x0a5b6c66ade5a5L,0x55db77b504ddadL,
        0x015992935eac35L },
      { 0x54fe51025e32fcL,0x5d7f52dbe4a579L,0x08c564a8c58696L,
        0x4482a8bec4503fL,0x440e75d9d94de9L,0x6992d768020bfaL,
        0x06c311e8ba01f6L } },
    /* 137 */
    { { 0x2a6ac808223878L,0x04d3ccb4aab0b8L,0x6e6ef09ff6e823L,
        0x15cb03ee9158dcL,0x0dc58919171bf7L,0x3273568abf3cb1L,
        0x1b55245b88d98bL },
      { 0x28e9383b1de0c1L,0x30d5009e4f1f1bL,0x334d185a56a134L,
        0x0875865dfa4c46L,0x266edf5eae3beeL,0x2e03ff16d1f7e5L,
        0x29a36bd9f0c16dL } },
    /* 138 */
    { { 0x004cff44b2e045L,0x426c96380ba982L,0x422292281e46d7L,
        0x508dd8d29d7204L,0x3a4ea73fb2995eL,0x4be64090ae07b2L,
        0x3339177a0eff22L },
      { 0x74a97ec2b3106eL,0x0c616d09169f5fL,0x1bb5d8907241a7L,
        0x661fb67f6d41bdL,0x018a88a0daf136L,0x746333a093a7b4L,
        0x3e19f1ac76424eL } },
    /* 139 */
    { { 0x542a5656527296L,0x0e7b9ce22f1bc9L,0x31b0945992b89bL,
        0x6e0570eb85056dL,0x32daf813483ae5L,0x69eeae9d59bb55L,
        0x315ad4b730b557L },
      { 0x2bc16795f32923L,0x6b02b7ba55130eL,0x1e9da67c012f85L,
        0x5616f014dabf8fL,0x777395fcd9c723L,0x2ff075e7743246L,
        0x2993538aff142eL } },
    /* 140 */
    { { 0x72dae20e552b40L,0x2e4ba69aa5d042L,0x001e563e618bd2L,
        0x28feeba3c98772L,0x648c356da2a907L,0x687e2325069ea7L,
        0x0d34ab09a394f0L },
      { 0x73c21813111286L,0x5829b53b304e20L,0x6fba574de08076L,
        0x79f7058f61614eL,0x4e71c9316f1191L,0x24ef12193e0a89L,
        0x35dc4e2bc9d848L } },
    /* 141 */
    { { 0x045e6d3b4ad1cdL,0x729c95493782f0L,0x77f59de85b361aL,
        0x5309b4babf28f8L,0x4d893d9290935fL,0x736f47f2b2669eL,
        0x23270922d757f3L },
      { 0x23a4826f70d4e9L,0x68a8c63215d33eL,0x4d6c2069205c9cL,
        0x46b2938a5eebe0L,0x41d1f1e2de3892L,0x5ca1775544bcb0L,
        0x3130629e5d19dcL } },
    /* 142 */
    { { 0x6e2681593375acL,0x117cfbabc22621L,0x6c903cd4e13ccaL,
        0x6f358f14d4bd97L,0x1bc58fa11089f1L,0x36aa2db4ac426aL,
        0x15ced8464b7ea1L },
      { 0x6966836cba7df5L,0x7c2b1851568113L,0x22b50ff2ffca66L,
        0x50e77d9f48e49aL,0x32775e9bbc7cc9L,0x403915bb0ece71L,
        0x1b8ec7cb9dd7aaL } },
    /* 143 */
    { { 0x65a888b677788bL,0x51887fac2e7806L,0x06792636f98d2bL,
        0x47bbcd59824c3bL,0x1aca908c43e6dcL,0x2e00d15c708981L,
        0x08e031c2c80634L },
      { 0x77fbc3a297c5ecL,0x10a7948af2919eL,0x10cdafb1fb6b2fL,
        0x27762309b486f0L,0x13abf26bbac641L,0x53da38478fc3eeL,
        0x3c22eff379bf55L } },
    /* 144 */
    { { 0x0163f484770ee3L,0x7f28e8942e0cbfL,0x5f86cb51b43831L,
        0x00feccd4e4782fL,0x40e5b417eafe7dL,0x79e5742bbea228L,
        0x3717154aa469beL },
      { 0x271d74a270f721L,0x40eb400890b70cL,0x0e37be81d4cb02L,
        0x786907f4e8d43fL,0x5a1f5b590a7acbL,0x048861883851fdL,
        0x11534a1e563dbbL } },
    /* 145 */
    { { 0x37a6357c525435L,0x6afe6f897b78a5L,0x7b7ff311d4f67bL,
        0x38879df15dc9f4L,0x727def7b8ba987L,0x20285dd0db4436L,
        0x156b0fc64b9243L },
      { 0x7e3a6ec0c1c390L,0x668a88d9bcf690L,0x5925aba5440dbeL,
        0x0f6891a044f593L,0x70b46edfed4d97L,0x1a6cc361bab201L,
        0x046f5bc6e160bcL } },
    /* 146 */
    { { 0x79350f076bc9d1L,0x077d9e79a586b9L,0x0896bc0c705764L,
        0x58e632b90e7e46L,0x14e87e0ad32488L,0x4b1bb3f72c6e00L,
        0x3c3ce9684a5fc5L },
      { 0x108fbaf1f703aaL,0x08405ecec17577L,0x199a8e2d44be73L,
        0x2eb22ed0067763L,0x633944deda3300L,0x20d739eb8e5efbL,
        0x2bbbd94086b532L } },
    /* 147 */
    { { 0x03c8b17a19045dL,0x6205a0a504980bL,0x67fdb3e962b9f0L,
        0x16399e01511a4bL,0x44b09fe9dffc96L,0x00a74ff44a1381L,
        0x14590deed3f886L },
      { 0x54e3d5c2a23ddbL,0x310e5138209d28L,0x613f45490c1c9bL,
        0x6bbc85d44bbec8L,0x2f85fc559e73f6L,0x0d71fa7d0fa8cbL,
        0x2898571d17fbb9L } },
    /* 148 */
    { { 0x5607a84335167dL,0x3009c1eb910f91L,0x7ce63447e62d0bL,
        0x03a0633afcf89eL,0x1234b5aaa50872L,0x5a307b534d547bL,
        0x2f4e97138a952eL },
      { 0x13914c2db0f658L,0x6cdcb47e6e75baL,0x5549169caca772L,
        0x0f20423dfeb16fL,0x6b1ae19d180239L,0x0b7b3bee9b7626L,
        0x1ca81adacfe4efL } },
    /* 149 */
    { { 0x219ec3ad19d96fL,0x3549f6548132dbL,0x699889c7aacd0bL,
        0x74602a58730b19L,0x62dc63bcece81cL,0x316f991c0c317aL,
        0x2b8627867b95e3L },
      { 0x67a25ddced1eedL,0x7e14f0eba756e7L,0x0873fbc09b0495L,
        0x0fefb0e16596adL,0x03e6cd98ef39bbL,0x1179b1cded249dL,
        0x35c79c1db1edc2L } },
    /* 150 */
    { { 0x1368309d4245bfL,0x442e55852a7667L,0x095b0f0f348b65L,
        0x6834cf459dfad4L,0x6645950c9be910L,0x06bd81288c71e6L,
        0x1b015b6e944edfL },
      { 0x7a6a83045ab0e3L,0x6afe88b9252ad0L,0x2285bd65523502L,
        0x6c78543879a282L,0x1c5e264b5c6393L,0x3a820c6a7453eeL,
        0x37562d1d61d3c3L } },
    /* 151 */
    { { 0x6c084f62230c72L,0x599490270bc6cfL,0x1d3369ddd3c53dL,
        0x516ddb5fac5da0L,0x35ab1e15011b1aL,0x5fba9106d3a180L,
        0x3be0f092a0917cL },
      { 0x57328f9fdc2538L,0x0526323fc8d5f6L,0x10cbb79521e602L,
        0x50d01167147ae2L,0x2ec7f1b3cda99eL,0x43073cc736e7beL,
        0x1ded89cadd83a6L } },
    /* 152 */
    { { 0x1d51bda65d56d5L,0x63f2fd4d2dc056L,0x326413d310ea6dL,
        0x3abba5bca92876L,0x6b9aa8bc4d6ebeL,0x1961c687f15d5dL,
        0x311cf07464c381L },
      { 0x2321b1064cd8aeL,0x6e3caac4443850L,0x3346fc4887d2d0L,
        0x1640417e0e640fL,0x4a958a52a07a9eL,0x1346a1b1cb374cL,
        0x0a793cf79beccbL } },
    /* 153 */
    { { 0x29d56cba89aaa5L,0x1581898c0b3c15L,0x1af5b77293c082L,
        0x1617ba53a006ceL,0x62dd3b384e475fL,0x71a9820c3f962aL,
        0x0e4938920b854eL },
      { 0x0b8d98849808abL,0x64c14923546de7L,0x6a20883b78a6fcL,
        0x72de211428acd6L,0x009678b47915bbL,0x21b5269ae5dae6L,
        0x313cc0e60b9457L } },
    /* 154 */
    { { 0x69ee421b1de38bL,0x44b484c6cec1c7L,0x0240596c6a8493L,
        0x2321a62c85fb9eL,0x7a10921802a341L,0x3d2a95507e45c3L,
        0x0752f40f3b6714L },
      { 0x596a38798751e6L,0x46bf186a0feb85L,0x0b23093e23b49cL,
        0x1bfa7bc5afdc07L,0x4ba96f873eefadL,0x292e453fae9e44L,
        0x2773646667b75cL } },
    /* 155 */
    { { 0x1f81a64e94f22aL,0x3125ee3d8683ddL,0x76a660a13b9582L,
        0x5aa584c3640c6eL,0x27cc99fd472953L,0x7048f4d58061d1L,
        0x379a1397ac81e8L },
      { 0x5d1ecd2b6b956bL,0x0829e0366b0697L,0x49548cec502421L,
        0x7af5e2f717c059L,0x329a25a0fec54eL,0x028e99e4bcd7f1L,
        0x071d5fe81fca78L } },
    /* 156 */
    { { 0x4b5c4aeb0fdfe4L,0x1367e11326ce37L,0x7c16f020ef5f19L,
        0x3c55303d77b471L,0x23a4457a06e46aL,0x2174426dd98424L,
        0x226f592114bd69L },
      { 0x4411b94455f15aL,0x52e0115381fae4L,0x45b6d8efbc8f7eL,
        0x58b1221bd86d26L,0x284fb6f8a7ec1fL,0x045835939ddd30L,
        0x0216960accd598L } },
    /* 157 */
    { { 0x4b61f9ec1f138aL,0x4460cd1e18502bL,0x277e4fce3c4726L,
        0x0244246d6414b9L,0x28fbfcef256984L,0x3347ed0db40577L,
        0x3b57fa9e044718L },
      { 0x4f73bcd6d1c833L,0x2c0d0dcf7f0136L,0x2010ac75454254L,
        0x7dc4f6151539a8L,0x0b8929ef6ea495L,0x517e20119d2bdfL,
        0x1e29f9a126ba15L } },
    /* 158 */
    { { 0x683a7c10470cd8L,0x0d05f0dbe0007fL,0x2f6a5026d649cdL,
        0x249ce2fdaed603L,0x116dc1e7a96609L,0x199bd8d82a0b98L,
        0x0694ad0219aeb2L },
      { 0x03a3656e864045L,0x4e552273df82a6L,0x19bcc7553d17abL,
        0x74ac536c1df632L,0x440302fb4a86f6L,0x1becec0e31c9feL,
        0x002045f8fa46b8L } },
    /* 159 */
    { { 0x5833ba384310a2L,0x1db83fad93f8baL,0x0a12713ee2f7edL,
        0x40e0f0fdcd2788L,0x1746de5fb239a5L,0x573748965cfa15L,
        0x1e3dedda0ef650L },
      { 0x6c8ca1c87607aeL,0x785dab9554fc0eL,0x649d8f91860ac8L,
        0x4436f88b52c0f9L,0x67f22ca8a5e4a3L,0x1f990fd219e4c9L,
        0x013dd21c08573fL } },
    /* 160 */
    { { 0x05d116141d161cL,0x5c1d2789da2ea5L,0x11f0d861f99f34L,
        0x692c2650963153L,0x3bd69f5329539eL,0x215898eef8885fL,
        0x041f79dd86f7f1L },
      { 0x76dcc5e96beebdL,0x7f2b50cb42a332L,0x067621cabef8abL,
        0x31e0be607054edL,0x4c67c5e357a3daL,0x5b1a63fbfb1c2bL,
        0x3112efbf5e5c31L } },
    /* 161 */
    { { 0x3f83e24c0c62f1L,0x51dc9c32aae4e0L,0x2ff89b33b66c78L,
        0x21b1c7d354142cL,0x243d8d381c84bcL,0x68729ee50cf4b7L,
        0x0ed29e0f442e09L },
      { 0x1ad7b57576451eL,0x6b2e296d6b91dcL,0x53f2b306e30f42L,
        0x3964ebd9ee184aL,0x0a32855df110e4L,0x31f2f90ddae05fL,
        0x3410cd04e23702L } },
    /* 162 */
    { { 0x60d1522ca8f2feL,0x12909237a83e34L,0x15637f80d58590L,
        0x3c72431b6d714dL,0x7c8e59a615bea2L,0x5f977b688ef35aL,
        0x071c198c0b3ab0L },
      { 0x2b54c699699b4bL,0x14da473c2fd0bcL,0x7ba818ea0ad427L,
        0x35117013940b2fL,0x6e1df6b5e609dbL,0x3f42502720b64dL,
        0x01ee7dc890e524L } },
    /* 163 */
    { { 0x12ec1448ff4e49L,0x3e2edac882522bL,0x20455ab300f93aL,
        0x5849585bd67c14L,0x0393d5aa34ba8bL,0x30f9a1f2044fa7L,
        0x1059c9377a93e0L },
      { 0x4e641cc0139e73L,0x0d9f23c9b0fa78L,0x4b2ad87e2b83f9L,
        0x1c343a9f6d9e3cL,0x1098a4cb46de4dL,0x4ddc893843a41eL,
        0x1797f4167d6e3aL } },
    /* 164 */
    { { 0x4add4675856031L,0x499bd5e5f7a0ffL,0x39ea1f1202271eL,
        0x0ecd7480d7a91eL,0x395f5e5fc10956L,0x0fa7f6b0c9f79bL,
        0x2fad4623aed6cbL },
      { 0x1563c33ae65825L,0x29881cafac827aL,0x50650baf4c45a1L,
        0x034aad988fb9e9L,0x20a6224dc5904cL,0x6fb141a990732bL,
        0x3ec9ae1b5755deL } },
    /* 165 */
    { { 0x3108e7c686ae17L,0x2e73a383b4ad8aL,0x4e6bb142ba4243L,
        0x24d355922c1d80L,0x2f850dd9a088baL,0x21c50325dd5e70L,
        0x33237dd5bd7fa4L },
      { 0x7823a39cab7630L,0x1535f71cff830eL,0x70d92ff0599261L,
        0x227154d2a2477cL,0x495e9bbb4f871cL,0x40d2034835686bL,
        0x31b08f97eaa942L } },
    /* 166 */
    { { 0x0016c19034d8ddL,0x68961627cf376fL,0x6acc90681615aeL,
        0x6bc7690c2e3204L,0x6ddf28d2fe19a2L,0x609b98f84dae4dL,
        0x0f32bfd7c94413L },
      { 0x7d7edc6b21f843L,0x49bbd2ebbc9872L,0x593d6ada7b6a23L,
        0x55736602939e9cL,0x79461537680e39L,0x7a7ee9399ca7cdL,
        0x008776f6655effL } },
    /* 167 */
    { { 0x64585f777233cfL,0x63ec12854de0f6L,0x6b7f9bbbc3f99dL,
        0x301c014b1b55d3L,0x7cf3663bbeb568L,0x24959dcb085bd1L,
        0x12366aa6752881L },
      { 0x77a74c0da5e57aL,0x3279ca93ad939fL,0x33c3c8a1ef08c9L,
        0x641b05ab42825eL,0x02f416d7d098dbL,0x7e3d58be292b68L,
        0x1864dbc46e1f46L } },
    /* 168 */
    { { 0x1da167b8153a9dL,0x47593d07d9e155L,0x386d984e12927fL,
        0x421a6f08a60c7cL,0x5ae9661c24dab3L,0x7927b2e7874507L,
        0x3266ea80609d53L },
      { 0x7d198f4c26b1e3L,0x430d4ea2c4048eL,0x58d8ab77e84ba3L,
        0x1cb14299c37297L,0x6db6031e8f695cL,0x159bd855e26d55L,
        0x3f3f6d318a73ddL } },
    /* 169 */
    { { 0x3ee958cca40298L,0x02a7e5eba32ad6L,0x43b4bab96f0e1eL,
        0x534be79062b2b1L,0x029ead089b37e3L,0x4d585da558f5aaL,
        0x1f9737eb43c376L },
      { 0x0426dfd9b86202L,0x4162866bc0a9f3L,0x18fc518e7bb465L,
        0x6db63380fed812L,0x421e117f709c30L,0x1597f8d0f5cee6L,
        0x04ffbf1289b06aL } },
    /* 170 */
    { { 0x61a1987ffa0a5fL,0x42058c7fc213c6L,0x15b1d38447d2c9L,
        0x3d5f5d7932565eL,0x5db754af445fa7L,0x5d489189fba499L,
        0x02c4c55f51141bL },
      { 0x26b15972e9993dL,0x2fc90bcbd97c45L,0x2ff60f8684b0f1L,
        0x1dc641dd339ab0L,0x3e38e6be23f82cL,0x3368162752c817L,
        0x19bba80ceb45ceL } },
    /* 171 */
    { { 0x7c6e95b4c6c693L,0x6bbc6d5efa7093L,0x74d7f90bf3bf1cL,
        0x54d5be1f0299a1L,0x7cb24f0aa427c6L,0x0a18f3e086c941L,
        0x058a1c90e4faefL },
      { 0x3d6bd016927e1eL,0x1da4ce773098b8L,0x2133522e690056L,
        0x0751416d3fc37eL,0x1beed1643eda66L,0x5288b6727d5c54L,
        0x199320e78655c6L } },
    /* 172 */
    { { 0x74575027eeaf94L,0x124bd533c3ceaeL,0x69421ab7a8a1d7L,
        0x37f2127e093f3dL,0x40281765252a08L,0x25a228798d856dL,
        0x326eca62759c4cL },
      { 0x0c337c51acb0a5L,0x122ba78c1ef110L,0x02498adbb68dc4L,
        0x67240c124b089eL,0x135865d25d9f89L,0x338a76d5ae5670L,
        0x03a8efaf130385L } },
    /* 173 */
    { { 0x3a450ac5e49beaL,0x282af80bb4b395L,0x6779eb0db1a139L,
        0x737cabdd174e55L,0x017b14ca79b5f2L,0x61fdef6048e137L,
        0x3acc12641f6277L },
      { 0x0f730746fe5096L,0x21d05c09d55ea1L,0x64d44bddb1a560L,
        0x75e5035c4778deL,0x158b7776613513L,0x7b5efa90c7599eL,
        0x2caa0791253b95L } },
    /* 174 */
    { { 0x288e5b6d53e6baL,0x435228909d45feL,0x33b4cf23b2a437L,
        0x45b352017d6db0L,0x4372d579d6ef32L,0x0fa9e5badbbd84L,
        0x3a78cff24759bbL },
      { 0x0899d2039eab6eL,0x4cf47d2f76bc22L,0x373f739a3a8c69L,
        0x09beaa5b1000b3L,0x0acdfbe83ebae5L,0x10c10befb0e900L,
        0x33d2ac4cc31be3L } },
    /* 175 */
    { { 0x765845931e08fbL,0x2a3c2a0dc58007L,0x7270da587d90e1L,
        0x1ee648b2bc8f86L,0x5d2ca68107b29eL,0x2b7064846e9e92L,
        0x3633ed98dbb962L },
      { 0x5e0f16a0349b1bL,0x58d8941f570ca4L,0x20abe376a4cf34L,
        0x0f4bd69a360977L,0x21eb07cc424ba7L,0x720d2ecdbbe6ecL,
        0x255597d5a97c34L } },
    /* 176 */
    { { 0x67bbf21a0f5e94L,0x422a3b05a64fc1L,0x773ac447ebddc7L,
        0x1a1331c08019f1L,0x01ef6d269744ddL,0x55f7be5b3b401aL,
        0x072e031c681273L },
      { 0x7183289e21c677L,0x5e0a3391f3162fL,0x5e02d9e65d914aL,
        0x07c79ea1adce2fL,0x667ca5c2e1cbe4L,0x4f287f22caccdaL,
        0x27eaa81673e75bL } },
    /* 177 */
    { { 0x5246180a078fe6L,0x67cc8c9fa3bb15L,0x370f8dd123db31L,
        0x1938dafa69671aL,0x5af72624950c5eL,0x78cc5221ebddf8L,
        0x22d616fe2a84caL },
      { 0x723985a839327fL,0x24fa95584a5e22L,0x3d8a5b3138d38bL,
        0x3829ef4a017acfL,0x4f09b00ae055c4L,0x01df84552e4516L,
        0x2a7a18993e8306L } },
    /* 178 */
    { { 0x7b6224bc310eccL,0x69e2cff429da16L,0x01c850e5722869L,
        0x2e4889443ee84bL,0x264a8df1b3d09fL,0x18a73fe478d0d6L,
        0x370b52740f9635L },
      { 0x52b7d3a9d6f501L,0x5c49808129ee42L,0x5b64e2643fd30cL,
        0x27d903fe31b32cL,0x594cb084d078f9L,0x567fb33e3ae650L,
        0x0db7be9932cb65L } },
    /* 179 */
    { { 0x19b78113ed7cbeL,0x002b2f097a1c8cL,0x70b1dc17fa5794L,
        0x786e8419519128L,0x1a45ba376af995L,0x4f6aa84b8d806cL,
        0x204b4b3bc7ca47L },
      { 0x7581a05fd94972L,0x1c73cadb870799L,0x758f6fefc09b88L,
        0x35c62ba8049b42L,0x6f5e71fc164cc3L,0x0cd738b5702721L,
        0x10021afac9a423L } },
    /* 180 */
    { { 0x654f7937e3c115L,0x5d198288b515cbL,0x4add965c25a6e3L,
        0x5a37df33cd76ffL,0x57bb7e288e1631L,0x049b69089e1a31L,
        0x383a88f4122a99L },
      { 0x4c0e4ef3d80a73L,0x553c77ac9f30e2L,0x20bb18c2021e82L,
        0x2aec0d1c4225c5L,0x397fce0ac9c302L,0x2ab0c2a246e8aaL,
        0x02e5e5190be080L } },
    /* 181 */
    { { 0x7a255a4ae03080L,0x0d68b01513f624L,0x29905bd4e48c8cL,
        0x1d81507027466bL,0x1684aaeb70dee1L,0x7dd460719f0981L,
        0x29c43b0f0a390cL },
      { 0x272567681b1f7dL,0x1d2a5f8502e0efL,0x0fd5cd6b221befL,
        0x5eb4749e9a0434L,0x7d1553a324e2a6L,0x2eefd8e86a7804L,
        0x2ad80d5335109cL } },
    /* 182 */
    { { 0x25342aef4c209dL,0x24e811ac4e0865L,0x3f209757f8ae9dL,
        0x1473ff8a5da57bL,0x340f61c3919cedL,0x7523bf85fb9bc0L,
        0x319602ebca7cceL },
      { 0x121e7541d442cbL,0x4ffa748e49c95cL,0x11493cd1d131dcL,
        0x42b215172ab6b5L,0x045fd87e13cc77L,0x0ae305df76342fL,
        0x373b033c538512L } },
    /* 183 */
    { { 0x389541e9539819L,0x769f3b29b7e239L,0x0d05f695e3232cL,
        0x029d04f0e9a9fbL,0x58b78b7a697fb8L,0x7531b082e6386bL,
        0x215d235bed95a9L },
      { 0x503947c1859c5dL,0x4b82a6ba45443fL,0x78328eab71b3a5L,
        0x7d8a77f8cb3509L,0x53fcd9802e41d4L,0x77552091976edbL,
        0x226c60ad7a5156L } },
    /* 184 */
    { { 0x77ad6a43360710L,0x0fdeabd326d7aeL,0x4012886c92104aL,
        0x2d6c378dd7ae33L,0x7e72ef2c0725f3L,0x4a4671f4ca18e0L,
        0x0afe3b4bb6220fL },
      { 0x212cf4b56e0d6aL,0x7c24d086521960L,0x0662cf71bd414dL,
        0x1085b916c58c25L,0x781eed2be9a350L,0x26880e80db6ab2L,
        0x169e356442f061L } },
    /* 185 */
    { { 0x57aa2ad748b02cL,0x68a34256772a9aL,0x1591c44962f96cL,
        0x110a9edd6e53d2L,0x31eab597e091a3L,0x603e64e200c65dL,
        0x2f66b72e8a1cfcL },
      { 0x5c79d138543f7fL,0x412524363fdfa3L,0x547977e3b40008L,
        0x735ca25436d9f7L,0x232b4888cae049L,0x27ce37a53d8f23L,
        0x34d45881a9b470L } },
    /* 186 */
    { { 0x76b95255924f43L,0x035c9f3bd1aa5dL,0x5eb71a010b4bd0L,
        0x6ce8dda7e39f46L,0x35679627ea70c0L,0x5c987767c7d77eL,
        0x1fa28952b620b7L },
      { 0x106f50b5924407L,0x1cc3435a889411L,0x0597cdce3bc528L,
        0x738f8b0d5077d1L,0x5894dd60c7dd6aL,0x0013d0721f5e2eL,
        0x344573480527d3L } },
    /* 187 */
    { { 0x2e2c1da52abf77L,0x394aa8464ad05eL,0x095259b7330a83L,
        0x686e81cf6a11f5L,0x405c7e48c93c7cL,0x65c3ca9444a2ecL,
        0x07bed6c59c3563L },
      { 0x51f9d994fb1471L,0x3c3ecfa5283b4eL,0x494dccda63f6ccL,
        0x4d07b255363a75L,0x0d2b6d3155d118L,0x3c688299fc9497L,
        0x235692fa3dea3aL } },
    /* 188 */
    { { 0x16b4d452669e98L,0x72451fa85406b9L,0x674a145d39151fL,
        0x325ffd067ae098L,0x527e7805cd1ae0L,0x422a1d1789e48dL,
        0x3e27be63f55e07L },
      { 0x7f95f6dee0b63fL,0x008e444cc74969L,0x01348f3a72b614L,
        0x000cfac81348c3L,0x508ae3e5309ce5L,0x2584fcdee44d34L,
        0x3a4dd994899ee9L } },
    /* 189 */
    { { 0x4d289cc0368708L,0x0e5ebc60dc3b40L,0x78cc44bfab1162L,
        0x77ef2173b7d11eL,0x06091718e39746L,0x30fe19319b83a4L,
        0x17e8f2988529c6L },
      { 0x68188bdcaa9f2aL,0x0e64b1350c1bddL,0x5b18ebac7cc4b3L,
        0x75315a9fcc046eL,0x36e9770fd43db4L,0x54c5857fc69121L,
        0x0417e18f3e909aL } },
    /* 190 */
    { { 0x29795db38059adL,0x6efd20c8fd4016L,0x3b6d1ce8f95a1aL,
        0x4db68f177f8238L,0x14ec7278d2340fL,0x47bd77ff2b77abL,
        0x3d2dc8cd34e9fcL },
      { 0x285980a5a83f0bL,0x08352e2d516654L,0x74894460481e1bL,
        0x17f6f3709c480dL,0x6b590d1b55221eL,0x45c100dc4c9be9L,
        0x1b13225f9d8b91L } },
    /* 191 */
    { { 0x0b905fb4b41d9dL,0x48cc8a474cb7a2L,0x4eda67e8de09b2L,
        0x1de47c829adde8L,0x118ad5b9933d77L,0x7a12665ac3f9a4L,
        0x05631a4fb52997L },
      { 0x5fb2a8e6806e63L,0x27d96bbcca369bL,0x46066f1a6b8c7bL,
        0x63b58fc7ca3072L,0x170a36229c0d62L,0x57176f1e463203L,
        0x0c7ce083e73b9cL } },
    /* 192 */
    { { 0x31caf2c09e1c72L,0x6530253219e9d2L,0x7650c98b601c57L,
        0x182469f99d56c0L,0x415f65d292b7a7L,0x30f62a55549b8eL,
        0x30f443f643f465L },
      { 0x6b35c575ddadd0L,0x14a23cf6d299eeL,0x2f0198c0967d7dL,
        0x1013058178d5bfL,0x39da601c9cc879L,0x09d8963ec340baL,
        0x1b735db13ad2a7L } },
    /* 193 */
    { { 0x20916ffdc83f01L,0x16892aa7c9f217L,0x6bff179888d532L,
        0x4adf3c3d366288L,0x41a62b954726aeL,0x3139609022aeb6L,
        0x3e8ab9b37aff7aL },
      { 0x76bbc70f24659aL,0x33fa98513886c6L,0x13b26af62c4ea6L,
        0x3c4d5826389a0cL,0x526ec28c02bf6aL,0x751ff083d79a7cL,
        0x110ac647990224L } },
    /* 194 */
    { { 0x2c6c62fa2b6e20L,0x3d37edad30c299L,0x6ef25b44b65fcaL,
        0x7470846914558eL,0x712456eb913275L,0x075a967a9a280eL,
        0x186c8188f2a2a0L },
      { 0x2f3b41a6a560b1L,0x3a8070b3f9e858L,0x140936ff0e1e78L,
        0x5fd298abe6da8aL,0x3823a55d08f153L,0x3445eafaee7552L,
        0x2a5fc96731a8b2L } },
    /* 195 */
    { { 0x06317be58edbbbL,0x4a38f3bfbe2786L,0x445b60f75896b7L,
        0x6ec7c92b5adf57L,0x07b6be8038a441L,0x1bcfe002879655L,
        0x2a2174037d6d0eL },
      { 0x776790cf9e48bdL,0x73e14a2c4ed1d3L,0x7eb5ed5f2fc2f7L,
        0x3e0aedb821b384L,0x0ee3b7e151c12fL,0x51a6a29e044bb2L,
        0x0ba13a00cb0d86L } },
    /* 196 */
    { { 0x77607d563ec8d8L,0x023fc726996e44L,0x6bd63f577a9986L,
        0x114a6351e53973L,0x3efe97989da046L,0x1051166e117ed7L,
        0x0354933dd4fb5fL },
      { 0x7699ca2f30c073L,0x4c973b83b9e6d3L,0x2017c2abdbc3e8L,
        0x0cdcdd7a26522bL,0x511070f5b23c7dL,0x70672327e83d57L,
        0x278f842b4a9f26L } },
    /* 197 */
    { { 0x0824f0d4ae972fL,0x60578dd08dcf52L,0x48a74858290fbbL,
        0x7302748bf23030L,0x184b229a178acfL,0x3e8460ade089d6L,
        0x13f2b557fad533L },
      { 0x7f96f3ae728d15L,0x018d8d40066341L,0x01fb94955a289aL,
        0x2d32ed6afc2657L,0x23f4f5e462c3acL,0x60eba5703bfc5aL,
        0x1b91cc06f16c7aL } },
    /* 198 */
    { { 0x411d68af8219b9L,0x79cca36320f4eeL,0x5c404e0ed72e20L,
        0x417cb8692e43f2L,0x305d29c7d98599L,0x3b754d5794a230L,
        0x1c97fb4be404e9L },
      { 0x7cdbafababd109L,0x1ead0eb0ca5090L,0x1a2b56095303e3L,
        0x75dea935012c8fL,0x67e31c071b1d1dL,0x7c324fbfd172c3L,
        0x157e257e6498f7L } },
    /* 199 */
    { { 0x19b00db175645bL,0x4c4f6cb69725f1L,0x36d9ce67bd47ceL,
        0x2005e105179d64L,0x7b952e717867feL,0x3c28599204032cL,
        0x0f5659d44fb347L },
      { 0x1ebcdedb979775L,0x4378d45cfd11a8L,0x14c85413ca66e9L,
        0x3dd17d681c8a4dL,0x58368e7dc23142L,0x14f3eaac6116afL,
        0x0adb45b255f6a0L } },
    /* 200 */
    { { 0x2f5e76279ad982L,0x125b3917034d09L,0x3839a6399e6ed3L,
        0x32fe0b3ebcd6a2L,0x24ccce8be90482L,0x467e26befcc187L,
        0x2828434e2e218eL },
      { 0x17247cd386efd9L,0x27f36a468d85c3L,0x65e181ef203bbfL,
        0x0433a6761120afL,0x1d607a2a8f8625L,0x49f4e55a13d919L,
        0x3367c3b7943e9dL } },
    /* 201 */
    { { 0x3391c7d1a46d4dL,0x38233d602d260cL,0x02127a0f78b7d4L,
        0x56841c162c24c0L,0x4273648fd09aa8L,0x019480bb0e754eL,
        0x3b927987b87e58L },
      { 0x6676be48c76f73L,0x01ec024e9655aeL,0x720fe1c6376704L,
        0x17e06b98885db3L,0x656adec85a4200L,0x73780893c3ce88L,
        0x0a339cdd8df664L } },
    /* 202 */
    { { 0x69af7244544ac7L,0x31ab7402084d2fL,0x67eceb7ef7cb19L,
        0x16f8583b996f61L,0x1e208d12faf91aL,0x4a91584ce4a42eL,
        0x3e08337216c93eL },
      { 0x7a6eea94f4cf77L,0x07a52894678c60L,0x302dd06b14631eL,
        0x7fddb7225c9ceaL,0x55e441d7acd153L,0x2a00d4490b0f44L,
        0x053ef125338cdbL } },
    /* 203 */
    { { 0x120c0c51584e3cL,0x78b3efca804f37L,0x662108aefb1dccL,
        0x11deb55f126709L,0x66def11ada8125L,0x05bbc0d1001711L,
        0x1ee1c99c7fa316L },
      { 0x746f287de53510L,0x1733ef2e32d09cL,0x1df64a2b0924beL,
        0x19758da8f6405eL,0x28f6eb3913e484L,0x7175a1090cc640L,
        0x048aee0d63f0bcL } },
    /* 204 */
    { { 0x1f3b1e3b0b29c3L,0x48649f4882a215L,0x485eca3a9e0dedL,
        0x4228ba85cc82e4L,0x36da1f39bc9379L,0x1659a7078499d1L,
        0x0a67d5f6c04188L },
      { 0x6ac39658afdce3L,0x0d667a0bde8ef6L,0x0ae6ec0bfe8548L,
        0x6d9cb2650571bfL,0x54bea107760ab9L,0x705c53bd340cf2L,
        0x111a86b610c70fL } },
    /* 205 */
    { { 0x7ecea05c6b8195L,0x4f8be93ce3738dL,0x305de9eb9f5d12L,
        0x2c3b9d3d474b56L,0x673691a05746c3L,0x2e3482c428c6eaL,
        0x2a8085fde1f472L },
      { 0x69d15877fd3226L,0x4609c9ec017cc3L,0x71e9b7fc1c3dbcL,
        0x4f8951254e2675L,0x63ee9d15afa010L,0x0f05775b645190L,
        0x28a0a439397ae3L } },
    /* 206 */
    { { 0x387fa03e9de330L,0x40cc32b828b6abL,0x02a482fbc04ac9L,
        0x68cad6e70429b7L,0x741877bff6f2c4L,0x48efe633d3b28bL,
        0x3e612218fe24b3L },
      { 0x6fc1d34fe37657L,0x3d04b9e1c8b5a1L,0x6a2c332ef8f163L,
        0x7ca97e2b135690L,0x37357d2a31208aL,0x29f02f2332bd68L,
        0x17c674c3e63a57L } },
    /* 207 */
    { { 0x683d9a0e6865bbL,0x5e77ec68ad4ce5L,0x4d18f236788bd6L,
        0x7f34b87204f4e3L,0x391ca40e9e578dL,0x3470ed6ddf4e23L,
        0x225544b3e50989L },
      { 0x48eda8cb4e462bL,0x2a948825cf9109L,0x473adedc7e1300L,
        0x37b843b82192edL,0x2b9ac1537dde36L,0x4efe7412732332L,
        0x29cc5981b5262bL } },
    /* 208 */
    { { 0x190d2fcad260f5L,0x7c53dd81d18027L,0x003def5f55db0eL,
        0x7f5ed25bee2df7L,0x2b87e9be167d2eL,0x2b999c7bbcd224L,
        0x1d68a2c260ad50L },
      { 0x010bcde84607a6L,0x0250de9b7e1bedL,0x746d36bfaf1b56L,
        0x3359475ff56abbL,0x7e84b9bc440b20L,0x2eaa7e3b52f162L,
        0x01165412f36a69L } },
    /* 209 */
    { { 0x639a02329e5836L,0x7aa3ee2e4d3a27L,0x5bc9b258ecb279L,
        0x4cb3dfae2d62c6L,0x08d9d3b0c6c437L,0x5a2c177d47eab2L,
        0x36120479fc1f26L },
      { 0x7609a75bd20e4aL,0x3ba414e17551fcL,0x42cd800e1b90c9L,
        0x04921811b88f9bL,0x4443697f9562fdL,0x3a8081b8186959L,
        0x3f5b5c97379e73L } },
    /* 210 */
    { { 0x6fd0e3cf13eafbL,0x3976b5415cbf67L,0x4de40889e48402L,
        0x17e4d36f24062aL,0x16ae7755cf334bL,0x2730ac94b7e0e1L,
        0x377592742f48e0L },
      { 0x5e10b18a045041L,0x682792afaae5a1L,0x19383ec971b816L,
        0x208b17dae2ffc0L,0x439f9d933179b6L,0x55485a9090bcaeL,
        0x1c316f42a2a35cL } },
    /* 211 */
    { { 0x67173897bdf646L,0x0b6956653ef94eL,0x5be3c97f7ea852L,
        0x3110c12671f08eL,0x2474076a3fc7ecL,0x53408be503fe72L,
        0x09155f53a5b44eL },
      { 0x5c804bdd4c27cdL,0x61e81eb8ffd50eL,0x2f7157fdf84717L,
        0x081f880d646440L,0x7aa892acddec51L,0x6ae70683443f33L,
        0x31ed9e8b33a75aL } },
    /* 212 */
    { { 0x0d724f8e357586L,0x1febbec91b4134L,0x6ff7b98a9475fdL,
        0x1c4d9b94e1f364L,0x2b8790499cef00L,0x42fd2080a1b31dL,
        0x3a3bbc6d9b0145L },
      { 0x75bfebc37e3ca9L,0x28db49c1723bd7L,0x50b12fa8a1f17aL,
        0x733d95bbc84b98L,0x45ede81f6c109eL,0x18f5e46fb37b5fL,
        0x34b980804aaec1L } },
    /* 213 */
    { { 0x56060c8a4f57bfL,0x0d2dfe223054c2L,0x718a5bbc03e5d6L,
        0x7b3344cc19b3b9L,0x4d11c9c054bcefL,0x1f5ad422c22e33L,
        0x2609299076f86bL },
      { 0x7b7a5fba89fd01L,0x7013113ef3b016L,0x23d5e0a173e34eL,
        0x736c14462f0f50L,0x1ef5f7ac74536aL,0x4baba6f4400ea4L,
        0x17b310612c9828L } },
    /* 214 */
    { { 0x4ebb19a708c8d3L,0x209f8c7f03d9bbL,0x00461cfe5798fbL,
        0x4f93b6ae822fadL,0x2e5b33b5ad5447L,0x40b024e547a84bL,
        0x22ffad40443385L },
      { 0x33809c888228bfL,0x559f655fefbe84L,0x0032f529fd2f60L,
        0x5a2191ece3478cL,0x5b957fcd771246L,0x6fec181f9ed123L,
        0x33eed3624136a3L } },
    /* 215 */
    { { 0x6a5df93b26139aL,0x55076598fd7134L,0x356a592f34f81dL,
        0x493c6b5a3d4741L,0x435498a4e2a39bL,0x2cd26a0d931c88L,
        0x01925ea3fc7835L },
      { 0x6e8d992b1efa05L,0x79508a727c667bL,0x5f3c15e6b4b698L,
        0x11b6c755257b93L,0x617f5af4b46393L,0x248d995b2b6656L,
        0x339db62e2e22ecL } },
    /* 216 */
    { { 0x52537a083843dcL,0x6a283c82a768c7L,0x13aa6bf25227acL,
        0x768d76ba8baf5eL,0x682977a6525808L,0x67ace52ac23b0bL,
        0x2374b5a2ed612dL },
      { 0x7139e60133c3a4L,0x715697a4f1d446L,0x4b018bf36677a0L,
        0x1dd43837414d83L,0x505ec70730d4f6L,0x09ac100907fa79L,
        0x21caad6e03217eL } },
    /* 217 */
    { { 0x0776d3999d4d49L,0x33bdd87e8bcff8L,0x1036b87f068fadL,
        0x0a9b8ffde4c872L,0x7ab2533596b1eaL,0x305a88fb965378L,
        0x3356d8fa4d65e5L },
      { 0x3366fa77d1ff11L,0x1e0bdbdcd2075cL,0x46910cefc967caL,
        0x7ce700737a1ff6L,0x1c5dc15409c9bdL,0x368436b9bdb595L,
        0x3e7ccd6560b5efL } },
    /* 218 */
    { { 0x1443789422c792L,0x524792b1717f2bL,0x1f7c1d95048e7aL,
        0x5cfe2a225b0d12L,0x245594d29ce85bL,0x20134d254ce168L,
        0x1b83296803921aL },
      { 0x79a78285b3beceL,0x3c738c3f3124d6L,0x6ab9d1fe0907cdL,
        0x0652ceb7fc104cL,0x06b5f58c8ae3fdL,0x486959261c5328L,
        0x0b3813ae677c90L } },
    /* 219 */
    { { 0x66b9941ac37b82L,0x651a4b609b0686L,0x046711edf3fc31L,
        0x77f89f38faa89bL,0x2683ddbf2d5edbL,0x389ef1dfaa3c25L,
        0x20b3616e66273eL },
      { 0x3c6db6e0cb5d37L,0x5d7ae5dc342bc4L,0x74a1dc6c52062bL,
        0x6f7c0bec109557L,0x5c51f7bc221d91L,0x0d7b5880745288L,
        0x1c46c145c4b0ddL } },
    /* 220 */
    { { 0x59ed485ea99eccL,0x201b71956bc21dL,0x72d5c32f73de65L,
        0x1aefd76547643eL,0x580a452cfb2c2dL,0x7cb1a63f5c4dc9L,
        0x39a8df727737aaL },
      { 0x365a341deca452L,0x714a1ad1689cbaL,0x16981d12c42697L,
        0x5a124f4ac91c75L,0x1b2e3f2fedc0dbL,0x4a1c72b8e9d521L,
        0x3855b4694e4e20L } },
    /* 221 */
    { { 0x16b3d047181ae9L,0x17508832f011afL,0x50d33cfeb2ebd1L,
        0x1deae237349984L,0x147c641aa6adecL,0x24a9fb4ebb1ddbL,
        0x2b367504a7a969L },
      { 0x4c55a3d430301bL,0x379ef6a5d492cbL,0x3c56541fc0f269L,
        0x73a546e91698ceL,0x2c2b62ee0b9b5dL,0x6284184d43d0efL,
        0x0e1f5cf6a4b9f0L } },
    /* 222 */
    { { 0x44833e8cd3fdacL,0x28e6665cb71c27L,0x2f8bf87f4ddbf3L,
        0x6cc6c767fb38daL,0x3bc114d734e8b5L,0x12963d5a78ca29L,
        0x34532a161ece41L },
      { 0x2443af5d2d37e9L,0x54e6008c8c452bL,0x2c55d54111cf1bL,
        0x55ac7f7522575aL,0x00a6fba3f8575fL,0x3f92ef3b793b8dL,
        0x387b97d69ecdf7L } },
    /* 223 */
    { { 0x0b464812d29f46L,0x36161daa626f9aL,0x5202fbdb264ca5L,
        0x21245805ff1304L,0x7f9c4a65657885L,0x542d3887f9501cL,
        0x086420deef8507L },
      { 0x5e159aa1b26cfbL,0x3f0ef5ffd0a50eL,0x364b29663a432aL,
        0x49c56888af32a8L,0x6f937e3e0945d1L,0x3cbdeec6d766cdL,
        0x2d80d342ece61aL } },
    /* 224 */
    { { 0x255e3026d8356eL,0x4ddba628c4de9aL,0x074323b593e0d9L,
        0x333bdb0a10eefbL,0x318b396e473c52L,0x6ebb5a95efd3d3L,
        0x3f3bff52aa4e4fL },
      { 0x3138a111c731d5L,0x674365e283b308L,0x5585edd9c416f2L,
        0x466763d9070fd4L,0x1b568befce8128L,0x16eb040e7b921eL,
        0x3d5c898687c157L } },
    /* 225 */
    { { 0x14827736973088L,0x4e110d53f301e6L,0x1f811b09870023L,
        0x53b5e500dbcacaL,0x4ddf0df1e6a7dcL,0x1e9575fb10ce35L,
        0x3fdc153644d936L },
      { 0x763547e2260594L,0x26e5ae764efc59L,0x13be6f4d791a29L,
        0x2021e61e3a0cf1L,0x339cd2b4a1c202L,0x5c7451e08f5121L,
        0x3728b3a851be68L } },
    /* 226 */
    { { 0x78873653277538L,0x444b9ed2ee7156L,0x79ac8b8b069cd3L,
        0x5f0e90933770e8L,0x307662c615389eL,0x40fe6d95a80057L,
        0x04822170cf993cL },
      { 0x677d5690fbfec2L,0x0355af4ae95cb3L,0x417411794fe79eL,
        0x48daf87400a085L,0x33521d3b5f0aaaL,0x53567a3be00ff7L,
        0x04712ccfb1cafbL } },
    /* 227 */
    { { 0x2b983283c3a7f3L,0x579f11b146a9a6L,0x1143d3b16a020eL,
        0x20f1483ef58b20L,0x3f03e18d747f06L,0x3129d12f15de37L,
        0x24c911f7222833L },
      { 0x1e0febcf3d5897L,0x505e26c01cdaacL,0x4f45a9adcff0e9L,
        0x14dfac063c5cebL,0x69e5ce713fededL,0x3481444a44611aL,
        0x0ea49295c7fdffL } },
    /* 228 */
    { { 0x64554cb4093beeL,0x344b4b18dd81f6L,0x350f43b4de9b59L,
        0x28a96a220934caL,0x4aa8da5689a515L,0x27171cbd518509L,
        0x0cfc1753f47c95L },
      { 0x7dfe091b615d6eL,0x7d1ee0aa0fb5c1L,0x145eef3200b7b5L,
        0x33fe88feeab18fL,0x1d62d4f87453e2L,0x43b8db4e47fff1L,
        0x1572f2b8b8f368L } },
    /* 229 */
    { { 0x6bc94e6b4e84f3L,0x60629dee586a66L,0x3bbad5fe65ca18L,
        0x217670db6c2fefL,0x0320a7f4e3272aL,0x3ccff0d976a6deL,
        0x3c26da8ae48cccL },
      { 0x53ecf156778435L,0x7533064765a443L,0x6c5c12f03ca5deL,
        0x44f8245350dabfL,0x342cdd777cf8b3L,0x2b539c42e9f58dL,
        0x10138affc279b1L } },
    /* 230 */
    { { 0x1b135e204c5ddbL,0x40887dfeaa1d37L,0x7fb0ef83da76ffL,
        0x521f2b79af55a5L,0x3f9b38b4c3f0d0L,0x20a9838cce61ceL,
        0x24bb4e2f4b1e32L },
      { 0x003f6aa386e27cL,0x68df59db0a0f8eL,0x21677d5192e713L,
        0x14ab9757501276L,0x411944af961524L,0x3184f39abc5c3fL,
        0x2a8dda80ca078dL } },
    /* 231 */
    { { 0x0592233cdbc95cL,0x54d5de5c66f40fL,0x351caa1512ab86L,
        0x681bdbee020084L,0x6ee2480c853e68L,0x6a5a44262b918fL,
        0x06574e15a3b91dL },
      { 0x31ba03dacd7fbeL,0x0c3da7c18a57a9L,0x49aaaded492d6bL,
        0x3071ff53469e02L,0x5efb4f0d7248c6L,0x6db5fb67f12628L,
        0x29cff668e3d024L } },
    /* 232 */
    { { 0x1b9ef3bb1b17ceL,0x6ccf8c24fe6312L,0x34c15487f45008L,
        0x1a84044095972cL,0x515073a47e449eL,0x2ddc93f9097feeL,
        0x1008fdc894c434L },
      { 0x08e5edb73399faL,0x65b1aa65547d4cL,0x3a117a1057c498L,
        0x7e16c3089d13acL,0x502f2ae4b6f851L,0x57a70f3eb62673L,
        0x111b48a9a03667L } },
    /* 233 */
    { { 0x5023024be164f1L,0x25ad117032401eL,0x46612b3bfe3427L,
        0x2f4f406a8a02b7L,0x16a93a5c4ddf07L,0x7ee71968fcdbe9L,
        0x2267875ace37daL },
      { 0x687e88b59eb2a6L,0x3ac7368fe716d3L,0x28d953a554a036L,
        0x34d52c0acca08fL,0x742a7cf8dd4fd9L,0x10bfeb8575ea60L,
        0x290e454d868dccL } },
    /* 234 */
    { { 0x4e72a3a8a4bdd2L,0x1ba36d1dee04d5L,0x7a43136b63195bL,
        0x6ca8e286a519f3L,0x568e64aece08a9L,0x571d5000b5c10bL,
        0x3f75e9f5dbdd40L },
      { 0x6fb0a698d6fa45L,0x0ce42209d7199cL,0x1f68275f708a3eL,
        0x5749832e91ec3cL,0x6c3665521428b2L,0x14b2bf5747bd4aL,
        0x3b6f940e42a22bL } },
    /* 235 */
    { { 0x4da0adbfb26c82L,0x16792a585f39acL,0x17df9dfda3975cL,
        0x4796b4afaf479bL,0x67be67234e0020L,0x69df5f201dda25L,
        0x09f71a4d12b3dcL },
      { 0x64ff5ec260a46aL,0x579c5b86385101L,0x4f29a7d549f697L,
        0x4e64261242e2ebL,0x54ecacdfb6b296L,0x46e0638b5fddadL,
        0x31eefd3208891dL } },
    /* 236 */
    { { 0x5b72c749fe01b2L,0x230cf27523713aL,0x533d1810e0d1e1L,
        0x5590db7d1dd1e2L,0x7b8ab73e8e43d3L,0x4c8a19bd1c17caL,
        0x19222ce9f74810L },
      { 0x6398b3dddc4582L,0x0352b7d88dfd53L,0x3c55b4e10c5a63L,
        0x38194d13f8a237L,0x106683fd25dd87L,0x59e0b62443458eL,
        0x196cb70aa9cbb9L } },
    /* 237 */
    { { 0x2885f7cd021d63L,0x162bfd4c3e1043L,0x77173dcf98fcd1L,
        0x13d4591d6add36L,0x59311154d0d8f2L,0x74336e86e79b8aL,
        0x13faadc5661883L },
      { 0x18938e7d9ec924L,0x14bcda8fcaa0a1L,0x706d85d41a1355L,
        0x0ac34520d168deL,0x5a92499fe17826L,0x36c2e3b4f00600L,
        0x29c2fd7b5f63deL } },
    /* 238 */
    { { 0x41250dfe2216c5L,0x44a0ec0366a217L,0x575bc1adf8b0dfL,
        0x5ff5cdbdb1800bL,0x7843d4dde8ca18L,0x5fa9e420865705L,
        0x235c38be6c6b02L },
      { 0x473b78aae91abbL,0x39470c6051e44bL,0x3f973cc2dc08c3L,
        0x2837932c5c91f6L,0x25e39ed754ec25L,0x1371c837118e53L,
        0x3b99f3b0aeafe2L } },
    /* 239 */
    { { 0x03acf51be46c65L,0x271fceacbaf5c3L,0x476589ed3a5e25L,
        0x78ec8c3c3c399cL,0x1f5c8bf4ac4c19L,0x730bb733ec68d2L,
        0x29a37e00dd287eL },
      { 0x448ed1bf92b5faL,0x10827c17b86478L,0x55e6fc05b28263L,
        0x0af1226c73a66aL,0x0b66e5df0d09c1L,0x26128315a02682L,
        0x22d84932c5e808L } },
    /* 240 */
    { { 0x5ec3afc26e3392L,0x08e142e45c0084L,0x4388d5ad0f01feL,
        0x0f7acd36e6140cL,0x028c14ed97dffbL,0x311845675a38c6L,
        0x01c1c8f09a3062L },
      { 0x5a302f4cf49e7dL,0x79267e254a44e1L,0x746165052317a1L,
        0x53a09263a566e8L,0x7d478ad5f73abcL,0x187ce5c947dad3L,
        0x18564e1a1ec45fL } },
    /* 241 */
    { { 0x7b9577a9aa0486L,0x766b40c7aaaef6L,0x1f6a411f5db907L,
        0x4543dd4d80beaeL,0x0ad938c7482806L,0x451568bf4b9be1L,
        0x3367ec85d30a22L },
      { 0x5446425747843dL,0x18d94ac223c6b2L,0x052ff3a354d359L,
        0x0b4933f89723f5L,0x03fb517740e056L,0x226b892871dddaL,
        0x2768c2b753f0fdL } },
    /* 242 */
    { { 0x685282ccfa5200L,0x411ed433627b89L,0x77d5c9b8bc9c1dL,
        0x4a13ef2ee5cd29L,0x5582a612407c9eL,0x2307cb42fc3aa9L,
        0x2e661df79956b8L },
      { 0x0e972b015254deL,0x5b63e14def8adeL,0x06995be2ca4a95L,
        0x6cc0cc1e94bf27L,0x7ed8499fe0052aL,0x671a6ca5a5e0f9L,
        0x31e10d4ba10f05L } },
    /* 243 */
    { { 0x690af07e9b2d8aL,0x6030af9e32c8ddL,0x45c7ca3bf2b235L,
        0x40959077b76c81L,0x61eee7f70d5a96L,0x6b04f6aafe9e38L,
        0x3c726f55f1898dL },
      { 0x77d0142a1a6194L,0x1c1631215708b9L,0x403a4f0a9b7585L,
        0x066c8e29f7cef0L,0x6fc32f98cf575eL,0x518a09d818c297L,
        0x34144e99989e75L } },
    /* 244 */
    { { 0x6adbada859fb6aL,0x0dcfb6506ccd51L,0x68f88b8d573e0dL,
        0x4b1ce35bd9af30L,0x241c8293ece2c9L,0x3b5f402c5c4adeL,
        0x34b9b1ee6fde87L },
      { 0x5e625340075e63L,0x54c3f3d9050da1L,0x2a3f9152509016L,
        0x3274e46111bc18L,0x3a7504fd01ac73L,0x4169b387a43209L,
        0x35626f852bc6d4L } },
    /* 245 */
    { { 0x576a4f4662e53bL,0x5ea3f20eecec26L,0x4e5f02be5cd7b0L,
        0x72cc5ac3314be8L,0x0f604ed3201fe9L,0x2a29378ea54bceL,
        0x2d52bd4d6ec4b6L },
      { 0x6a4c2b212c1c76L,0x778fd64a1bfa6dL,0x326828691863d6L,
        0x5616c8bd06a336L,0x5fab552564da4dL,0x46640cab3e91d2L,
        0x1d21f06427299eL } },
    /* 246 */
    { { 0x2bfe37dde98e9cL,0x164c54822332ebL,0x5b736c7df266e4L,
        0x59dab3a8da084cL,0x0ae1eab346f118L,0x182090a4327e3fL,
        0x07b13489dae2e6L },
      { 0x3bc92645452baaL,0x30b159894ae574L,0x5b947c5c78e1f4L,
        0x18f0e004a3c77fL,0x48ca8f357077d9L,0x349ffdcef9bca9L,
        0x3ed224bfd54772L } },
    /* 247 */
    { { 0x1bdad02db8dff8L,0x69fab4450b44b6L,0x3b6802d187518bL,
        0x098368d8eb556cL,0x3fe1943fbefcf4L,0x008851d0de6d42L,
        0x322cbc4605fe25L },
      { 0x2528aaf0d51afbL,0x7d48a9363a0cecL,0x4ba8f77d9a8f8bL,
        0x7dee903437d6c7L,0x1ff5a0d9ccc4b4L,0x34d9bd2fa99831L,
        0x30d9e4f58667c6L } },
    /* 248 */
    { { 0x38909b51b85197L,0x7ba16992512bd4L,0x2c776cfcfffec5L,
        0x2be7879075843cL,0x557e2b05d28ffcL,0x641b17bc5ce357L,
        0x1fcaf8a3710306L },
      { 0x54dca2299a2d48L,0x745d06ef305acaL,0x7c41c65c6944c2L,
        0x679412ec431902L,0x48f2b15ee62827L,0x341a96d8afe06eL,
        0x2a78fd3690c0e1L } },
    /* 249 */
    { { 0x6b7cec83fbc9c6L,0x238e8a82eefc67L,0x5d3c1d9ff0928cL,
        0x55b816d6409bbfL,0x7969612adae364L,0x55b6ff96db654eL,
        0x129beca10073a9L },
      { 0x0b1d2acdfc73deL,0x5d1a3605fa64bdL,0x436076146743beL,
        0x64044b89fcce0cL,0x7ae7b3c18f7fafL,0x7f083ee27cea36L,
        0x0292cd0d7c1ff0L } },
    /* 250 */
    { { 0x5a3c4c019b7d2eL,0x1a35a9b89712fbL,0x38736cc4f18c72L,
        0x603dd832a44e6bL,0x000d1d44aed104L,0x69b1f2fc274ebeL,
        0x03a7b993f76977L },
      { 0x299f3b3e346910L,0x5243f45295afd5L,0x34342cbfa588bdL,
        0x72c40dd1155510L,0x718024fed2f991L,0x2f935e765ad82aL,
        0x246799ea371fb8L } },
    /* 251 */
    { { 0x24fe4c76250533L,0x01cafb02fdf18eL,0x505cb25d462882L,
        0x3e038175157d87L,0x7e3e99b10cdeb1L,0x38b7e72ebc7936L,
        0x081845f7c73433L },
      { 0x049e61be05ebd5L,0x6ab82d8f0581f6L,0x62adffb427ac2eL,
        0x19431f809d198dL,0x36195f6c58b1d6L,0x22cc4c9dedc9a7L,
        0x24b146d8e694fcL } },
    /* 252 */
    { { 0x7c7bc8288b364dL,0x5c10f683cb894aL,0x19a62a68452958L,
        0x1fc24dcb4ce90eL,0x726baa4ed9581fL,0x1f34447dde73d6L,
        0x04c56708f30a21L },
      { 0x131e583a3f4963L,0x071215b4d502e7L,0x196aca542e5940L,
        0x3afd5a91f7450eL,0x671b6eedf49497L,0x6aac7aca5c29e4L,
        0x3fb512470f138bL } },
    /* 253 */
    { { 0x5eadc3f4eb453eL,0x16c795ba34b666L,0x5d7612a4697fddL,
        0x24dd19bb499e86L,0x415b89ca3eeb9bL,0x7c83edf599d809L,
        0x13bc64c9b70269L },
      { 0x52d3243dca3233L,0x0b21444b3a96a7L,0x6d551bc0083b90L,
        0x4f535b88c61176L,0x11e61924298010L,0x0a155b415bb61dL,
        0x17f94fbd26658fL } },
    /* 254 */
    { { 0x2dd06b90c28c65L,0x48582339c8fa6eL,0x01ac8bf2085d94L,
        0x053e660e020fdcL,0x1bece667edf07bL,0x4558f2b33ce24cL,
        0x2f1a766e8673fcL },
      { 0x1d77cd13c06819L,0x4d5dc5056f3a01L,0x18896c6fa18d69L,
        0x120047ca76d625L,0x6af8457d4f4e45L,0x70ddc53358b60aL,
        0x330e11130e82f0L } },
    /* 255 */
    { { 0x0643b1cd4c2356L,0x10a2ea0a8f7c92L,0x2752513011d029L,
        0x4cd4c50321f579L,0x5fdf9ba5724792L,0x2f691653e2ddc0L,
        0x0cfed3d84226cbL },
      { 0x704902a950f955L,0x069bfdb87bbf0cL,0x5817eeda8a5f84L,
        0x1914cdd9089905L,0x0e4a323d7b93f4L,0x1cc3fc340af0b2L,
        0x23874161bd6303L } },
};

/* Multiply the base point of P384 by the scalar and return the result.
 * If map is true then convert result to affine coordinates.
 *
 * r     Resulting point.
 * k     Scalar to multiply by.
 * map   Indicates whether to convert result to affine.
 * ct    Constant time required.
 * heap  Heap to use for allocation.
 * returns MEMORY_E when memory allocation fails and MP_OKAY on success.
 */
static int sp_384_ecc_mulmod_base_7(sp_point_384* r, const sp_digit* k,
        int map, int ct, void* heap)
{
    return sp_384_ecc_mulmod_stripe_7(r, &p384_base, p384_table,
                                      k, map, ct, heap);
}

#endif

/* Multiply the base point of P384 by the scalar and return the result.
 * If map is true then convert result to affine coordinates.
 *
 * km    Scalar to multiply by.
 * r     Resulting point.
 * map   Indicates whether to convert result to affine.
 * heap  Heap to use for allocation.
 * returns MEMORY_E when memory allocation fails and MP_OKAY on success.
 */
int sp_ecc_mulmod_base_384(mp_int* km, ecc_point* r, int map, void* heap)
{
#if (!defined(WOLFSSL_SP_SMALL) && !defined(WOLFSSL_SMALL_STACK)) || defined(WOLFSSL_SP_NO_MALLOC)
    sp_point_384 p;
    sp_digit kd[7];
#endif
    sp_point_384* point;
    sp_digit* k = NULL;
    int err = MP_OKAY;

    err = sp_384_point_new_7(heap, p, point);
#if (defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)) && !defined(WOLFSSL_SP_NO_MALLOC)
    if (err == MP_OKAY) {
        k = (sp_digit*)XMALLOC(sizeof(sp_digit) * 7, heap,
                                                              DYNAMIC_TYPE_ECC);
        if (k == NULL) {
            err = MEMORY_E;
        }
    }
#else
    k = kd;
#endif
    if (err == MP_OKAY) {
        sp_384_from_mp(k, 7, km);

            err = sp_384_ecc_mulmod_base_7(point, k, map, 1, heap);
    }
    if (err == MP_OKAY) {
        err = sp_384_point_to_ecc_point_7(point, r);
    }

#if (defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)) && !defined(WOLFSSL_SP_NO_MALLOC)
    if (k != NULL) {
        XFREE(k, heap, DYNAMIC_TYPE_ECC);
    }
#endif
    sp_384_point_free_7(point, 0, heap);

    return err;
}

#if defined(WOLFSSL_VALIDATE_ECC_KEYGEN) || defined(HAVE_ECC_SIGN) || \
                                                        defined(HAVE_ECC_VERIFY)
/* Returns 1 if the number of zero.
 * Implementation is constant time.
 *
 * a  Number to check.
 * returns 1 if the number is zero and 0 otherwise.
 */
static int sp_384_iszero_7(const sp_digit* a)
{
    return (a[0] | a[1] | a[2] | a[3] | a[4] | a[5] | a[6]) == 0;
}

#endif /* WOLFSSL_VALIDATE_ECC_KEYGEN || HAVE_ECC_SIGN || HAVE_ECC_VERIFY */
/* Add 1 to a. (a = a + 1)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 */
SP_NOINLINE static void sp_384_add_one_7(sp_digit* a)
{
    a[0]++;
    sp_384_norm_7(a);
}

/* Read big endian unsigned byte array into r.
 *
 * r  A single precision integer.
 * size  Maximum number of bytes to convert
 * a  Byte array.
 * n  Number of bytes in array to read.
 */
static void sp_384_from_bin(sp_digit* r, int size, const byte* a, int n)
{
    int i, j = 0;
    word32 s = 0;

    r[0] = 0;
    for (i = n-1; i >= 0; i--) {
        r[j] |= (((sp_digit)a[i]) << s);
        if (s >= 47U) {
            r[j] &= 0x7fffffffffffffL;
            s = 55U - s;
            if (j + 1 >= size) {
                break;
            }
            r[++j] = (sp_digit)a[i] >> s;
            s = 8U - s;
        }
        else {
            s += 8U;
        }
    }

    for (j++; j < size; j++) {
        r[j] = 0;
    }
}

/* Generates a scalar that is in the range 1..order-1.
 *
 * rng  Random number generator.
 * k    Scalar value.
 * returns RNG failures, MEMORY_E when memory allocation fails and
 * MP_OKAY on success.
 */
static int sp_384_ecc_gen_k_7(WC_RNG* rng, sp_digit* k)
{
    int err;
    byte buf[48];

    do {
        err = wc_RNG_GenerateBlock(rng, buf, sizeof(buf));
        if (err == 0) {
            sp_384_from_bin(k, 7, buf, (int)sizeof(buf));
            if (sp_384_cmp_7(k, p384_order2) < 0) {
                sp_384_add_one_7(k);
                break;
            }
        }
    }
    while (err == 0);

    return err;
}

/* Makes a random EC key pair.
 *
 * rng   Random number generator.
 * priv  Generated private value.
 * pub   Generated public point.
 * heap  Heap to use for allocation.
 * returns ECC_INF_E when the point does not have the correct order, RNG
 * failures, MEMORY_E when memory allocation fails and MP_OKAY on success.
 */
int sp_ecc_make_key_384(WC_RNG* rng, mp_int* priv, ecc_point* pub, void* heap)
{
#if (!defined(WOLFSSL_SP_SMALL) && !defined(WOLFSSL_SMALL_STACK)) || defined(WOLFSSL_SP_NO_MALLOC)
    sp_point_384 p;
    sp_digit kd[7];
#ifdef WOLFSSL_VALIDATE_ECC_KEYGEN
    sp_point_384 inf;
#endif
#endif
    sp_point_384* point;
    sp_digit* k = NULL;
#ifdef WOLFSSL_VALIDATE_ECC_KEYGEN
    sp_point_384* infinity = NULL;
#endif
    int err;

    (void)heap;

    err = sp_384_point_new_7(heap, p, point);
#ifdef WOLFSSL_VALIDATE_ECC_KEYGEN
    if (err == MP_OKAY) {
        err = sp_384_point_new_7(heap, inf, infinity);
    }
#endif
#if (defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)) && !defined(WOLFSSL_SP_NO_MALLOC)
    if (err == MP_OKAY) {
        k = (sp_digit*)XMALLOC(sizeof(sp_digit) * 7, heap,
                                                              DYNAMIC_TYPE_ECC);
        if (k == NULL) {
            err = MEMORY_E;
        }
    }
#else
    k = kd;
#endif

    if (err == MP_OKAY) {
        err = sp_384_ecc_gen_k_7(rng, k);
    }
    if (err == MP_OKAY) {
            err = sp_384_ecc_mulmod_base_7(point, k, 1, 1, NULL);
    }

#ifdef WOLFSSL_VALIDATE_ECC_KEYGEN
    if (err == MP_OKAY) {
            err = sp_384_ecc_mulmod_7(infinity, point, p384_order, 1, 1, NULL);
    }
    if (err == MP_OKAY) {
        if (sp_384_iszero_7(point->x) || sp_384_iszero_7(point->y)) {
            err = ECC_INF_E;
        }
    }
#endif

    if (err == MP_OKAY) {
        err = sp_384_to_mp(k, priv);
    }
    if (err == MP_OKAY) {
        err = sp_384_point_to_ecc_point_7(point, pub);
    }

#if (defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)) && !defined(WOLFSSL_SP_NO_MALLOC)
    if (k != NULL) {
        XFREE(k, heap, DYNAMIC_TYPE_ECC);
    }
#endif
#ifdef WOLFSSL_VALIDATE_ECC_KEYGEN
    sp_384_point_free_7(infinity, 1, heap);
#endif
    sp_384_point_free_7(point, 1, heap);

    return err;
}

#ifdef HAVE_ECC_DHE
/* Write r as big endian to byte array.
 * Fixed length number of bytes written: 48
 *
 * r  A single precision integer.
 * a  Byte array.
 */
static void sp_384_to_bin(sp_digit* r, byte* a)
{
    int i, j, s = 0, b;

    for (i=0; i<6; i++) {
        r[i+1] += r[i] >> 55;
        r[i] &= 0x7fffffffffffffL;
    }
    j = 384 / 8 - 1;
    a[j] = 0;
    for (i=0; i<7 && j>=0; i++) {
        b = 0;
        /* lint allow cast of mismatch sp_digit and int */
        a[j--] |= (byte)(r[i] << s); /*lint !e9033*/
        b += 8 - s;
        if (j < 0) {
            break;
        }
        while (b < 55) {
            a[j--] = (byte)(r[i] >> b);
            b += 8;
            if (j < 0) {
                break;
            }
        }
        s = 8 - (b - 55);
        if (j >= 0) {
            a[j] = 0;
        }
        if (s != 0) {
            j++;
        }
    }
}

/* Multiply the point by the scalar and serialize the X ordinate.
 * The number is 0 padded to maximum size on output.
 *
 * priv    Scalar to multiply the point by.
 * pub     Point to multiply.
 * out     Buffer to hold X ordinate.
 * outLen  On entry, size of the buffer in bytes.
 *         On exit, length of data in buffer in bytes.
 * heap    Heap to use for allocation.
 * returns BUFFER_E if the buffer is to small for output size,
 * MEMORY_E when memory allocation fails and MP_OKAY on success.
 */
int sp_ecc_secret_gen_384(mp_int* priv, ecc_point* pub, byte* out,
                          word32* outLen, void* heap)
{
#if (!defined(WOLFSSL_SP_SMALL) && !defined(WOLFSSL_SMALL_STACK)) || defined(WOLFSSL_SP_NO_MALLOC)
    sp_point_384 p;
    sp_digit kd[7];
#endif
    sp_point_384* point = NULL;
    sp_digit* k = NULL;
    int err = MP_OKAY;

    if (*outLen < 48U) {
        err = BUFFER_E;
    }

    if (err == MP_OKAY) {
        err = sp_384_point_new_7(heap, p, point);
    }
#if (defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)) && !defined(WOLFSSL_SP_NO_MALLOC)
    if (err == MP_OKAY) {
        k = (sp_digit*)XMALLOC(sizeof(sp_digit) * 7, heap,
                                                              DYNAMIC_TYPE_ECC);
        if (k == NULL)
            err = MEMORY_E;
    }
#else
    k = kd;
#endif

    if (err == MP_OKAY) {
        sp_384_from_mp(k, 7, priv);
        sp_384_point_from_ecc_point_7(point, pub);
            err = sp_384_ecc_mulmod_7(point, point, k, 1, 1, heap);
    }
    if (err == MP_OKAY) {
        sp_384_to_bin(point->x, out);
        *outLen = 48;
    }

#if (defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)) && !defined(WOLFSSL_SP_NO_MALLOC)
    if (k != NULL) {
        XFREE(k, heap, DYNAMIC_TYPE_ECC);
    }
#endif
    sp_384_point_free_7(point, 0, heap);

    return err;
}
#endif /* HAVE_ECC_DHE */

#if defined(HAVE_ECC_SIGN) || defined(HAVE_ECC_VERIFY)
#endif
#if defined(HAVE_ECC_SIGN) || defined(HAVE_ECC_VERIFY)
/* Multiply a by scalar b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A scalar.
 */
SP_NOINLINE static void sp_384_mul_d_7(sp_digit* r, const sp_digit* a,
    sp_digit b)
{
#ifdef WOLFSSL_SP_SMALL
    int128_t tb = b;
    int128_t t = 0;
    int i;

    for (i = 0; i < 7; i++) {
        t += tb * a[i];
        r[i] = (sp_digit)(t & 0x7fffffffffffffL);
        t >>= 55;
    }
    r[7] = (sp_digit)t;
#else
    int128_t tb = b;
    int128_t t[7];

    t[ 0] = tb * a[ 0];
    t[ 1] = tb * a[ 1];
    t[ 2] = tb * a[ 2];
    t[ 3] = tb * a[ 3];
    t[ 4] = tb * a[ 4];
    t[ 5] = tb * a[ 5];
    t[ 6] = tb * a[ 6];
    r[ 0] = (sp_digit)                 (t[ 0] & 0x7fffffffffffffL);
    r[ 1] = (sp_digit)((t[ 0] >> 55) + (t[ 1] & 0x7fffffffffffffL));
    r[ 2] = (sp_digit)((t[ 1] >> 55) + (t[ 2] & 0x7fffffffffffffL));
    r[ 3] = (sp_digit)((t[ 2] >> 55) + (t[ 3] & 0x7fffffffffffffL));
    r[ 4] = (sp_digit)((t[ 3] >> 55) + (t[ 4] & 0x7fffffffffffffL));
    r[ 5] = (sp_digit)((t[ 4] >> 55) + (t[ 5] & 0x7fffffffffffffL));
    r[ 6] = (sp_digit)((t[ 5] >> 55) + (t[ 6] & 0x7fffffffffffffL));
    r[ 7] = (sp_digit) (t[ 6] >> 55);
#endif /* WOLFSSL_SP_SMALL */
}

#ifdef WOLFSSL_SP_DIV_64
static WC_INLINE sp_digit sp_384_div_word_7(sp_digit d1, sp_digit d0,
    sp_digit dv)
{
    sp_digit d, r, t;

    /* All 55 bits from d1 and top 8 bits from d0. */
    d = (d1 << 8) | (d0 >> 47);
    r = d / dv;
    d -= r * dv;
    /* Up to 9 bits in r */
    /* Next 8 bits from d0. */
    r <<= 8;
    d <<= 8;
    d |= (d0 >> 39) & ((1 << 8) - 1);
    t = d / dv;
    d -= t * dv;
    r += t;
    /* Up to 17 bits in r */
    /* Next 8 bits from d0. */
    r <<= 8;
    d <<= 8;
    d |= (d0 >> 31) & ((1 << 8) - 1);
    t = d / dv;
    d -= t * dv;
    r += t;
    /* Up to 25 bits in r */
    /* Next 8 bits from d0. */
    r <<= 8;
    d <<= 8;
    d |= (d0 >> 23) & ((1 << 8) - 1);
    t = d / dv;
    d -= t * dv;
    r += t;
    /* Up to 33 bits in r */
    /* Next 8 bits from d0. */
    r <<= 8;
    d <<= 8;
    d |= (d0 >> 15) & ((1 << 8) - 1);
    t = d / dv;
    d -= t * dv;
    r += t;
    /* Up to 41 bits in r */
    /* Next 8 bits from d0. */
    r <<= 8;
    d <<= 8;
    d |= (d0 >> 7) & ((1 << 8) - 1);
    t = d / dv;
    d -= t * dv;
    r += t;
    /* Up to 49 bits in r */
    /* Remaining 7 bits from d0. */
    r <<= 7;
    d <<= 7;
    d |= d0 & ((1 << 7) - 1);
    t = d / dv;
    r += t;

    return r;
}
#endif /* WOLFSSL_SP_DIV_64 */

/* Divide d in a and put remainder into r (m*d + r = a)
 * m is not calculated as it is not needed at this time.
 *
 * a  Number to be divided.
 * d  Number to divide with.
 * m  Multiplier result.
 * r  Remainder from the division.
 * returns MEMORY_E when unable to allocate memory and MP_OKAY otherwise.
 */
static int sp_384_div_7(const sp_digit* a, const sp_digit* d, sp_digit* m,
        sp_digit* r)
{
    int i;
#ifndef WOLFSSL_SP_DIV_64
    int128_t d1;
#endif
    sp_digit dv, r1;
#if (defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)) && !defined(WOLFSSL_SP_NO_MALLOC)
    sp_digit* td;
#else
    sp_digit t1d[14], t2d[7 + 1];
#endif
    sp_digit* t1;
    sp_digit* t2;
    int err = MP_OKAY;

    (void)m;

#if (defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)) && !defined(WOLFSSL_SP_NO_MALLOC)
    td = (sp_digit*)XMALLOC(sizeof(sp_digit) * (3 * 7 + 1), NULL,
                                                       DYNAMIC_TYPE_TMP_BUFFER);
    if (td == NULL) {
        err = MEMORY_E;
    }
#endif

    if (err == MP_OKAY) {
#if (defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)) && !defined(WOLFSSL_SP_NO_MALLOC)
        t1 = td;
        t2 = td + 2 * 7;
#else
        t1 = t1d;
        t2 = t2d;
#endif

        dv = d[6];
        XMEMCPY(t1, a, sizeof(*t1) * 2U * 7U);
        for (i=6; i>=0; i--) {
            sp_digit hi;
            t1[7 + i] += t1[7 + i - 1] >> 55;
            t1[7 + i - 1] &= 0x7fffffffffffffL;
            hi = t1[7 + i] - (t1[7 + i] == dv);
#ifndef WOLFSSL_SP_DIV_64
            d1 = hi;
            d1 <<= 55;
            d1 += t1[7 + i - 1];
            r1 = (sp_digit)(d1 / dv);
#else
            r1 = sp_384_div_word_7(hi, t1[7 + i - 1], dv);
#endif

            sp_384_mul_d_7(t2, d, r1);
            (void)sp_384_sub_7(&t1[i], &t1[i], t2);
            t1[7 + i] -= t2[7];
            t1[7 + i] += t1[7 + i - 1] >> 55;
            t1[7 + i - 1] &= 0x7fffffffffffffL;
            r1 = (((-t1[7 + i]) << 55) - t1[7 + i - 1]) / dv;
            r1++;
            sp_384_mul_d_7(t2, d, r1);
            (void)sp_384_add_7(&t1[i], &t1[i], t2);
            t1[7 + i] += t1[7 + i - 1] >> 55;
            t1[7 + i - 1] &= 0x7fffffffffffffL;
        }
        t1[7 - 1] += t1[7 - 2] >> 55;
        t1[7 - 2] &= 0x7fffffffffffffL;
        r1 = t1[7 - 1] / dv;

        sp_384_mul_d_7(t2, d, r1);
        (void)sp_384_sub_7(t1, t1, t2);
        XMEMCPY(r, t1, sizeof(*r) * 2U * 7U);
        for (i=0; i<6; i++) {
            r[i+1] += r[i] >> 55;
            r[i] &= 0x7fffffffffffffL;
        }
        sp_384_cond_add_7(r, r, d, 0 - ((r[6] < 0) ?
                    (sp_digit)1 : (sp_digit)0));
    }

#if (defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)) && !defined(WOLFSSL_SP_NO_MALLOC)
    if (td != NULL) {
        XFREE(td, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
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
static int sp_384_mod_7(sp_digit* r, const sp_digit* a, const sp_digit* m)
{
    return sp_384_div_7(a, m, NULL, r);
}

#endif
#if defined(HAVE_ECC_SIGN) || defined(HAVE_ECC_VERIFY)
#ifdef WOLFSSL_SP_SMALL
/* Order-2 for the P384 curve. */
static const uint64_t p384_order_minus_2[6] = {
    0xecec196accc52971U,0x581a0db248b0a77aU,0xc7634d81f4372ddfU,
    0xffffffffffffffffU,0xffffffffffffffffU,0xffffffffffffffffU
};
#else
/* The low half of the order-2 of the P384 curve. */
static const uint64_t p384_order_low[3] = {
    0xecec196accc52971U,0x581a0db248b0a77aU,0xc7634d81f4372ddfU
    
};
#endif /* WOLFSSL_SP_SMALL */

/* Multiply two number mod the order of P384 curve. (r = a * b mod order)
 *
 * r  Result of the multiplication.
 * a  First operand of the multiplication.
 * b  Second operand of the multiplication.
 */
static void sp_384_mont_mul_order_7(sp_digit* r, const sp_digit* a, const sp_digit* b)
{
    sp_384_mul_7(r, a, b);
    sp_384_mont_reduce_order_7(r, p384_order, p384_mp_order);
}

/* Square number mod the order of P384 curve. (r = a * a mod order)
 *
 * r  Result of the squaring.
 * a  Number to square.
 */
static void sp_384_mont_sqr_order_7(sp_digit* r, const sp_digit* a)
{
    sp_384_sqr_7(r, a);
    sp_384_mont_reduce_order_7(r, p384_order, p384_mp_order);
}

#ifndef WOLFSSL_SP_SMALL
/* Square number mod the order of P384 curve a number of times.
 * (r = a ^ n mod order)
 *
 * r  Result of the squaring.
 * a  Number to square.
 */
static void sp_384_mont_sqr_n_order_7(sp_digit* r, const sp_digit* a, int n)
{
    int i;

    sp_384_mont_sqr_order_7(r, a);
    for (i=1; i<n; i++) {
        sp_384_mont_sqr_order_7(r, r);
    }
}
#endif /* !WOLFSSL_SP_SMALL */

/* Invert the number, in Montgomery form, modulo the order of the P384 curve.
 * (r = 1 / a mod order)
 *
 * r   Inverse result.
 * a   Number to invert.
 * td  Temporary data.
 */

static void sp_384_mont_inv_order_7(sp_digit* r, const sp_digit* a,
        sp_digit* td)
{
#ifdef WOLFSSL_SP_SMALL
    sp_digit* t = td;
    int i;

    XMEMCPY(t, a, sizeof(sp_digit) * 7);
    for (i=382; i>=0; i--) {
        sp_384_mont_sqr_order_7(t, t);
        if ((p384_order_minus_2[i / 64] & ((sp_int_digit)1 << (i % 64))) != 0) {
            sp_384_mont_mul_order_7(t, t, a);
        }
    }
    XMEMCPY(r, t, sizeof(sp_digit) * 7U);
#else
    sp_digit* t = td;
    sp_digit* t2 = td + 2 * 7;
    sp_digit* t3 = td + 4 * 7;
    int i;

    /* t = a^2 */
    sp_384_mont_sqr_order_7(t, a);
    /* t = a^3 = t * a */
    sp_384_mont_mul_order_7(t, t, a);
    /* t2= a^c = t ^ 2 ^ 2 */
    sp_384_mont_sqr_n_order_7(t2, t, 2);
    /* t = a^f = t2 * t */
    sp_384_mont_mul_order_7(t, t2, t);
    /* t2= a^f0 = t ^ 2 ^ 4 */
    sp_384_mont_sqr_n_order_7(t2, t, 4);
    /* t = a^ff = t2 * t */
    sp_384_mont_mul_order_7(t, t2, t);
    /* t2= a^ff00 = t ^ 2 ^ 8 */
    sp_384_mont_sqr_n_order_7(t2, t, 8);
    /* t3= a^ffff = t2 * t */
    sp_384_mont_mul_order_7(t3, t2, t);
    /* t2= a^ffff0000 = t3 ^ 2 ^ 16 */
    sp_384_mont_sqr_n_order_7(t2, t3, 16);
    /* t = a^ffffffff = t2 * t3 */
    sp_384_mont_mul_order_7(t, t2, t3);
    /* t2= a^ffffffff0000 = t ^ 2 ^ 16  */
    sp_384_mont_sqr_n_order_7(t2, t, 16);
    /* t = a^ffffffffffff = t2 * t3 */
    sp_384_mont_mul_order_7(t, t2, t3);
    /* t2= a^ffffffffffff000000000000 = t ^ 2 ^ 48  */
    sp_384_mont_sqr_n_order_7(t2, t, 48);
    /* t= a^fffffffffffffffffffffffff = t2 * t */
    sp_384_mont_mul_order_7(t, t2, t);
    /* t2= a^ffffffffffffffffffffffff000000000000000000000000 */
    sp_384_mont_sqr_n_order_7(t2, t, 96);
    /* t2= a^ffffffffffffffffffffffffffffffffffffffffffffffff = t2 * t */
    sp_384_mont_mul_order_7(t2, t2, t);
    for (i=191; i>=1; i--) {
        sp_384_mont_sqr_order_7(t2, t2);
        if (((sp_digit)p384_order_low[i / 64] & ((sp_int_digit)1 << (i % 64))) != 0) {
            sp_384_mont_mul_order_7(t2, t2, a);
        }
    }
    sp_384_mont_sqr_order_7(t2, t2);
    sp_384_mont_mul_order_7(r, t2, a);
#endif /* WOLFSSL_SP_SMALL */
}

#endif /* HAVE_ECC_SIGN || HAVE_ECC_VERIFY */
#ifdef HAVE_ECC_SIGN
#ifndef SP_ECC_MAX_SIG_GEN
#define SP_ECC_MAX_SIG_GEN  64
#endif


int sp_ecc_sign_384(const byte* hash, word32 hashLen, WC_RNG* rng, mp_int* priv,
                    mp_int* rm, mp_int* sm, mp_int* km, void* heap)
{
#if (defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)) && !defined(WOLFSSL_SP_NO_MALLOC)
    sp_digit* d = NULL;
#else
    sp_digit ed[2*7];
    sp_digit xd[2*7];
    sp_digit kd[2*7];
    sp_digit rd[2*7];
    sp_digit td[3 * 2*7];
    sp_point_384 p;
#endif
    sp_digit* e = NULL;
    sp_digit* x = NULL;
    sp_digit* k = NULL;
    sp_digit* r = NULL;
    sp_digit* tmp = NULL;
    sp_point_384* point = NULL;
    sp_digit carry;
    sp_digit* s = NULL;
    sp_digit* kInv = NULL;
    int err = MP_OKAY;
    int64_t c;
    int i;

    (void)heap;

    err = sp_384_point_new_7(heap, p, point);
#if (defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)) && !defined(WOLFSSL_SP_NO_MALLOC)
    if (err == MP_OKAY) {
        d = (sp_digit*)XMALLOC(sizeof(sp_digit) * 7 * 2 * 7, heap,
                                                              DYNAMIC_TYPE_ECC);
        if (d == NULL) {
            err = MEMORY_E;
        }
    }
#endif

    if (err == MP_OKAY) {
#if (defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)) && !defined(WOLFSSL_SP_NO_MALLOC)
        e = d + 0 * 7;
        x = d + 2 * 7;
        k = d + 4 * 7;
        r = d + 6 * 7;
        tmp = d + 8 * 7;
#else
        e = ed;
        x = xd;
        k = kd;
        r = rd;
        tmp = td;
#endif
        s = e;
        kInv = k;

        if (hashLen > 48U) {
            hashLen = 48U;
        }

        sp_384_from_bin(e, 7, hash, (int)hashLen);
    }

    for (i = SP_ECC_MAX_SIG_GEN; err == MP_OKAY && i > 0; i--) {
        sp_384_from_mp(x, 7, priv);

        /* New random point. */
        if (km == NULL || mp_iszero(km)) {
            err = sp_384_ecc_gen_k_7(rng, k);
        }
        else {
            sp_384_from_mp(k, 7, km);
            mp_zero(km);
        }
        if (err == MP_OKAY) {
                err = sp_384_ecc_mulmod_base_7(point, k, 1, 1, NULL);
        }

        if (err == MP_OKAY) {
            /* r = point->x mod order */
            XMEMCPY(r, point->x, sizeof(sp_digit) * 7U);
            sp_384_norm_7(r);
            c = sp_384_cmp_7(r, p384_order);
            sp_384_cond_sub_7(r, r, p384_order, 0L - (sp_digit)(c >= 0));
            sp_384_norm_7(r);

            /* Conv k to Montgomery form (mod order) */
                sp_384_mul_7(k, k, p384_norm_order);
            err = sp_384_mod_7(k, k, p384_order);
        }
        if (err == MP_OKAY) {
            sp_384_norm_7(k);
            /* kInv = 1/k mod order */
                sp_384_mont_inv_order_7(kInv, k, tmp);
            sp_384_norm_7(kInv);

            /* s = r * x + e */
                sp_384_mul_7(x, x, r);
            err = sp_384_mod_7(x, x, p384_order);
        }
        if (err == MP_OKAY) {
            sp_384_norm_7(x);
            carry = sp_384_add_7(s, e, x);
            sp_384_cond_sub_7(s, s, p384_order, 0 - carry);
            sp_384_norm_7(s);
            c = sp_384_cmp_7(s, p384_order);
            sp_384_cond_sub_7(s, s, p384_order, 0L - (sp_digit)(c >= 0));
            sp_384_norm_7(s);

            /* s = s * k^-1 mod order */
                sp_384_mont_mul_order_7(s, s, kInv);
            sp_384_norm_7(s);

            /* Check that signature is usable. */
            if (sp_384_iszero_7(s) == 0) {
                break;
            }
        }
    }

    if (i == 0) {
        err = RNG_FAILURE_E;
    }

    if (err == MP_OKAY) {
        err = sp_384_to_mp(r, rm);
    }
    if (err == MP_OKAY) {
        err = sp_384_to_mp(s, sm);
    }

#if (defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)) && !defined(WOLFSSL_SP_NO_MALLOC)
    if (d != NULL) {
        XMEMSET(d, 0, sizeof(sp_digit) * 8 * 7);
        XFREE(d, heap, DYNAMIC_TYPE_ECC);
    }
#else
    XMEMSET(e, 0, sizeof(sp_digit) * 2U * 7U);
    XMEMSET(x, 0, sizeof(sp_digit) * 2U * 7U);
    XMEMSET(k, 0, sizeof(sp_digit) * 2U * 7U);
    XMEMSET(r, 0, sizeof(sp_digit) * 2U * 7U);
    XMEMSET(r, 0, sizeof(sp_digit) * 2U * 7U);
    XMEMSET(tmp, 0, sizeof(sp_digit) * 3U * 2U * 7U);
#endif
    sp_384_point_free_7(point, 1, heap);

    return err;
}
#endif /* HAVE_ECC_SIGN */

#ifndef WOLFSSL_SP_SMALL
static const char sp_384_tab64_7[64] = {
    64,  1, 59,  2, 60, 48, 54,  3,
    61, 40, 49, 28, 55, 34, 43,  4,
    62, 52, 38, 41, 50, 19, 29, 21,
    56, 31, 35, 12, 44, 15, 23,  5,
    63, 58, 47, 53, 39, 27, 33, 42,
    51, 37, 18, 20, 30, 11, 14, 22,
    57, 46, 26, 32, 36, 17, 10, 13,
    45, 25, 16,  9, 24,  8,  7,  6};

static int sp_384_num_bits_55_7(sp_digit v)
{
    v |= v >> 1;
    v |= v >> 2;
    v |= v >> 4;
    v |= v >> 8;
    v |= v >> 16;
    v |= v >> 32;
    return sp_384_tab64_7[((uint64_t)((v - (v >> 1))*0x07EDD5E59A4E28C2)) >> 58];
}

static int sp_384_num_bits_7(const sp_digit* a)
{
    int i;
    int r = 0;

    for (i = 6; i >= 0; i--) {
        if (a[i] != 0) {
            r = sp_384_num_bits_55_7(a[i]);
            r += i * 55;
            break;
        }
    }

    return r;
}

/* Non-constant time modular inversion.
 *
 * @param  [out]  r   Resulting number.
 * @param  [in]   a   Number to invert.
 * @param  [in]   m   Modulus.
 * @return  MP_OKAY on success.
 * @return  MEMEORY_E when dynamic memory allocation fails.
 */
static int sp_384_mod_inv_7(sp_digit* r, const sp_digit* a, const sp_digit* m)
{
    int err = MP_OKAY;
#if defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)
    sp_digit* u;
    sp_digit* v;
    sp_digit* b;
    sp_digit* d;
#else
    sp_digit u[7];
    sp_digit v[7];
    sp_digit b[7];
    sp_digit d[7];
#endif
    int ut, vt;

#if defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)
    u = (sp_digit*)XMALLOC(sizeof(sp_digit) * 7 * 4, NULL,
                                                              DYNAMIC_TYPE_ECC);
    if (u == NULL)
        err = MEMORY_E;
#endif

    if (err == MP_OKAY) {
#if defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)
        v = u + 7;
        b = u + 2 * 7;
        d = u + 3 * 7;
#endif

        XMEMCPY(u, m, sizeof(sp_digit) * 7);
        XMEMCPY(v, a, sizeof(sp_digit) * 7);

        ut = sp_384_num_bits_7(u);
        vt = sp_384_num_bits_7(v);

        XMEMSET(b, 0, sizeof(sp_digit) * 7);
        if ((v[0] & 1) == 0) {
            sp_384_rshift1_7(v, v);
            XMEMCPY(d, m, sizeof(sp_digit) * 7);
            d[0]++;
            sp_384_rshift1_7(d, d);
            vt--;

            while ((v[0] & 1) == 0) {
                sp_384_rshift1_7(v, v);
                if (d[0] & 1)
                    sp_384_add_7(d, d, m);
                sp_384_rshift1_7(d, d);
                vt--;
            }
        }
        else {
            XMEMSET(d+1, 0, sizeof(sp_digit) * (7 - 1));
            d[0] = 1;
        }

        while (ut > 1 && vt > 1) {
            if (ut > vt || (ut == vt &&
                                       sp_384_cmp_7(u, v) >= 0)) {
                sp_384_sub_7(u, u, v);
                sp_384_norm_7(u);

                sp_384_sub_7(b, b, d);
                sp_384_norm_7(b);
                if (b[6] < 0)
                    sp_384_add_7(b, b, m);
                sp_384_norm_7(b);
                ut = sp_384_num_bits_7(u);

                do {
                    sp_384_rshift1_7(u, u);
                    if (b[0] & 1)
                        sp_384_add_7(b, b, m);
                    sp_384_rshift1_7(b, b);
                    ut--;
                }
                while (ut > 0 && (u[0] & 1) == 0);
            }
            else {
                sp_384_sub_7(v, v, u);
                sp_384_norm_7(v);

                sp_384_sub_7(d, d, b);
                sp_384_norm_7(d);
                if (d[6] < 0)
                    sp_384_add_7(d, d, m);
                sp_384_norm_7(d);
                vt = sp_384_num_bits_7(v);

                do {
                    sp_384_rshift1_7(v, v);
                    if (d[0] & 1)
                        sp_384_add_7(d, d, m);
                    sp_384_rshift1_7(d, d);
                    vt--;
                }
                while (vt > 0 && (v[0] & 1) == 0);
            }
        }

        if (ut == 1)
            XMEMCPY(r, b, sizeof(sp_digit) * 7);
        else
            XMEMCPY(r, d, sizeof(sp_digit) * 7);
    }
#if defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)
    if (u != NULL)
        XFREE(u, NULL, DYNAMIC_TYPE_ECC);
#endif

    return err;
}

#endif /* WOLFSSL_SP_SMALL */
#ifdef HAVE_ECC_VERIFY
/* Verify the signature values with the hash and public key.
 *   e = Truncate(hash, 384)
 *   u1 = e/s mod order
 *   u2 = r/s mod order
 *   r == (u1.G + u2.Q)->x mod order
 * Optimization: Leave point in projective form.
 *   (x, y, 1) == (x' / z'*z', y' / z'*z'*z', z' / z')
 *   (r + n*order).z'.z' mod prime == (u1.G + u2.Q)->x'
 * The hash is truncated to the first 384 bits.
 *
 * hash     Hash to sign.
 * hashLen  Length of the hash data.
 * rng      Random number generator.
 * priv     Private part of key - scalar.
 * rm       First part of result as an mp_int.
 * sm       Sirst part of result as an mp_int.
 * heap     Heap to use for allocation.
 * returns RNG failures, MEMORY_E when memory allocation fails and
 * MP_OKAY on success.
 */


int sp_ecc_verify_384(const byte* hash, word32 hashLen, mp_int* pX,
    mp_int* pY, mp_int* pZ, mp_int* r, mp_int* sm, int* res, void* heap)
{
#if (defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)) && !defined(WOLFSSL_SP_NO_MALLOC)
    sp_digit* d = NULL;
#else
    sp_digit u1d[2*7];
    sp_digit u2d[2*7];
    sp_digit sd[2*7];
    sp_digit tmpd[2*7 * 5];
    sp_point_384 p1d;
    sp_point_384 p2d;
#endif
    sp_digit* u1 = NULL;
    sp_digit* u2 = NULL;
    sp_digit* s = NULL;
    sp_digit* tmp = NULL;
    sp_point_384* p1;
    sp_point_384* p2 = NULL;
    sp_digit carry;
    int64_t c;
    int err;

    err = sp_384_point_new_7(heap, p1d, p1);
    if (err == MP_OKAY) {
        err = sp_384_point_new_7(heap, p2d, p2);
    }
#if (defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)) && !defined(WOLFSSL_SP_NO_MALLOC)
    if (err == MP_OKAY) {
        d = (sp_digit*)XMALLOC(sizeof(sp_digit) * 16 * 7, heap,
                                                              DYNAMIC_TYPE_ECC);
        if (d == NULL) {
            err = MEMORY_E;
        }
    }
#endif

    if (err == MP_OKAY) {
#if (defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)) && !defined(WOLFSSL_SP_NO_MALLOC)
        u1  = d + 0 * 7;
        u2  = d + 2 * 7;
        s   = d + 4 * 7;
        tmp = d + 6 * 7;
#else
        u1 = u1d;
        u2 = u2d;
        s  = sd;
        tmp = tmpd;
#endif

        if (hashLen > 48U) {
            hashLen = 48U;
        }

        sp_384_from_bin(u1, 7, hash, (int)hashLen);
        sp_384_from_mp(u2, 7, r);
        sp_384_from_mp(s, 7, sm);
        sp_384_from_mp(p2->x, 7, pX);
        sp_384_from_mp(p2->y, 7, pY);
        sp_384_from_mp(p2->z, 7, pZ);

#ifndef WOLFSSL_SP_SMALL
        {
            sp_384_mod_inv_7(s, s, p384_order);
        }
#endif /* !WOLFSSL_SP_SMALL */
        {
            sp_384_mul_7(s, s, p384_norm_order);
        }
        err = sp_384_mod_7(s, s, p384_order);
    }
    if (err == MP_OKAY) {
        sp_384_norm_7(s);
#ifdef WOLFSSL_SP_SMALL
        {
            sp_384_mont_inv_order_7(s, s, tmp);
            sp_384_mont_mul_order_7(u1, u1, s);
            sp_384_mont_mul_order_7(u2, u2, s);
        }

#else
        {
            sp_384_mont_mul_order_7(u1, u1, s);
            sp_384_mont_mul_order_7(u2, u2, s);
        }

#endif /* WOLFSSL_SP_SMALL */
            err = sp_384_ecc_mulmod_base_7(p1, u1, 0, 0, heap);
    }
    if (err == MP_OKAY) {
            err = sp_384_ecc_mulmod_7(p2, p2, u2, 0, 0, heap);
    }

    if (err == MP_OKAY) {
        {
            sp_384_proj_point_add_7(p1, p1, p2, tmp);
            if (sp_384_iszero_7(p1->z)) {
                if (sp_384_iszero_7(p1->x) && sp_384_iszero_7(p1->y)) {
                    sp_384_proj_point_dbl_7(p1, p2, tmp);
                }
                else {
                    /* Y ordinate is not used from here - don't set. */
                    p1->x[0] = 0;
                    p1->x[1] = 0;
                    p1->x[2] = 0;
                    p1->x[3] = 0;
                    p1->x[4] = 0;
                    p1->x[5] = 0;
                    p1->x[6] = 0;
                    XMEMCPY(p1->z, p384_norm_mod, sizeof(p384_norm_mod));
                }
            }
        }

        /* (r + n*order).z'.z' mod prime == (u1.G + u2.Q)->x' */
        /* Reload r and convert to Montgomery form. */
        sp_384_from_mp(u2, 7, r);
        err = sp_384_mod_mul_norm_7(u2, u2, p384_mod);
    }

    if (err == MP_OKAY) {
        /* u1 = r.z'.z' mod prime */
        sp_384_mont_sqr_7(p1->z, p1->z, p384_mod, p384_mp_mod);
        sp_384_mont_mul_7(u1, u2, p1->z, p384_mod, p384_mp_mod);
        *res = (int)(sp_384_cmp_7(p1->x, u1) == 0);
        if (*res == 0) {
            /* Reload r and add order. */
            sp_384_from_mp(u2, 7, r);
            carry = sp_384_add_7(u2, u2, p384_order);
            /* Carry means result is greater than mod and is not valid. */
            if (carry == 0) {
                sp_384_norm_7(u2);

                /* Compare with mod and if greater or equal then not valid. */
                c = sp_384_cmp_7(u2, p384_mod);
                if (c < 0) {
                    /* Convert to Montogomery form */
                    err = sp_384_mod_mul_norm_7(u2, u2, p384_mod);
                    if (err == MP_OKAY) {
                        /* u1 = (r + 1*order).z'.z' mod prime */
                        sp_384_mont_mul_7(u1, u2, p1->z, p384_mod,
                                                                  p384_mp_mod);
                        *res = (int)(sp_384_cmp_7(p1->x, u1) == 0);
                    }
                }
            }
        }
    }

#if (defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)) && !defined(WOLFSSL_SP_NO_MALLOC)
    if (d != NULL)
        XFREE(d, heap, DYNAMIC_TYPE_ECC);
#endif
    sp_384_point_free_7(p1, 0, heap);
    sp_384_point_free_7(p2, 0, heap);

    return err;
}
#endif /* HAVE_ECC_VERIFY */

#ifdef HAVE_ECC_CHECK_KEY
/* Check that the x and y oridinates are a valid point on the curve.
 *
 * point  EC point.
 * heap   Heap to use if dynamically allocating.
 * returns MEMORY_E if dynamic memory allocation fails, MP_VAL if the point is
 * not on the curve and MP_OKAY otherwise.
 */
static int sp_384_ecc_is_point_7(sp_point_384* point, void* heap)
{
#if (defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)) && !defined(WOLFSSL_SP_NO_MALLOC)
    sp_digit* d = NULL;
#else
    sp_digit t1d[2*7];
    sp_digit t2d[2*7];
#endif
    sp_digit* t1;
    sp_digit* t2;
    int err = MP_OKAY;

#if (defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)) && !defined(WOLFSSL_SP_NO_MALLOC)
    d = (sp_digit*)XMALLOC(sizeof(sp_digit) * 7 * 4, heap, DYNAMIC_TYPE_ECC);
    if (d == NULL) {
        err = MEMORY_E;
    }
#endif
    (void)heap;

    if (err == MP_OKAY) {
#if (defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)) && !defined(WOLFSSL_SP_NO_MALLOC)
        t1 = d + 0 * 7;
        t2 = d + 2 * 7;
#else
        t1 = t1d;
        t2 = t2d;
#endif

        sp_384_sqr_7(t1, point->y);
        (void)sp_384_mod_7(t1, t1, p384_mod);
        sp_384_sqr_7(t2, point->x);
        (void)sp_384_mod_7(t2, t2, p384_mod);
        sp_384_mul_7(t2, t2, point->x);
        (void)sp_384_mod_7(t2, t2, p384_mod);
        (void)sp_384_sub_7(t2, p384_mod, t2);
        sp_384_mont_add_7(t1, t1, t2, p384_mod);

        sp_384_mont_add_7(t1, t1, point->x, p384_mod);
        sp_384_mont_add_7(t1, t1, point->x, p384_mod);
        sp_384_mont_add_7(t1, t1, point->x, p384_mod);

        if (sp_384_cmp_7(t1, p384_b) != 0) {
            err = MP_VAL;
        }
    }

#if (defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)) && !defined(WOLFSSL_SP_NO_MALLOC)
    if (d != NULL) {
        XFREE(d, heap, DYNAMIC_TYPE_ECC);
    }
#endif

    return err;
}

/* Check that the x and y oridinates are a valid point on the curve.
 *
 * pX  X ordinate of EC point.
 * pY  Y ordinate of EC point.
 * returns MEMORY_E if dynamic memory allocation fails, MP_VAL if the point is
 * not on the curve and MP_OKAY otherwise.
 */
int sp_ecc_is_point_384(mp_int* pX, mp_int* pY)
{
#if (!defined(WOLFSSL_SP_SMALL) && !defined(WOLFSSL_SMALL_STACK)) || defined(WOLFSSL_SP_NO_MALLOC)
    sp_point_384 pubd;
#endif
    sp_point_384* pub;
    byte one[1] = { 1 };
    int err;

    err = sp_384_point_new_7(NULL, pubd, pub);
    if (err == MP_OKAY) {
        sp_384_from_mp(pub->x, 7, pX);
        sp_384_from_mp(pub->y, 7, pY);
        sp_384_from_bin(pub->z, 7, one, (int)sizeof(one));

        err = sp_384_ecc_is_point_7(pub, NULL);
    }

    sp_384_point_free_7(pub, 0, NULL);

    return err;
}

/* Check that the private scalar generates the EC point (px, py), the point is
 * on the curve and the point has the correct order.
 *
 * pX     X ordinate of EC point.
 * pY     Y ordinate of EC point.
 * privm  Private scalar that generates EC point.
 * returns MEMORY_E if dynamic memory allocation fails, MP_VAL if the point is
 * not on the curve, ECC_INF_E if the point does not have the correct order,
 * ECC_PRIV_KEY_E when the private scalar doesn't generate the EC point and
 * MP_OKAY otherwise.
 */
int sp_ecc_check_key_384(mp_int* pX, mp_int* pY, mp_int* privm, void* heap)
{
#if (!defined(WOLFSSL_SP_SMALL) && !defined(WOLFSSL_SMALL_STACK)) || defined(WOLFSSL_SP_NO_MALLOC)
    sp_digit privd[7];
    sp_point_384 pubd;
    sp_point_384 pd;
#endif
    sp_digit* priv = NULL;
    sp_point_384* pub;
    sp_point_384* p = NULL;
    byte one[1] = { 1 };
    int err;

    err = sp_384_point_new_7(heap, pubd, pub);
    if (err == MP_OKAY) {
        err = sp_384_point_new_7(heap, pd, p);
    }
#if (defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)) && !defined(WOLFSSL_SP_NO_MALLOC)
    if (err == MP_OKAY && privm) {
        priv = (sp_digit*)XMALLOC(sizeof(sp_digit) * 7, heap,
                                                              DYNAMIC_TYPE_ECC);
        if (priv == NULL) {
            err = MEMORY_E;
        }
    }
#endif

    /* Quick check the lengs of public key ordinates and private key are in
     * range. Proper check later.
     */
    if ((err == MP_OKAY) && ((mp_count_bits(pX) > 384) ||
        (mp_count_bits(pY) > 384) ||
        ((privm != NULL) && (mp_count_bits(privm) > 384)))) {
        err = ECC_OUT_OF_RANGE_E;
    }

    if (err == MP_OKAY) {
#if (!defined(WOLFSSL_SP_SMALL) && !defined(WOLFSSL_SMALL_STACK)) || defined(WOLFSSL_SP_NO_MALLOC)
        priv = privd;
#endif

        sp_384_from_mp(pub->x, 7, pX);
        sp_384_from_mp(pub->y, 7, pY);
        sp_384_from_bin(pub->z, 7, one, (int)sizeof(one));
        if (privm)
            sp_384_from_mp(priv, 7, privm);

        /* Check point at infinitiy. */
        if ((sp_384_iszero_7(pub->x) != 0) &&
            (sp_384_iszero_7(pub->y) != 0)) {
            err = ECC_INF_E;
        }
    }

    if (err == MP_OKAY) {
        /* Check range of X and Y */
        if (sp_384_cmp_7(pub->x, p384_mod) >= 0 ||
            sp_384_cmp_7(pub->y, p384_mod) >= 0) {
            err = ECC_OUT_OF_RANGE_E;
        }
    }

    if (err == MP_OKAY) {
        /* Check point is on curve */
        err = sp_384_ecc_is_point_7(pub, heap);
    }

    if (err == MP_OKAY) {
        /* Point * order = infinity */
            err = sp_384_ecc_mulmod_7(p, pub, p384_order, 1, 1, heap);
    }
    if (err == MP_OKAY) {
        /* Check result is infinity */
        if ((sp_384_iszero_7(p->x) == 0) ||
            (sp_384_iszero_7(p->y) == 0)) {
            err = ECC_INF_E;
        }
    }

    if (privm) {
        if (err == MP_OKAY) {
            /* Base * private = point */
                err = sp_384_ecc_mulmod_base_7(p, priv, 1, 1, heap);
        }
        if (err == MP_OKAY) {
            /* Check result is public key */
            if (sp_384_cmp_7(p->x, pub->x) != 0 ||
                sp_384_cmp_7(p->y, pub->y) != 0) {
                err = ECC_PRIV_KEY_E;
            }
        }
    }

#if (defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)) && !defined(WOLFSSL_SP_NO_MALLOC)
    if (priv != NULL) {
        XFREE(priv, heap, DYNAMIC_TYPE_ECC);
    }
#endif
    sp_384_point_free_7(p, 0, heap);
    sp_384_point_free_7(pub, 0, heap);

    return err;
}
#endif
#endif /* WOLFSSL_SP_384 */
#endif /* WOLFSSL_HAVE_SP_ECC */
#endif /* SP_WORD_SIZE == 64 */
#endif /* !WOLFSSL_SP_ASM */
#endif /* WOLFSSL_HAVE_SP_RSA || WOLFSSL_HAVE_SP_DH || WOLFSSL_HAVE_SP_ECC */
