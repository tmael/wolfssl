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
#ifndef WOLFSSL_SP_SMALL
#define WOLFSSL_SP_SMALL
#endif
#endif

#include <wolfssl/wolfcrypt/sp.h>

#ifdef WOLFSSL_SP_ARM64_ASM
#ifdef WOLFSSL_HAVE_SP_ECC
#ifdef WOLFSSL_SP_384

/* Point structure to use. */
typedef struct sp_point_384 {
    sp_digit x[2 * 6];
    sp_digit y[2 * 6];
    sp_digit z[2 * 6];
    int infinity;
} sp_point_384;

/* The modulus (prime) of the curve P384. */
static const sp_digit p384_mod[6] = {
    0x00000000ffffffffL,0xffffffff00000000L,0xfffffffffffffffeL,
    0xffffffffffffffffL,0xffffffffffffffffL,0xffffffffffffffffL
};
/* The Montogmery normalizer for modulus of the curve P384. */
static const sp_digit p384_norm_mod[6] = {
    0xffffffff00000001L,0x00000000ffffffffL,0x0000000000000001L,
    0x0000000000000000L,0x0000000000000000L,0x0000000000000000L
};
/* The Montogmery multiplier for modulus of the curve P384. */
static sp_digit p384_mp_mod = 0x0000000100000001;
#if defined(WOLFSSL_VALIDATE_ECC_KEYGEN) || defined(HAVE_ECC_SIGN) || \
                                            defined(HAVE_ECC_VERIFY)
/* The order of the curve P384. */
static const sp_digit p384_order[6] = {
    0xecec196accc52973L,0x581a0db248b0a77aL,0xc7634d81f4372ddfL,
    0xffffffffffffffffL,0xffffffffffffffffL,0xffffffffffffffffL
};
#endif
/* The order of the curve P384 minus 2. */
static const sp_digit p384_order2[6] = {
    0xecec196accc52971L,0x581a0db248b0a77aL,0xc7634d81f4372ddfL,
    0xffffffffffffffffL,0xffffffffffffffffL,0xffffffffffffffffL
};
#if defined(HAVE_ECC_SIGN) || defined(HAVE_ECC_VERIFY)
/* The Montogmery normalizer for order of the curve P384. */
static const sp_digit p384_norm_order[6] = {
    0x1313e695333ad68dL,0xa7e5f24db74f5885L,0x389cb27e0bc8d220L,
    0x0000000000000000L,0x0000000000000000L,0x0000000000000000L
};
#endif
#if defined(HAVE_ECC_SIGN) || defined(HAVE_ECC_VERIFY)
/* The Montogmery multiplier for order of the curve P384. */
static sp_digit p384_mp_order = 0x6ed46089e88fdc45l;
#endif
/* The base point of curve P384. */
static const sp_point_384 p384_base = {
    /* X ordinate */
    {
        0x3a545e3872760ab7L,0x5502f25dbf55296cL,0x59f741e082542a38L,
        0x6e1d3b628ba79b98L,0x8eb1c71ef320ad74L,0xaa87ca22be8b0537L,
        0L, 0L, 0L, 0L, 0L, 0L
    },
    /* Y ordinate */
    {
        0x7a431d7c90ea0e5fL,0x0a60b1ce1d7e819dL,0xe9da3113b5f0b8c0L,
        0xf8f41dbd289a147cL,0x5d9e98bf9292dc29L,0x3617de4a96262c6fL,
        0L, 0L, 0L, 0L, 0L, 0L
    },
    /* Z ordinate */
    {
        0x0000000000000001L,0x0000000000000000L,0x0000000000000000L,
        0x0000000000000000L,0x0000000000000000L,0x0000000000000000L,
        0L, 0L, 0L, 0L, 0L, 0L
    },
    /* infinity */
    0
};
#if defined(HAVE_ECC_CHECK_KEY) || defined(HAVE_COMP_KEY)
static const sp_digit p384_b[6] = {
    0x2a85c8edd3ec2aefL,0xc656398d8a2ed19dL,0x0314088f5013875aL,
    0x181d9c6efe814112L,0x988e056be3f82d19L,0xb3312fa7e23ee7e4L
};
#endif

static int sp_384_point_new_ex_6(void* heap, sp_point_384* sp, sp_point_384** p)
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
#define sp_384_point_new_6(heap, sp, p) sp_384_point_new_ex_6((heap), NULL, &(p))
#else
/* Set pointer to data and return no error. */
#define sp_384_point_new_6(heap, sp, p) sp_384_point_new_ex_6((heap), &(sp), &(p))
#endif


static void sp_384_point_free_6(sp_point_384* p, int clear, void* heap)
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
static int sp_384_mod_mul_norm_6(sp_digit* r, const sp_digit* a, const sp_digit* m)
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

        a32[0] = a[0] & 0xffffffff;
        a32[1] = a[0] >> 32;
        a32[2] = a[1] & 0xffffffff;
        a32[3] = a[1] >> 32;
        a32[4] = a[2] & 0xffffffff;
        a32[5] = a[2] >> 32;
        a32[6] = a[3] & 0xffffffff;
        a32[7] = a[3] >> 32;
        a32[8] = a[4] & 0xffffffff;
        a32[9] = a[4] >> 32;
        a32[10] = a[5] & 0xffffffff;
        a32[11] = a[5] >> 32;

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

        r[0] = (t[1] << 32) | t[0];
        r[1] = (t[3] << 32) | t[2];
        r[2] = (t[5] << 32) | t[4];
        r[3] = (t[7] << 32) | t[6];
        r[4] = (t[9] << 32) | t[8];
        r[5] = (t[11] << 32) | t[10];
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
#if DIGIT_BIT == 64
    int j;

    XMEMCPY(r, a->dp, sizeof(sp_digit) * a->used);

    for (j = a->used; j < size; j++) {
        r[j] = 0;
    }
#elif DIGIT_BIT > 64
    int i, j = 0;
    word32 s = 0;

    r[0] = 0;
    for (i = 0; i < a->used && j < size; i++) {
        r[j] |= ((sp_digit)a->dp[i] << s);
        r[j] &= 0xffffffffffffffffl;
        s = 64U - s;
        if (j + 1 >= size) {
            break;
        }
        /* lint allow cast of mismatch word32 and mp_digit */
        r[++j] = (sp_digit)(a->dp[i] >> s); /*lint !e9033*/
        while ((s + 64U) <= (word32)DIGIT_BIT) {
            s += 64U;
            r[j] &= 0xffffffffffffffffl;
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
        if (s + DIGIT_BIT >= 64) {
            r[j] &= 0xffffffffffffffffl;
            if (j + 1 >= size) {
                break;
            }
            s = 64 - s;
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
static void sp_384_point_from_ecc_point_6(sp_point_384* p, const ecc_point* pm)
{
    XMEMSET(p->x, 0, sizeof(p->x));
    XMEMSET(p->y, 0, sizeof(p->y));
    XMEMSET(p->z, 0, sizeof(p->z));
    sp_384_from_mp(p->x, 6, pm->x);
    sp_384_from_mp(p->y, 6, pm->y);
    sp_384_from_mp(p->z, 6, pm->z);
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
#if DIGIT_BIT == 64
        XMEMCPY(r->dp, a, sizeof(sp_digit) * 6);
        r->used = 6;
        mp_clamp(r);
#elif DIGIT_BIT < 64
        int i, j = 0, s = 0;

        r->dp[0] = 0;
        for (i = 0; i < 6; i++) {
            r->dp[j] |= (mp_digit)(a[i] << s);
            r->dp[j] &= (1L << DIGIT_BIT) - 1;
            s = DIGIT_BIT - s;
            r->dp[++j] = (mp_digit)(a[i] >> s);
            while (s + DIGIT_BIT <= 64) {
                s += DIGIT_BIT;
                r->dp[j++] &= (1L << DIGIT_BIT) - 1;
                if (s == SP_WORD_SIZE) {
                    r->dp[j] = 0;
                }
                else {
                    r->dp[j] = (mp_digit)(a[i] >> s);
                }
            }
            s = 64 - s;
        }
        r->used = (384 + DIGIT_BIT - 1) / DIGIT_BIT;
        mp_clamp(r);
#else
        int i, j = 0, s = 0;

        r->dp[0] = 0;
        for (i = 0; i < 6; i++) {
            r->dp[j] |= ((mp_digit)a[i]) << s;
            if (s + 64 >= DIGIT_BIT) {
    #if DIGIT_BIT != 32 && DIGIT_BIT != 64
                r->dp[j] &= (1L << DIGIT_BIT) - 1;
    #endif
                s = DIGIT_BIT - s;
                r->dp[++j] = a[i] >> s;
                s = 64 - s;
            }
            else {
                s += 64;
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
static int sp_384_point_to_ecc_point_6(const sp_point_384* p, ecc_point* pm)
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

/* Conditionally copy a into r using the mask m.
 * m is -1 to copy and 0 when not.
 *
 * r  A single precision number to copy over.
 * a  A single precision number to copy.
 * m  Mask value to apply.
 */
static void sp_384_cond_copy_6(sp_digit* r, const sp_digit* a, sp_digit m)
{
    __asm__ __volatile__ (
        "ldp	x3, x4, [%[r], 0]\n\t"
        "ldp	x5, x6, [%[r], 16]\n\t"
        "ldp	x7, x8, [%[r], 32]\n\t"
        "ldp	x9, x10, [%[a], 0]\n\t"
        "ldp	x11, x12, [%[a], 16]\n\t"
        "ldp	x13, x14, [%[a], 32]\n\t"
        "eor	x9, x9, x3\n\t"
        "eor	x10, x10, x4\n\t"
        "eor	x11, x11, x5\n\t"
        "eor	x12, x12, x6\n\t"
        "eor	x13, x13, x7\n\t"
        "eor	x14, x14, x8\n\t"
        "and	x9, x9, %[m]\n\t"
        "and	x10, x10, %[m]\n\t"
        "and	x11, x11, %[m]\n\t"
        "and	x12, x12, %[m]\n\t"
        "and	x13, x13, %[m]\n\t"
        "and	x14, x14, %[m]\n\t"
        "eor	x3, x3, x9\n\t"
        "eor	x4, x4, x10\n\t"
        "eor	x5, x5, x11\n\t"
        "eor	x6, x6, x12\n\t"
        "eor	x7, x7, x13\n\t"
        "eor	x8, x8, x14\n\t"
        "stp	x3, x4, [%[r], 0]\n\t"
        "stp	x5, x6, [%[r], 16]\n\t"
        "stp	x7, x8, [%[r], 32]\n\t"
        :
        : [r] "r" (r), [a] "r" (a), [m] "r" (m)
        : "memory", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14"
    );
}

#ifdef WOLFSSL_SP_SMALL
/* Multiply a and b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
static void sp_384_mul_6(sp_digit* r, const sp_digit* a, const sp_digit* b)
{
    sp_digit tmp[12];

    __asm__ __volatile__ (
        "mov	x5, 0\n\t"
        "mov	x6, 0\n\t"
        "mov	x7, 0\n\t"
        "mov	x8, 0\n\t"
        "\n1:\n\t"
        "subs	x3, x5, 40\n\t"
        "csel	x3, xzr, x3, cc\n\t"
        "sub	x4, x5, x3\n\t"
        "\n2:\n\t"
        "ldr	x10, [%[a], x3]\n\t"
        "ldr	x11, [%[b], x4]\n\t"
        "mul	x9, x10, x11\n\t"
        "umulh	x10, x10, x11\n\t"
        "adds	x6, x6, x9\n\t"
        "adcs	x7, x7, x10\n\t"
        "adc	x8, x8, xzr\n\t"
        "add	x3, x3, #8\n\t"
        "sub	x4, x4, #8\n\t"
        "cmp	x3, 48\n\t"
        "b.eq	3f\n\t"
        "cmp	x3, x5\n\t"
        "b.le	2b\n\t"
        "\n3:\n\t"
        "str	x6, [%[r], x5]\n\t"
        "mov	x6, x7\n\t"
        "mov	x7, x8\n\t"
        "mov	x8, #0\n\t"
        "add	x5, x5, #8\n\t"
        "cmp	x5, 80\n\t"
        "b.le	1b\n\t"
        "str	x6, [%[r], x5]\n\t"
        :
        : [r] "r" (tmp), [a] "r" (a), [b] "r" (b)
        : "memory", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11"
    );

    XMEMCPY(r, tmp, sizeof(tmp));
}

#else
/* Multiply a and b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
static void sp_384_mul_6(sp_digit* r, const sp_digit* a, const sp_digit* b)
{
    sp_digit tmp[6];

    __asm__ __volatile__ (
        "ldp	x9, x10, [%[a], 0]\n\t"
        "ldp	x11, x12, [%[a], 16]\n\t"
        "ldp	x13, x14, [%[a], 32]\n\t"
        "ldp	x15, x16, [%[b], 0]\n\t"
        "ldp	x17, x19, [%[b], 16]\n\t"
        "ldp	x20, x21, [%[b], 32]\n\t"
        "#  A[0] * B[0]\n\t"
        "mul	x4, x9, x15\n\t"
        "umulh	x5, x9, x15\n\t"
        "str	x4, [%[tmp]]\n\t"
        "#  A[0] * B[1]\n\t"
        "mul	x7, x9, x16\n\t"
        "umulh	x8, x9, x16\n\t"
        "adds	x5, x5, x7\n\t"
        "#  A[1] * B[0]\n\t"
        "mul	x7, x10, x15\n\t"
        "adc	x6, xzr, x8\n\t"
        "umulh	x8, x10, x15\n\t"
        "adds	x5, x5, x7\n\t"
        "adcs	x6, x6, x8\n\t"
        "str	x5, [%[tmp], 8]\n\t"
        "adc	x4, xzr, xzr\n\t"
        "#  A[0] * B[2]\n\t"
        "mul	x7, x9, x17\n\t"
        "umulh	x8, x9, x17\n\t"
        "adds	x6, x6, x7\n\t"
        "#  A[1] * B[1]\n\t"
        "mul	x7, x10, x16\n\t"
        "adcs	x4, x4, x8\n\t"
        "umulh	x8, x10, x16\n\t"
        "adc	x5, xzr, xzr\n\t"
        "adds	x6, x6, x7\n\t"
        "#  A[2] * B[0]\n\t"
        "mul	x7, x11, x15\n\t"
        "adcs	x4, x4, x8\n\t"
        "umulh	x8, x11, x15\n\t"
        "adc	x5, x5, xzr\n\t"
        "adds	x6, x6, x7\n\t"
        "adcs	x4, x4, x8\n\t"
        "str	x6, [%[tmp], 16]\n\t"
        "adc	x5, x5, xzr\n\t"
        "#  A[0] * B[3]\n\t"
        "mul	x7, x9, x19\n\t"
        "umulh	x8, x9, x19\n\t"
        "adds	x4, x4, x7\n\t"
        "#  A[1] * B[2]\n\t"
        "mul	x7, x10, x17\n\t"
        "adcs	x5, x5, x8\n\t"
        "umulh	x8, x10, x17\n\t"
        "adc	x6, xzr, xzr\n\t"
        "adds	x4, x4, x7\n\t"
        "#  A[2] * B[1]\n\t"
        "mul	x7, x11, x16\n\t"
        "adcs	x5, x5, x8\n\t"
        "umulh	x8, x11, x16\n\t"
        "adc	x6, x6, xzr\n\t"
        "adds	x4, x4, x7\n\t"
        "#  A[3] * B[0]\n\t"
        "mul	x7, x12, x15\n\t"
        "adcs	x5, x5, x8\n\t"
        "umulh	x8, x12, x15\n\t"
        "adc	x6, x6, xzr\n\t"
        "adds	x4, x4, x7\n\t"
        "adcs	x5, x5, x8\n\t"
        "str	x4, [%[tmp], 24]\n\t"
        "adc	x6, x6, xzr\n\t"
        "#  A[0] * B[4]\n\t"
        "mul	x7, x9, x20\n\t"
        "umulh	x8, x9, x20\n\t"
        "adds	x5, x5, x7\n\t"
        "#  A[1] * B[3]\n\t"
        "mul	x7, x10, x19\n\t"
        "adcs	x6, x6, x8\n\t"
        "umulh	x8, x10, x19\n\t"
        "adc	x4, xzr, xzr\n\t"
        "adds	x5, x5, x7\n\t"
        "#  A[2] * B[2]\n\t"
        "mul	x7, x11, x17\n\t"
        "adcs	x6, x6, x8\n\t"
        "umulh	x8, x11, x17\n\t"
        "adc	x4, x4, xzr\n\t"
        "adds	x5, x5, x7\n\t"
        "#  A[3] * B[1]\n\t"
        "mul	x7, x12, x16\n\t"
        "adcs	x6, x6, x8\n\t"
        "umulh	x8, x12, x16\n\t"
        "adc	x4, x4, xzr\n\t"
        "adds	x5, x5, x7\n\t"
        "#  A[4] * B[0]\n\t"
        "mul	x7, x13, x15\n\t"
        "adcs	x6, x6, x8\n\t"
        "umulh	x8, x13, x15\n\t"
        "adc	x4, x4, xzr\n\t"
        "adds	x5, x5, x7\n\t"
        "adcs	x6, x6, x8\n\t"
        "str	x5, [%[tmp], 32]\n\t"
        "adc	x4, x4, xzr\n\t"
        "#  A[0] * B[5]\n\t"
        "mul	x7, x9, x21\n\t"
        "umulh	x8, x9, x21\n\t"
        "adds	x6, x6, x7\n\t"
        "#  A[1] * B[4]\n\t"
        "mul	x7, x10, x20\n\t"
        "adcs	x4, x4, x8\n\t"
        "umulh	x8, x10, x20\n\t"
        "adc	x5, xzr, xzr\n\t"
        "adds	x6, x6, x7\n\t"
        "#  A[2] * B[3]\n\t"
        "mul	x7, x11, x19\n\t"
        "adcs	x4, x4, x8\n\t"
        "umulh	x8, x11, x19\n\t"
        "adc	x5, x5, xzr\n\t"
        "adds	x6, x6, x7\n\t"
        "#  A[3] * B[2]\n\t"
        "mul	x7, x12, x17\n\t"
        "adcs	x4, x4, x8\n\t"
        "umulh	x8, x12, x17\n\t"
        "adc	x5, x5, xzr\n\t"
        "adds	x6, x6, x7\n\t"
        "#  A[4] * B[1]\n\t"
        "mul	x7, x13, x16\n\t"
        "adcs	x4, x4, x8\n\t"
        "umulh	x8, x13, x16\n\t"
        "adc	x5, x5, xzr\n\t"
        "adds	x6, x6, x7\n\t"
        "#  A[5] * B[0]\n\t"
        "mul	x7, x14, x15\n\t"
        "adcs	x4, x4, x8\n\t"
        "umulh	x8, x14, x15\n\t"
        "adc	x5, x5, xzr\n\t"
        "adds	x6, x6, x7\n\t"
        "adcs	x4, x4, x8\n\t"
        "str	x6, [%[tmp], 40]\n\t"
        "adc	x5, x5, xzr\n\t"
        "#  A[1] * B[5]\n\t"
        "mul	x7, x10, x21\n\t"
        "umulh	x8, x10, x21\n\t"
        "adds	x4, x4, x7\n\t"
        "#  A[2] * B[4]\n\t"
        "mul	x7, x11, x20\n\t"
        "adcs	x5, x5, x8\n\t"
        "umulh	x8, x11, x20\n\t"
        "adc	x6, xzr, xzr\n\t"
        "adds	x4, x4, x7\n\t"
        "#  A[3] * B[3]\n\t"
        "mul	x7, x12, x19\n\t"
        "adcs	x5, x5, x8\n\t"
        "umulh	x8, x12, x19\n\t"
        "adc	x6, x6, xzr\n\t"
        "adds	x4, x4, x7\n\t"
        "#  A[4] * B[2]\n\t"
        "mul	x7, x13, x17\n\t"
        "adcs	x5, x5, x8\n\t"
        "umulh	x8, x13, x17\n\t"
        "adc	x6, x6, xzr\n\t"
        "adds	x4, x4, x7\n\t"
        "#  A[5] * B[1]\n\t"
        "mul	x7, x14, x16\n\t"
        "adcs	x5, x5, x8\n\t"
        "umulh	x8, x14, x16\n\t"
        "adc	x6, x6, xzr\n\t"
        "adds	x4, x4, x7\n\t"
        "adcs	x5, x5, x8\n\t"
        "str	x4, [%[r], 48]\n\t"
        "adc	x6, x6, xzr\n\t"
        "#  A[2] * B[5]\n\t"
        "mul	x7, x11, x21\n\t"
        "umulh	x8, x11, x21\n\t"
        "adds	x5, x5, x7\n\t"
        "#  A[3] * B[4]\n\t"
        "mul	x7, x12, x20\n\t"
        "adcs	x6, x6, x8\n\t"
        "umulh	x8, x12, x20\n\t"
        "adc	x4, xzr, xzr\n\t"
        "adds	x5, x5, x7\n\t"
        "#  A[4] * B[3]\n\t"
        "mul	x7, x13, x19\n\t"
        "adcs	x6, x6, x8\n\t"
        "umulh	x8, x13, x19\n\t"
        "adc	x4, x4, xzr\n\t"
        "adds	x5, x5, x7\n\t"
        "#  A[5] * B[2]\n\t"
        "mul	x7, x14, x17\n\t"
        "adcs	x6, x6, x8\n\t"
        "umulh	x8, x14, x17\n\t"
        "adc	x4, x4, xzr\n\t"
        "adds	x5, x5, x7\n\t"
        "adcs	x6, x6, x8\n\t"
        "str	x5, [%[r], 56]\n\t"
        "adc	x4, x4, xzr\n\t"
        "#  A[3] * B[5]\n\t"
        "mul	x7, x12, x21\n\t"
        "umulh	x8, x12, x21\n\t"
        "adds	x6, x6, x7\n\t"
        "#  A[4] * B[4]\n\t"
        "mul	x7, x13, x20\n\t"
        "adcs	x4, x4, x8\n\t"
        "umulh	x8, x13, x20\n\t"
        "adc	x5, xzr, xzr\n\t"
        "adds	x6, x6, x7\n\t"
        "#  A[5] * B[3]\n\t"
        "mul	x7, x14, x19\n\t"
        "adcs	x4, x4, x8\n\t"
        "umulh	x8, x14, x19\n\t"
        "adc	x5, x5, xzr\n\t"
        "adds	x6, x6, x7\n\t"
        "adcs	x4, x4, x8\n\t"
        "str	x6, [%[r], 64]\n\t"
        "adc	x5, x5, xzr\n\t"
        "#  A[4] * B[5]\n\t"
        "mul	x7, x13, x21\n\t"
        "umulh	x8, x13, x21\n\t"
        "adds	x4, x4, x7\n\t"
        "#  A[5] * B[4]\n\t"
        "mul	x7, x14, x20\n\t"
        "adcs	x5, x5, x8\n\t"
        "umulh	x8, x14, x20\n\t"
        "adc	x6, xzr, xzr\n\t"
        "adds	x4, x4, x7\n\t"
        "adcs	x5, x5, x8\n\t"
        "str	x4, [%[r], 72]\n\t"
        "adc	x6, x6, xzr\n\t"
        "#  A[5] * B[5]\n\t"
        "mul	x7, x14, x21\n\t"
        "umulh	x8, x14, x21\n\t"
        "adds	x5, x5, x7\n\t"
        "adc	x6, x6, x8\n\t"
        "stp	x5, x6, [%[r], 80]\n\t"
        "ldp	x9, x10, [%[tmp], 0]\n\t"
        "ldp	x11, x12, [%[tmp], 16]\n\t"
        "ldp	x13, x14, [%[tmp], 32]\n\t"
        "stp	x9, x10, [%[r], 0]\n\t"
        "stp	x11, x12, [%[r], 16]\n\t"
        "stp	x13, x14, [%[r], 32]\n\t"
        :
        : [r] "r" (r), [a] "r" (a), [b] "r" (b), [tmp] "r" (tmp)
        : "memory", "x4", "x5", "x6", "x7", "x8", "x9", "x9", "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17", "x19", "x20", "x21"
    );
}

#endif /* WOLFSSL_SP_SMALL */
/* Conditionally subtract b from a using the mask m.
 * m is -1 to subtract and 0 when not copying.
 *
 * r  A single precision number representing condition subtract result.
 * a  A single precision number to subtract from.
 * b  A single precision number to subtract.
 * m  Mask value to apply.
 */
static sp_digit sp_384_cond_sub_6(sp_digit* r, const sp_digit* a, const sp_digit* b,
        sp_digit m)
{
    __asm__ __volatile__ (

        "ldp	x5, x7, [%[b], 0]\n\t"
        "ldp	x11, x12, [%[b], 16]\n\t"
        "ldp	x4, x6, [%[a], 0]\n\t"
        "and	x5, x5, %[m]\n\t"
        "ldp	x9, x10, [%[a], 16]\n\t"
        "and	x7, x7, %[m]\n\t"
        "subs	x4, x4, x5\n\t"
        "and	x11, x11, %[m]\n\t"
        "sbcs	x6, x6, x7\n\t"
        "and	x12, x12, %[m]\n\t"
        "sbcs	x9, x9, x11\n\t"
        "stp	x4, x6, [%[r], 0]\n\t"
        "sbcs	x10, x10, x12\n\t"
        "stp	x9, x10, [%[r], 16]\n\t"
        "ldp	x5, x7, [%[b], 32]\n\t"
        "ldp	x4, x6, [%[a], 32]\n\t"
        "and	x5, x5, %[m]\n\t"
        "and	x7, x7, %[m]\n\t"
        "sbcs	x4, x4, x5\n\t"
        "sbcs	x6, x6, x7\n\t"
        "stp	x4, x6, [%[r], 32]\n\t"
        "csetm	%[r], cc\n\t"
        : [r] "+r" (r)
        : [a] "r" (a), [b] "r" (b), [m] "r" (m)
        : "memory", "x4", "x6", "x5", "x7", "x8", "x9", "x10", "x11", "x12"
    );

    return (sp_digit)r;
}

#define sp_384_mont_reduce_order_6    sp_384_mont_reduce_6

/* Reduce the number back to 384 bits using Montgomery reduction.
 *
 * a   A single precision number to reduce in place.
 * m   The single precision number representing the modulus.
 * mp  The digit representing the negative inverse of m mod 2^n.
 */
SP_NOINLINE static void sp_384_mont_reduce_6(sp_digit* a, const sp_digit* m,
        sp_digit mp)
{
    sp_digit ca = 0;

    __asm__ __volatile__ (
        "ldp	x14, x15, [%[m], 0]\n\t"
        "ldp	x16, x17, [%[m], 16]\n\t"
        "ldp	x19, x20, [%[m], 32]\n\t"
        "# i = 6\n\t"
        "mov	x4, 6\n\t"
        "ldp	x12, x13, [%[a], 0]\n\t"
        "\n1:\n\t"
        "# mu = a[i] * mp\n\t"
        "mul	x9, %[mp], x12\n\t"
        "# a[i+0] += m[0] * mu\n\t"
        "mul	x7, x14, x9\n\t"
        "umulh	x8, x14, x9\n\t"
        "adds	x12, x12, x7\n\t"
        "# a[i+1] += m[1] * mu\n\t"
        "mul	x7, x15, x9\n\t"
        "adc	x6, x8, xzr\n\t"
        "umulh	x8, x15, x9\n\t"
        "adds	x12, x13, x7\n\t"
        "# a[i+2] += m[2] * mu\n\t"
        "ldr	x13, [%[a], 16]\n\t"
        "adc	x5, x8, xzr\n\t"
        "mul	x7, x16, x9\n\t"
        "adds	x12, x12, x6\n\t"
        "umulh	x8, x16, x9\n\t"
        "adc	x5, x5, xzr\n\t"
        "adds	x13, x13, x7\n\t"
        "# a[i+3] += m[3] * mu\n\t"
        "ldr	x10, [%[a], 24]\n\t"
        "adc	x6, x8, xzr\n\t"
        "mul	x7, x17, x9\n\t"
        "adds	x13, x13, x5\n\t"
        "umulh	x8, x17, x9\n\t"
        "adc	x6, x6, xzr\n\t"
        "adds	x10, x10, x7\n\t"
        "# a[i+4] += m[4] * mu\n\t"
        "ldr	x11, [%[a], 32]\n\t"
        "adc	x5, x8, xzr\n\t"
        "adds	x10, x10, x6\n\t"
        "mul	x7, x19, x9\n\t"
        "adc	x5, x5, xzr\n\t"
        "umulh	x8, x19, x9\n\t"
        "str	x10, [%[a], 24]\n\t"
        "adds	x11, x11, x7\n\t"
        "# a[i+5] += m[5] * mu\n\t"
        "ldr	x10, [%[a], 40]\n\t"
        "adc	x6, x8, xzr\n\t"
        "adds	x11, x11, x5\n\t"
        "mul	x7, x20, x9\n\t"
        "adc	x6, x6, xzr\n\t"
        "umulh	x8, x20, x9\n\t"
        "adds	x6, x6, x7\n\t"
        "adcs	x8, x8, %[ca]\n\t"
        "str	x11, [%[a], 32]\n\t"
        "cset  %[ca], cs\n\t"
        "adds	x10, x10, x6\n\t"
        "ldr	x11, [%[a], 48]\n\t"
        "str	x10, [%[a], 40]\n\t"
        "adcs	x11, x11, x8\n\t"
        "str	x11, [%[a], 48]\n\t"
        "adc	%[ca], %[ca], xzr\n\t"
        "subs	x4, x4, 1\n\t"
        "add	%[a], %[a], 8\n\t"
        "bne	1b\n\t"
        "stp	x12, x13, [%[a], 0]\n\t"
        : [ca] "+r" (ca), [a] "+r" (a)
        : [m] "r" (m), [mp] "r" (mp)
        : "memory", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17", "x19", "x20"
    );

    sp_384_cond_sub_6(a - 6, a, m, (sp_digit)0 - ca);
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
static void sp_384_mont_mul_6(sp_digit* r, const sp_digit* a, const sp_digit* b,
        const sp_digit* m, sp_digit mp)
{
    sp_384_mul_6(r, a, b);
    sp_384_mont_reduce_6(r, m, mp);
}

#ifdef WOLFSSL_SP_SMALL
/* Square a and put result in r. (r = a * a)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 */
static void sp_384_sqr_6(sp_digit* r, const sp_digit* a)
{
    sp_digit tmp[12];

    __asm__ __volatile__ (
        "mov	x6, 0\n\t"
        "mov	x7, 0\n\t"
        "mov	x8, 0\n\t"
        "mov	x5, 0\n\t"
        "\n1:\n\t"
        "subs	x3, x5, 40\n\t"
        "csel	x3, xzr, x3, cc\n\t"
        "sub	x4, x5, x3\n\t"
        "\n2:\n\t"
        "cmp	x4, x3\n\t"
        "b.eq	4f\n\t"
        "ldr	x10, [%[a], x3]\n\t"
        "ldr	x11, [%[a], x4]\n\t"
        "mul	x9, x10, x11\n\t"
        "umulh	x10, x10, x11\n\t"
        "adds	x6, x6, x9\n\t"
        "adcs	x7, x7, x10\n\t"
        "adc	x8, x8, xzr\n\t"
        "adds	x6, x6, x9\n\t"
        "adcs	x7, x7, x10\n\t"
        "adc	x8, x8, xzr\n\t"
        "b.al	5f\n\t"
        "\n4:\n\t"
        "ldr	x10, [%[a], x3]\n\t"
        "mul	x9, x10, x10\n\t"
        "umulh	x10, x10, x10\n\t"
        "adds	x6, x6, x9\n\t"
        "adcs	x7, x7, x10\n\t"
        "adc	x8, x8, xzr\n\t"
        "\n5:\n\t"
        "add	x3, x3, #8\n\t"
        "sub	x4, x4, #8\n\t"
        "cmp	x3, 48\n\t"
        "b.eq	3f\n\t"
        "cmp	x3, x4\n\t"
        "b.gt	3f\n\t"
        "cmp	x3, x5\n\t"
        "b.le	2b\n\t"
        "\n3:\n\t"
        "str	x6, [%[r], x5]\n\t"
        "mov	x6, x7\n\t"
        "mov	x7, x8\n\t"
        "mov	x8, #0\n\t"
        "add	x5, x5, #8\n\t"
        "cmp	x5, 80\n\t"
        "b.le	1b\n\t"
        "str	x6, [%[r], x5]\n\t"
        :
        : [r] "r" (tmp), [a] "r" (a)
        : "memory", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11"
    );

    XMEMCPY(r, tmp, sizeof(tmp));
}

#else
/* Square a and put result in r. (r = a * a)
 *
 * All registers version.
 *
 * r  A single precision integer.
 * a  A single precision integer.
 */
static void sp_384_sqr_6(sp_digit* r, const sp_digit* a)
{
    __asm__ __volatile__ (
        "ldp       x16, x17, [%[a], 0]\n\t"
        "ldp       x19, x20, [%[a], 16]\n\t"
        "ldp       x21, x22, [%[a], 32]\n\t"
        "#  A[0] * A[1]\n\t"
        "mul	x6, x16, x17\n\t"
        "umulh	x7, x16, x17\n\t"
        "#  A[0] * A[2]\n\t"
        "mul	x4, x16, x19\n\t"
        "umulh	x5, x16, x19\n\t"
        "adds	x7, x7, x4\n\t"
        "#  A[0] * A[3]\n\t"
        "mul	x4, x16, x20\n\t"
        "adc	x8, xzr, x5\n\t"
        "umulh	x5, x16, x20\n\t"
        "adds	x8, x8, x4\n\t"
        "#  A[1] * A[2]\n\t"
        "mul	x4, x17, x19\n\t"
        "adc	x9, xzr, x5\n\t"
        "umulh	x5, x17, x19\n\t"
        "adds	x8, x8, x4\n\t"
        "#  A[0] * A[4]\n\t"
        "mul	x4, x16, x21\n\t"
        "adcs	x9, x9, x5\n\t"
        "umulh	x5, x16, x21\n\t"
        "adc	x10, xzr, xzr\n\t"
        "adds	x9, x9, x4\n\t"
        "#  A[1] * A[3]\n\t"
        "mul	x4, x17, x20\n\t"
        "adc	x10, x10, x5\n\t"
        "umulh	x5, x17, x20\n\t"
        "adds	x9, x9, x4\n\t"
        "#  A[0] * A[5]\n\t"
        "mul	x4, x16, x22\n\t"
        "adcs	x10, x10, x5\n\t"
        "umulh	x5, x16, x22\n\t"
        "adc	x11, xzr, xzr\n\t"
        "adds	x10, x10, x4\n\t"
        "#  A[1] * A[4]\n\t"
        "mul	x4, x17, x21\n\t"
        "adc	x11, x11, x5\n\t"
        "umulh	x5, x17, x21\n\t"
        "adds	x10, x10, x4\n\t"
        "#  A[2] * A[3]\n\t"
        "mul	x4, x19, x20\n\t"
        "adcs	x11, x11, x5\n\t"
        "umulh	x5, x19, x20\n\t"
        "adc	x12, xzr, xzr\n\t"
        "adds	x10, x10, x4\n\t"
        "#  A[1] * A[5]\n\t"
        "mul	x4, x17, x22\n\t"
        "adcs	x11, x11, x5\n\t"
        "umulh	x5, x17, x22\n\t"
        "adc	x12, x12, xzr\n\t"
        "adds	x11, x11, x4\n\t"
        "#  A[2] * A[4]\n\t"
        "mul	x4, x19, x21\n\t"
        "adcs	x12, x12, x5\n\t"
        "umulh	x5, x19, x21\n\t"
        "adc	x13, xzr, xzr\n\t"
        "adds	x11, x11, x4\n\t"
        "#  A[2] * A[5]\n\t"
        "mul	x4, x19, x22\n\t"
        "adcs	x12, x12, x5\n\t"
        "umulh	x5, x19, x22\n\t"
        "adc	x13, x13, xzr\n\t"
        "adds	x12, x12, x4\n\t"
        "#  A[3] * A[4]\n\t"
        "mul	x4, x20, x21\n\t"
        "adcs	x13, x13, x5\n\t"
        "umulh	x5, x20, x21\n\t"
        "adc	x14, xzr, xzr\n\t"
        "adds	x12, x12, x4\n\t"
        "#  A[3] * A[5]\n\t"
        "mul	x4, x20, x22\n\t"
        "adcs	x13, x13, x5\n\t"
        "umulh	x5, x20, x22\n\t"
        "adc	x14, x14, xzr\n\t"
        "adds	x13, x13, x4\n\t"
        "#  A[4] * A[5]\n\t"
        "mul	x4, x21, x22\n\t"
        "adcs	x14, x14, x5\n\t"
        "umulh	x5, x21, x22\n\t"
        "adc	x15, xzr, xzr\n\t"
        "adds	x14, x14, x4\n\t"
        "adc	x15, x15, x5\n\t"
        "# Double\n\t"
        "adds	x6, x6, x6\n\t"
        "adcs	x7, x7, x7\n\t"
        "adcs	x8, x8, x8\n\t"
        "adcs	x9, x9, x9\n\t"
        "adcs	x10, x10, x10\n\t"
        "adcs	x11, x11, x11\n\t"
        "adcs	x12, x12, x12\n\t"
        "adcs	x13, x13, x13\n\t"
        "adcs	x14, x14, x14\n\t"
        "#  A[0] * A[0]\n\t"
        "mul	x5, x16, x16\n\t"
        "adcs	x15, x15, x15\n\t"
        "umulh	x2, x16, x16\n\t"
        "cset  x16, cs\n\t"
        "#  A[1] * A[1]\n\t"
        "mul	x3, x17, x17\n\t"
        "adds	x6, x6, x2\n\t"
        "umulh	x4, x17, x17\n\t"
        "adcs	x7, x7, x3\n\t"
        "#  A[2] * A[2]\n\t"
        "mul	x2, x19, x19\n\t"
        "adcs	x8, x8, x4\n\t"
        "umulh	x3, x19, x19\n\t"
        "adcs	x9, x9, x2\n\t"
        "#  A[3] * A[3]\n\t"
        "mul	x4, x20, x20\n\t"
        "adcs	x10, x10, x3\n\t"
        "umulh	x2, x20, x20\n\t"
        "adcs	x11, x11, x4\n\t"
        "#  A[4] * A[4]\n\t"
        "mul	x3, x21, x21\n\t"
        "adcs	x12, x12, x2\n\t"
        "umulh	x4, x21, x21\n\t"
        "adcs	x13, x13, x3\n\t"
        "#  A[5] * A[5]\n\t"
        "mul	x2, x22, x22\n\t"
        "adcs	x14, x14, x4\n\t"
        "umulh	x3, x22, x22\n\t"
        "adcs	x15, x15, x2\n\t"
        "stp	x5, x6, [%[r], 0]\n\t"
        "adc	x16, x16, x3\n\t"
        "stp	x7, x8, [%[r], 16]\n\t"
        "stp	x9, x10, [%[r], 32]\n\t"
        "stp	x11, x12, [%[r], 48]\n\t"
        "stp	x13, x14, [%[r], 64]\n\t"
        "stp	x15, x16, [%[r], 80]\n\t"
        :
        : [r] "r" (r), [a] "r" (a)
        : "memory", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x16", "x17", "x19", "x20", "x21", "x22"
    );
}

#endif /* WOLFSSL_SP_SMALL */
/* Square the Montgomery form number. (r = a * a mod m)
 *
 * r   Result of squaring.
 * a   Number to square in Montogmery form.
 * m   Modulus (prime).
 * mp  Montogmery mulitplier.
 */
static void sp_384_mont_sqr_6(sp_digit* r, const sp_digit* a, const sp_digit* m,
        sp_digit mp)
{
    sp_384_sqr_6(r, a);
    sp_384_mont_reduce_6(r, m, mp);
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
static void sp_384_mont_sqr_n_6(sp_digit* r, const sp_digit* a, int n,
        const sp_digit* m, sp_digit mp)
{
    sp_384_mont_sqr_6(r, a, m, mp);
    for (; n > 1; n--) {
        sp_384_mont_sqr_6(r, r, m, mp);
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
static void sp_384_mont_inv_6(sp_digit* r, const sp_digit* a, sp_digit* td)
{
#ifdef WOLFSSL_SP_SMALL
    sp_digit* t = td;
    int i;

    XMEMCPY(t, a, sizeof(sp_digit) * 6);
    for (i=382; i>=0; i--) {
        sp_384_mont_sqr_6(t, t, p384_mod, p384_mp_mod);
        if (p384_mod_minus_2[i / 64] & ((sp_digit)1 << (i % 64)))
            sp_384_mont_mul_6(t, t, a, p384_mod, p384_mp_mod);
    }
    XMEMCPY(r, t, sizeof(sp_digit) * 6);
#else
    sp_digit* t1 = td;
    sp_digit* t2 = td + 2 * 6;
    sp_digit* t3 = td + 4 * 6;
    sp_digit* t4 = td + 6 * 6;
    sp_digit* t5 = td + 8 * 6;

    /* 0x2 */
    sp_384_mont_sqr_6(t1, a, p384_mod, p384_mp_mod);
    /* 0x3 */
    sp_384_mont_mul_6(t5, t1, a, p384_mod, p384_mp_mod);
    /* 0xc */
    sp_384_mont_sqr_n_6(t1, t5, 2, p384_mod, p384_mp_mod);
    /* 0xf */
    sp_384_mont_mul_6(t2, t5, t1, p384_mod, p384_mp_mod);
    /* 0x1e */
    sp_384_mont_sqr_6(t1, t2, p384_mod, p384_mp_mod);
    /* 0x1f */
    sp_384_mont_mul_6(t4, t1, a, p384_mod, p384_mp_mod);
    /* 0x3e0 */
    sp_384_mont_sqr_n_6(t1, t4, 5, p384_mod, p384_mp_mod);
    /* 0x3ff */
    sp_384_mont_mul_6(t2, t4, t1, p384_mod, p384_mp_mod);
    /* 0x7fe0 */
    sp_384_mont_sqr_n_6(t1, t2, 5, p384_mod, p384_mp_mod);
    /* 0x7fff */
    sp_384_mont_mul_6(t4, t4, t1, p384_mod, p384_mp_mod);
    /* 0x3fff8000 */
    sp_384_mont_sqr_n_6(t1, t4, 15, p384_mod, p384_mp_mod);
    /* 0x3fffffff */
    sp_384_mont_mul_6(t2, t4, t1, p384_mod, p384_mp_mod);
    /* 0xfffffffc */
    sp_384_mont_sqr_n_6(t3, t2, 2, p384_mod, p384_mp_mod);
    /* 0xfffffffd */
    sp_384_mont_mul_6(r, t3, a, p384_mod, p384_mp_mod);
    /* 0xffffffff */
    sp_384_mont_mul_6(t3, t5, t3, p384_mod, p384_mp_mod);
    /* 0xfffffffc0000000 */
    sp_384_mont_sqr_n_6(t1, t2, 30, p384_mod, p384_mp_mod);
    /* 0xfffffffffffffff */
    sp_384_mont_mul_6(t2, t2, t1, p384_mod, p384_mp_mod);
    /* 0xfffffffffffffff000000000000000 */
    sp_384_mont_sqr_n_6(t1, t2, 60, p384_mod, p384_mp_mod);
    /* 0xffffffffffffffffffffffffffffff */
    sp_384_mont_mul_6(t2, t2, t1, p384_mod, p384_mp_mod);
    /* 0xffffffffffffffffffffffffffffff000000000000000000000000000000 */
    sp_384_mont_sqr_n_6(t1, t2, 120, p384_mod, p384_mp_mod);
    /* 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff */
    sp_384_mont_mul_6(t2, t2, t1, p384_mod, p384_mp_mod);
    /* 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff8000 */
    sp_384_mont_sqr_n_6(t1, t2, 15, p384_mod, p384_mp_mod);
    /* 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff */
    sp_384_mont_mul_6(t2, t4, t1, p384_mod, p384_mp_mod);
    /* 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe00000000 */
    sp_384_mont_sqr_n_6(t1, t2, 33, p384_mod, p384_mp_mod);
    /* 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff */
    sp_384_mont_mul_6(t2, t3, t1, p384_mod, p384_mp_mod);
    /* 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff000000000000000000000000 */
    sp_384_mont_sqr_n_6(t1, t2, 96, p384_mod, p384_mp_mod);
    /* 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffd */
    sp_384_mont_mul_6(r, r, t1, p384_mod, p384_mp_mod);

#endif /* WOLFSSL_SP_SMALL */
}

/* Compare a with b in constant time.
 *
 * a  A single precision integer.
 * b  A single precision integer.
 * return -ve, 0 or +ve if a is less than, equal to or greater than b
 * respectively.
 */
static int64_t sp_384_cmp_6(const sp_digit* a, const sp_digit* b)
{
#ifdef WOLFSSL_SP_SMALL
    __asm__ __volatile__ (
        "mov	x2, -1\n\t"
        "mov	x3, 1\n\t"
        "mov	x4, -1\n\t"
        "mov	x5, 40\n\t"
        "1:\n\t"
        "ldr	x6, [%[a], x5]\n\t"
        "ldr	x7, [%[b], x5]\n\t"
        "and	x6, x6, x4\n\t"
        "and	x7, x7, x4\n\t"
        "subs	x6, x6, x7\n\t"
        "csel	x2, x3, x2, hi\n\t"
        "csel	x2, x4, x2, lo\n\t"
        "csel	x4, x4, xzr, eq\n\t"
        "subs	x5, x5, #8\n\t"
        "b.cs	1b\n\t"
        "eor	%[a], x2, x4\n\t"
        : [a] "+r" (a)
        : [b] "r" (b)
        : "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15", "x16"
    );
#else
    __asm__ __volatile__ (
        "mov	x2, -1\n\t"
        "mov	x3, 1\n\t"
        "mov	x4, -1\n\t"
        "ldp	x5, x6, [%[a], 0]\n\t"
        "ldp	x7, x8, [%[a], 16]\n\t"
        "ldp	x9, x10, [%[a], 32]\n\t"
        "ldp	x11, x12, [%[b], 0]\n\t"
        "ldp	x13, x14, [%[b], 16]\n\t"
        "ldp	x15, x16, [%[b], 32]\n\t"
        "and	x10, x10, x4\n\t"
        "and	x16, x16, x4\n\t"
        "subs	x10, x10, x16\n\t"
        "csel	x2, x4, x2, lo\n\t"
        "csel	x4, x4, xzr, eq\n\t"
        "csel	x2, x3, x2, hi\n\t"
        "and	x9, x9, x4\n\t"
        "and	x15, x15, x4\n\t"
        "subs	x9, x9, x15\n\t"
        "csel	x2, x4, x2, lo\n\t"
        "csel	x4, x4, xzr, eq\n\t"
        "csel	x2, x3, x2, hi\n\t"
        "and	x8, x8, x4\n\t"
        "and	x14, x14, x4\n\t"
        "subs	x8, x8, x14\n\t"
        "csel	x2, x4, x2, lo\n\t"
        "csel	x4, x4, xzr, eq\n\t"
        "csel	x2, x3, x2, hi\n\t"
        "and	x7, x7, x4\n\t"
        "and	x13, x13, x4\n\t"
        "subs	x7, x7, x13\n\t"
        "csel	x2, x4, x2, lo\n\t"
        "csel	x4, x4, xzr, eq\n\t"
        "csel	x2, x3, x2, hi\n\t"
        "and	x6, x6, x4\n\t"
        "and	x12, x12, x4\n\t"
        "subs	x6, x6, x12\n\t"
        "csel	x2, x4, x2, lo\n\t"
        "csel	x4, x4, xzr, eq\n\t"
        "csel	x2, x3, x2, hi\n\t"
        "and	x5, x5, x4\n\t"
        "and	x11, x11, x4\n\t"
        "subs	x5, x5, x11\n\t"
        "csel	x2, x4, x2, lo\n\t"
        "csel	x4, x4, xzr, eq\n\t"
        "csel	x2, x3, x2, hi\n\t"
        "eor	%[a], x2, x4\n\t"
        : [a] "+r" (a)
        : [b] "r" (b)
        : "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15", "x16"
    );
#endif

    return (int64_t)a;
}

/* Normalize the values in each word to 64.
 *
 * a  Array of sp_digit to normalize.
 */
#define sp_384_norm_6(a)

/* Map the Montgomery form projective coordinate point to an affine point.
 *
 * r  Resulting affine coordinate point.
 * p  Montgomery form projective coordinate point.
 * t  Temporary ordinate data.
 */
static void sp_384_map_6(sp_point_384* r, const sp_point_384* p, sp_digit* t)
{
    sp_digit* t1 = t;
    sp_digit* t2 = t + 2*6;
    int64_t n;

    sp_384_mont_inv_6(t1, p->z, t + 2*6);

    sp_384_mont_sqr_6(t2, t1, p384_mod, p384_mp_mod);
    sp_384_mont_mul_6(t1, t2, t1, p384_mod, p384_mp_mod);

    /* x /= z^2 */
    sp_384_mont_mul_6(r->x, p->x, t2, p384_mod, p384_mp_mod);
    XMEMSET(r->x + 6, 0, sizeof(r->x) / 2U);
    sp_384_mont_reduce_6(r->x, p384_mod, p384_mp_mod);
    /* Reduce x to less than modulus */
    n = sp_384_cmp_6(r->x, p384_mod);
    sp_384_cond_sub_6(r->x, r->x, p384_mod, 0 - ((n >= 0) ?
                (sp_digit)1 : (sp_digit)0));
    sp_384_norm_6(r->x);

    /* y /= z^3 */
    sp_384_mont_mul_6(r->y, p->y, t1, p384_mod, p384_mp_mod);
    XMEMSET(r->y + 6, 0, sizeof(r->y) / 2U);
    sp_384_mont_reduce_6(r->y, p384_mod, p384_mp_mod);
    /* Reduce y to less than modulus */
    n = sp_384_cmp_6(r->y, p384_mod);
    sp_384_cond_sub_6(r->y, r->y, p384_mod, 0 - ((n >= 0) ?
                (sp_digit)1 : (sp_digit)0));
    sp_384_norm_6(r->y);

    XMEMSET(r->z, 0, sizeof(r->z));
    r->z[0] = 1;

}

/* Add b to a into r. (r = a + b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
static sp_digit sp_384_add_6(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    __asm__ __volatile__ (
        "ldp	x3, x4, [%[a], 0]\n\t"
        "ldp	x7, x8, [%[b], 0]\n\t"
        "adds	x3, x3, x7\n\t"
        "ldp	x5, x6, [%[a], 16]\n\t"
        "adcs	x4, x4, x8\n\t"
        "ldp	x9, x10, [%[b], 16]\n\t"
        "adcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r], 0]\n\t"
        "adcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r], 16]\n\t"
        "ldr		x3, [%[a], 32]\n\t"
        "ldr		x4, [%[a], 40]\n\t"
        "ldr		x7, [%[b], 32]\n\t"
        "ldr		x8, [%[b], 40]\n\t"
        "adcs	x3, x3, x7\n\t"
        "adcs	x4, x4, x8\n\t"
        "str		x3, [%[r], 32]\n\t"
        "str		x4, [%[r], 40]\n\t"
        "cset	%[r], cs\n\t"
        : [r] "+r" (r)
        : [a] "r" (a), [b] "r" (b)
        : "memory", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10"
    );

    return (sp_digit)r;
}

/* Add two Montgomery form numbers (r = a + b % m).
 *
 * r   Result of addition.
 * a   First number to add in Montogmery form.
 * b   Second number to add in Montogmery form.
 * m   Modulus (prime).
 */
static void sp_384_mont_add_6(sp_digit* r, const sp_digit* a, const sp_digit* b,
        const sp_digit* m)
{
    sp_digit o;

    o = sp_384_add_6(r, a, b);
    sp_384_cond_sub_6(r, r, m, 0 - o);
}

/* Double a Montgomery form number (r = a + a % m).
 *
 * r   Result of doubling.
 * a   Number to double in Montogmery form.
 * m   Modulus (prime).
 */
static void sp_384_mont_dbl_6(sp_digit* r, const sp_digit* a, const sp_digit* m)
{
    sp_digit o;

    o = sp_384_add_6(r, a, a);
    sp_384_cond_sub_6(r, r, m, 0 - o);
}

/* Triple a Montgomery form number (r = a + a + a % m).
 *
 * r   Result of Tripling.
 * a   Number to triple in Montogmery form.
 * m   Modulus (prime).
 */
static void sp_384_mont_tpl_6(sp_digit* r, const sp_digit* a, const sp_digit* m)
{
    sp_digit o;

    o = sp_384_add_6(r, a, a);
    sp_384_cond_sub_6(r, r, m, 0 - o);
    o = sp_384_add_6(r, r, a);
    sp_384_cond_sub_6(r, r, m, 0 - o);
}

/* Sub b from a into r. (r = a - b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision integer.
 */
static sp_digit sp_384_sub_6(sp_digit* r, const sp_digit* a,
        const sp_digit* b)
{
    __asm__ __volatile__ (
        "ldp	x3, x4, [%[a], 0]\n\t"
        "ldp	x7, x8, [%[b], 0]\n\t"
        "subs	x3, x3, x7\n\t"
        "ldp	x5, x6, [%[a], 16]\n\t"
        "sbcs	x4, x4, x8\n\t"
        "ldp	x9, x10, [%[b], 16]\n\t"
        "sbcs	x5, x5, x9\n\t"
        "stp	x3, x4, [%[r], 0]\n\t"
        "sbcs	x6, x6, x10\n\t"
        "stp	x5, x6, [%[r], 16]\n\t"
        "ldr		x3, [%[a], 32]\n\t"
        "ldr		x4, [%[a], 40]\n\t"
        "ldr		x7, [%[b], 32]\n\t"
        "ldr		x8, [%[b], 40]\n\t"
        "sbcs	x3, x3, x7\n\t"
        "sbcs	x4, x4, x8\n\t"
        "str		x3, [%[r], 32]\n\t"
        "str		x4, [%[r], 40]\n\t"
        "csetm	%[r], cc\n\t"
        : [r] "+r" (r)
        : [a] "r" (a), [b] "r" (b)
        : "memory", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10"
    );

    return (sp_digit)r;
}

/* Conditionally add a and b using the mask m.
 * m is -1 to add and 0 when not.
 *
 * r  A single precision number representing conditional add result.
 * a  A single precision number to add with.
 * b  A single precision number to add.
 * m  Mask value to apply.
 */
static sp_digit sp_384_cond_add_6(sp_digit* r, const sp_digit* a, const sp_digit* b,
        sp_digit m)
{
#ifdef WOLFSSL_SP_SMALL
    sp_digit c = 0;

    __asm__ __volatile__ (
        "mov	x8, #0\n\t"
        "1:\n\t"
        "adds	%[c], %[c], #-1\n\t"
        "ldr	x4, [%[a], x8]\n\t"
        "ldr	x5, [%[b], x8]\n\t"
        "and	x5, x5, %[m]\n\t"
        "adcs	x4, x4, x5\n\t"
        "cset	%[c], cs\n\t"
        "str	x4, [%[r], x8]\n\t"
        "add	x8, x8, #8\n\t"
        "cmp	x8, 48\n\t"
        "b.lt	1b\n\t"
        : [c] "+r" (c)
        : [r] "r" (r), [a] "r" (a), [b] "r" (b), [m] "r" (m)
        : "memory", "x4", "x6", "x5", "x7", "x8", "x9", "x10", "x11", "x12"
    );

    return c;
#else
    __asm__ __volatile__ (

        "ldp	x5, x7, [%[b], 0]\n\t"
        "ldp	x11, x12, [%[b], 16]\n\t"
        "ldp	x4, x6, [%[a], 0]\n\t"
        "and	x5, x5, %[m]\n\t"
        "ldp	x9, x10, [%[a], 16]\n\t"
        "and	x7, x7, %[m]\n\t"
        "adds	x4, x4, x5\n\t"
        "and	x11, x11, %[m]\n\t"
        "adcs	x6, x6, x7\n\t"
        "and	x12, x12, %[m]\n\t"
        "adcs	x9, x9, x11\n\t"
        "stp	x4, x6, [%[r], 0]\n\t"
        "adcs	x10, x10, x12\n\t"
        "stp	x9, x10, [%[r], 16]\n\t"
        "ldp	x5, x7, [%[b], 32]\n\t"
        "ldp	x4, x6, [%[a], 32]\n\t"
        "and	x5, x5, %[m]\n\t"
        "and	x7, x7, %[m]\n\t"
        "adcs	x4, x4, x5\n\t"
        "adcs	x6, x6, x7\n\t"
        "stp	x4, x6, [%[r], 32]\n\t"
        "cset	%[r], cs\n\t"
        : [r] "+r" (r)
        : [a] "r" (a), [b] "r" (b), [m] "r" (m)
        : "memory", "x4", "x6", "x5", "x7", "x8", "x9", "x10", "x11", "x12"
    );

    return (sp_digit)r;
#endif /* WOLFSSL_SP_SMALL */
}

/* Subtract two Montgomery form numbers (r = a - b % m).
 *
 * r   Result of subtration.
 * a   Number to subtract from in Montogmery form.
 * b   Number to subtract with in Montogmery form.
 * m   Modulus (prime).
 */
static void sp_384_mont_sub_6(sp_digit* r, const sp_digit* a, const sp_digit* b,
        const sp_digit* m)
{
    sp_digit o;

    o = sp_384_sub_6(r, a, b);
    sp_384_cond_add_6(r, r, m, o);
}

static void sp_384_rshift1_6(sp_digit* r, sp_digit* a)
{
    __asm__ __volatile__ (
        "ldp	x2, x3, [%[a]]\n\t"
        "ldp	x4, x5, [%[a], 16]\n\t"
        "ldp	x6, x7, [%[a], 32]\n\t"
        "lsr	x11, x6, 1\n\t"
        "lsr	x10, x5, 1\n\t"
        "lsr	x9, x4, 1\n\t"
        "lsr	x8, x3, 1\n\t"
        "lsr	x2, x2, 1\n\t"
        "orr	x2, x2, x3, lsl 63\n\t"
        "orr	x3, x8, x4, lsl 63\n\t"
        "orr	x4, x9, x5, lsl 63\n\t"
        "orr	x5, x10, x6, lsl 63\n\t"
        "orr	x6, x11, x7, lsl 63\n\t"
        "lsr	x7, x7, 1\n\t"
        "stp	x2, x3, [%[r]]\n\t"
        "stp	x4, x5, [%[r], 16]\n\t"
        "stp	x6, x7, [%[r], 32]\n\t"
        :
        : [r] "r" (r), [a] "r" (a)
        : "memory", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11"
    );
}

/* Divide the number by 2 mod the modulus (prime). (r = a / 2 % m)
 *
 * r  Result of division by 2.
 * a  Number to divide.
 * m  Modulus (prime).
 */
static void sp_384_div2_6(sp_digit* r, const sp_digit* a, const sp_digit* m)
{
    sp_digit o;

    o = sp_384_cond_add_6(r, a, m, 0 - (a[0] & 1));
    sp_384_rshift1_6(r, r);
    r[5] |= o << 63;
}

/* Double the Montgomery form projective point p.
 *
 * r  Result of doubling point.
 * p  Point to double.
 * t  Temporary ordinate data.
 */

static void sp_384_proj_point_dbl_6(sp_point_384* r, const sp_point_384* p, sp_digit* t)
{
    sp_digit* t1 = t;
    sp_digit* t2 = t + 2*6;
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
    sp_384_mont_sqr_6(t1, p->z, p384_mod, p384_mp_mod);
    /* Z = Y * Z */
    sp_384_mont_mul_6(z, p->y, p->z, p384_mod, p384_mp_mod);
    /* Z = 2Z */
    sp_384_mont_dbl_6(z, z, p384_mod);
    /* T2 = X - T1 */
    sp_384_mont_sub_6(t2, p->x, t1, p384_mod);
    /* T1 = X + T1 */
    sp_384_mont_add_6(t1, p->x, t1, p384_mod);
    /* T2 = T1 * T2 */
    sp_384_mont_mul_6(t2, t1, t2, p384_mod, p384_mp_mod);
    /* T1 = 3T2 */
    sp_384_mont_tpl_6(t1, t2, p384_mod);
    /* Y = 2Y */
    sp_384_mont_dbl_6(y, p->y, p384_mod);
    /* Y = Y * Y */
    sp_384_mont_sqr_6(y, y, p384_mod, p384_mp_mod);
    /* T2 = Y * Y */
    sp_384_mont_sqr_6(t2, y, p384_mod, p384_mp_mod);
    /* T2 = T2/2 */
    sp_384_div2_6(t2, t2, p384_mod);
    /* Y = Y * X */
    sp_384_mont_mul_6(y, y, p->x, p384_mod, p384_mp_mod);
    /* X = T1 * T1 */
    sp_384_mont_sqr_6(x, t1, p384_mod, p384_mp_mod);
    /* X = X - Y */
    sp_384_mont_sub_6(x, x, y, p384_mod);
    /* X = X - Y */
    sp_384_mont_sub_6(x, x, y, p384_mod);
    /* Y = Y - X */
    sp_384_mont_sub_6(y, y, x, p384_mod);
    /* Y = Y * T1 */
    sp_384_mont_mul_6(y, y, t1, p384_mod, p384_mp_mod);
    /* Y = Y - T2 */
    sp_384_mont_sub_6(y, y, t2, p384_mod);
}

/* Double the Montgomery form projective point p a number of times.
 *
 * r  Result of repeated doubling of point.
 * p  Point to double.
 * n  Number of times to double
 * t  Temporary ordinate data.
 */
static void sp_384_proj_point_dbl_n_6(sp_point_384* p, int n, sp_digit* t)
{
    sp_digit* w = t;
    sp_digit* a = t + 2*6;
    sp_digit* b = t + 4*6;
    sp_digit* t1 = t + 6*6;
    sp_digit* t2 = t + 8*6;
    sp_digit* x;
    sp_digit* y;
    sp_digit* z;

    x = p->x;
    y = p->y;
    z = p->z;

    /* Y = 2*Y */
    sp_384_mont_dbl_6(y, y, p384_mod);
    /* W = Z^4 */
    sp_384_mont_sqr_6(w, z, p384_mod, p384_mp_mod);
    sp_384_mont_sqr_6(w, w, p384_mod, p384_mp_mod);

#ifndef WOLFSSL_SP_SMALL
    while (--n > 0)
#else
    while (--n >= 0)
#endif
    {
        /* A = 3*(X^2 - W) */
        sp_384_mont_sqr_6(t1, x, p384_mod, p384_mp_mod);
        sp_384_mont_sub_6(t1, t1, w, p384_mod);
        sp_384_mont_tpl_6(a, t1, p384_mod);
        /* B = X*Y^2 */
        sp_384_mont_sqr_6(t1, y, p384_mod, p384_mp_mod);
        sp_384_mont_mul_6(b, t1, x, p384_mod, p384_mp_mod);
        /* X = A^2 - 2B */
        sp_384_mont_sqr_6(x, a, p384_mod, p384_mp_mod);
        sp_384_mont_dbl_6(t2, b, p384_mod);
        sp_384_mont_sub_6(x, x, t2, p384_mod);
        /* Z = Z*Y */
        sp_384_mont_mul_6(z, z, y, p384_mod, p384_mp_mod);
        /* t2 = Y^4 */
        sp_384_mont_sqr_6(t1, t1, p384_mod, p384_mp_mod);
#ifdef WOLFSSL_SP_SMALL
        if (n != 0)
#endif
        {
            /* W = W*Y^4 */
            sp_384_mont_mul_6(w, w, t1, p384_mod, p384_mp_mod);
        }
        /* y = 2*A*(B - X) - Y^4 */
        sp_384_mont_sub_6(y, b, x, p384_mod);
        sp_384_mont_mul_6(y, y, a, p384_mod, p384_mp_mod);
        sp_384_mont_dbl_6(y, y, p384_mod);
        sp_384_mont_sub_6(y, y, t1, p384_mod);
    }
#ifndef WOLFSSL_SP_SMALL
    /* A = 3*(X^2 - W) */
    sp_384_mont_sqr_6(t1, x, p384_mod, p384_mp_mod);
    sp_384_mont_sub_6(t1, t1, w, p384_mod);
    sp_384_mont_tpl_6(a, t1, p384_mod);
    /* B = X*Y^2 */
    sp_384_mont_sqr_6(t1, y, p384_mod, p384_mp_mod);
    sp_384_mont_mul_6(b, t1, x, p384_mod, p384_mp_mod);
    /* X = A^2 - 2B */
    sp_384_mont_sqr_6(x, a, p384_mod, p384_mp_mod);
    sp_384_mont_dbl_6(t2, b, p384_mod);
    sp_384_mont_sub_6(x, x, t2, p384_mod);
    /* Z = Z*Y */
    sp_384_mont_mul_6(z, z, y, p384_mod, p384_mp_mod);
    /* t2 = Y^4 */
    sp_384_mont_sqr_6(t1, t1, p384_mod, p384_mp_mod);
    /* y = 2*A*(B - X) - Y^4 */
    sp_384_mont_sub_6(y, b, x, p384_mod);
    sp_384_mont_mul_6(y, y, a, p384_mod, p384_mp_mod);
    sp_384_mont_dbl_6(y, y, p384_mod);
    sp_384_mont_sub_6(y, y, t1, p384_mod);
#endif
    /* Y = Y/2 */
    sp_384_div2_6(y, y, p384_mod);
}

/* Compare two numbers to determine if they are equal.
 * Constant time implementation.
 *
 * a  First number to compare.
 * b  Second number to compare.
 * returns 1 when equal and 0 otherwise.
 */
static int sp_384_cmp_equal_6(const sp_digit* a, const sp_digit* b)
{
    return ((a[0] ^ b[0]) | (a[1] ^ b[1]) | (a[2] ^ b[2]) | (a[3] ^ b[3]) |
            (a[4] ^ b[4]) | (a[5] ^ b[5])) == 0;
}

/* Add two Montgomery form projective points.
 *
 * r  Result of addition.
 * p  First point to add.
 * q  Second point to add.
 * t  Temporary ordinate data.
 */


static void sp_384_proj_point_add_6(sp_point_384* r, const sp_point_384* p, const sp_point_384* q,
        sp_digit* t)
{
    const sp_point_384* ap[2];
    sp_point_384* rp[2];
    sp_digit* t1 = t;
    sp_digit* t2 = t + 2*6;
    sp_digit* t3 = t + 4*6;
    sp_digit* t4 = t + 6*6;
    sp_digit* t5 = t + 8*6;
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
    (void)sp_384_sub_6(t1, p384_mod, q->y);
    sp_384_norm_6(t1);
    if ((sp_384_cmp_equal_6(p->x, q->x) & sp_384_cmp_equal_6(p->z, q->z) &
        (sp_384_cmp_equal_6(p->y, q->y) | sp_384_cmp_equal_6(p->y, t1))) != 0) {
        sp_384_proj_point_dbl_6(r, p, t);
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
        for (i=0; i<6; i++) {
            r->x[i] = ap[p->infinity]->x[i];
        }
        for (i=0; i<6; i++) {
            r->y[i] = ap[p->infinity]->y[i];
        }
        for (i=0; i<6; i++) {
            r->z[i] = ap[p->infinity]->z[i];
        }
        r->infinity = ap[p->infinity]->infinity;

        /* U1 = X1*Z2^2 */
        sp_384_mont_sqr_6(t1, q->z, p384_mod, p384_mp_mod);
        sp_384_mont_mul_6(t3, t1, q->z, p384_mod, p384_mp_mod);
        sp_384_mont_mul_6(t1, t1, x, p384_mod, p384_mp_mod);
        /* U2 = X2*Z1^2 */
        sp_384_mont_sqr_6(t2, z, p384_mod, p384_mp_mod);
        sp_384_mont_mul_6(t4, t2, z, p384_mod, p384_mp_mod);
        sp_384_mont_mul_6(t2, t2, q->x, p384_mod, p384_mp_mod);
        /* S1 = Y1*Z2^3 */
        sp_384_mont_mul_6(t3, t3, y, p384_mod, p384_mp_mod);
        /* S2 = Y2*Z1^3 */
        sp_384_mont_mul_6(t4, t4, q->y, p384_mod, p384_mp_mod);
        /* H = U2 - U1 */
        sp_384_mont_sub_6(t2, t2, t1, p384_mod);
        /* R = S2 - S1 */
        sp_384_mont_sub_6(t4, t4, t3, p384_mod);
        /* Z3 = H*Z1*Z2 */
        sp_384_mont_mul_6(z, z, q->z, p384_mod, p384_mp_mod);
        sp_384_mont_mul_6(z, z, t2, p384_mod, p384_mp_mod);
        /* X3 = R^2 - H^3 - 2*U1*H^2 */
        sp_384_mont_sqr_6(x, t4, p384_mod, p384_mp_mod);
        sp_384_mont_sqr_6(t5, t2, p384_mod, p384_mp_mod);
        sp_384_mont_mul_6(y, t1, t5, p384_mod, p384_mp_mod);
        sp_384_mont_mul_6(t5, t5, t2, p384_mod, p384_mp_mod);
        sp_384_mont_sub_6(x, x, t5, p384_mod);
        sp_384_mont_dbl_6(t1, y, p384_mod);
        sp_384_mont_sub_6(x, x, t1, p384_mod);
        /* Y3 = R*(U1*H^2 - X3) - S1*H^3 */
        sp_384_mont_sub_6(y, y, x, p384_mod);
        sp_384_mont_mul_6(y, y, t4, p384_mod, p384_mp_mod);
        sp_384_mont_mul_6(t5, t5, t3, p384_mod, p384_mp_mod);
        sp_384_mont_sub_6(y, y, t5, p384_mod);
    }
}

/* Double the Montgomery form projective point p a number of times.
 *
 * r  Result of repeated doubling of point.
 * p  Point to double.
 * n  Number of times to double
 * t  Temporary ordinate data.
 */
static void sp_384_proj_point_dbl_n_store_6(sp_point_384* r, const sp_point_384* p,
        int n, int m, sp_digit* t)
{
    sp_digit* w = t;
    sp_digit* a = t + 2*6;
    sp_digit* b = t + 4*6;
    sp_digit* t1 = t + 6*6;
    sp_digit* t2 = t + 8*6;
    sp_digit* x = r[2*m].x;
    sp_digit* y = r[(1<<n)*m].y;
    sp_digit* z = r[2*m].z;
    int i;

    for (i=0; i<6; i++) {
        x[i] = p->x[i];
    }
    for (i=0; i<6; i++) {
        y[i] = p->y[i];
    }
    for (i=0; i<6; i++) {
        z[i] = p->z[i];
    }

    /* Y = 2*Y */
    sp_384_mont_dbl_6(y, y, p384_mod);
    /* W = Z^4 */
    sp_384_mont_sqr_6(w, z, p384_mod, p384_mp_mod);
    sp_384_mont_sqr_6(w, w, p384_mod, p384_mp_mod);
    for (i=1; i<=n; i++) {
        /* A = 3*(X^2 - W) */
        sp_384_mont_sqr_6(t1, x, p384_mod, p384_mp_mod);
        sp_384_mont_sub_6(t1, t1, w, p384_mod);
        sp_384_mont_tpl_6(a, t1, p384_mod);
        /* B = X*Y^2 */
        sp_384_mont_sqr_6(t2, y, p384_mod, p384_mp_mod);
        sp_384_mont_mul_6(b, t2, x, p384_mod, p384_mp_mod);
        x = r[(1<<i)*m].x;
        /* X = A^2 - 2B */
        sp_384_mont_sqr_6(x, a, p384_mod, p384_mp_mod);
        sp_384_mont_dbl_6(t1, b, p384_mod);
        sp_384_mont_sub_6(x, x, t1, p384_mod);
        /* Z = Z*Y */
        sp_384_mont_mul_6(r[(1<<i)*m].z, z, y, p384_mod, p384_mp_mod);
        z = r[(1<<i)*m].z;
        /* t2 = Y^4 */
        sp_384_mont_sqr_6(t2, t2, p384_mod, p384_mp_mod);
        if (i != n) {
            /* W = W*Y^4 */
            sp_384_mont_mul_6(w, w, t2, p384_mod, p384_mp_mod);
        }
        /* y = 2*A*(B - X) - Y^4 */
        sp_384_mont_sub_6(y, b, x, p384_mod);
        sp_384_mont_mul_6(y, y, a, p384_mod, p384_mp_mod);
        sp_384_mont_dbl_6(y, y, p384_mod);
        sp_384_mont_sub_6(y, y, t2, p384_mod);

        /* Y = Y/2 */
        sp_384_div2_6(r[(1<<i)*m].y, y, p384_mod);
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
static void sp_384_proj_point_add_sub_6(sp_point_384* ra, sp_point_384* rs,
        const sp_point_384* p, const sp_point_384* q, sp_digit* t)
{
    sp_digit* t1 = t;
    sp_digit* t2 = t + 2*6;
    sp_digit* t3 = t + 4*6;
    sp_digit* t4 = t + 6*6;
    sp_digit* t5 = t + 8*6;
    sp_digit* t6 = t + 10*6;
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
    sp_384_mont_sqr_6(t1, q->z, p384_mod, p384_mp_mod);
    sp_384_mont_mul_6(t3, t1, q->z, p384_mod, p384_mp_mod);
    sp_384_mont_mul_6(t1, t1, x, p384_mod, p384_mp_mod);
    /* U2 = X2*Z1^2 */
    sp_384_mont_sqr_6(t2, z, p384_mod, p384_mp_mod);
    sp_384_mont_mul_6(t4, t2, z, p384_mod, p384_mp_mod);
    sp_384_mont_mul_6(t2, t2, q->x, p384_mod, p384_mp_mod);
    /* S1 = Y1*Z2^3 */
    sp_384_mont_mul_6(t3, t3, y, p384_mod, p384_mp_mod);
    /* S2 = Y2*Z1^3 */
    sp_384_mont_mul_6(t4, t4, q->y, p384_mod, p384_mp_mod);
    /* H = U2 - U1 */
    sp_384_mont_sub_6(t2, t2, t1, p384_mod);
    /* RS = S2 + S1 */
    sp_384_mont_add_6(t6, t4, t3, p384_mod);
    /* R = S2 - S1 */
    sp_384_mont_sub_6(t4, t4, t3, p384_mod);
    /* Z3 = H*Z1*Z2 */
    /* ZS = H*Z1*Z2 */
    sp_384_mont_mul_6(z, z, q->z, p384_mod, p384_mp_mod);
    sp_384_mont_mul_6(z, z, t2, p384_mod, p384_mp_mod);
    XMEMCPY(zs, z, sizeof(p->z)/2);
    /* X3 = R^2 - H^3 - 2*U1*H^2 */
    /* XS = RS^2 - H^3 - 2*U1*H^2 */
    sp_384_mont_sqr_6(x, t4, p384_mod, p384_mp_mod);
    sp_384_mont_sqr_6(xs, t6, p384_mod, p384_mp_mod);
    sp_384_mont_sqr_6(t5, t2, p384_mod, p384_mp_mod);
    sp_384_mont_mul_6(y, t1, t5, p384_mod, p384_mp_mod);
    sp_384_mont_mul_6(t5, t5, t2, p384_mod, p384_mp_mod);
    sp_384_mont_sub_6(x, x, t5, p384_mod);
    sp_384_mont_sub_6(xs, xs, t5, p384_mod);
    sp_384_mont_dbl_6(t1, y, p384_mod);
    sp_384_mont_sub_6(x, x, t1, p384_mod);
    sp_384_mont_sub_6(xs, xs, t1, p384_mod);
    /* Y3 = R*(U1*H^2 - X3) - S1*H^3 */
    /* YS = -RS*(U1*H^2 - XS) - S1*H^3 */
    sp_384_mont_sub_6(ys, y, xs, p384_mod);
    sp_384_mont_sub_6(y, y, x, p384_mod);
    sp_384_mont_mul_6(y, y, t4, p384_mod, p384_mp_mod);
    sp_384_sub_6(t6, p384_mod, t6);
    sp_384_mont_mul_6(ys, ys, t6, p384_mod, p384_mp_mod);
    sp_384_mont_mul_6(t5, t5, t3, p384_mod, p384_mp_mod);
    sp_384_mont_sub_6(y, y, t5, p384_mod);
    sp_384_mont_sub_6(ys, ys, t5, p384_mod);
}

/* Structure used to describe recoding of scalar multiplication. */
typedef struct ecc_recode_384 {
    /* Index into pre-computation table. */
    uint8_t i;
    /* Use the negative of the point. */
    uint8_t neg;
} ecc_recode_384;

/* The index into pre-computation table to use. */
static const uint8_t recode_index_6_6[66] = {
     0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
    16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
    32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17,
    16, 15, 14, 13, 12, 11, 10,  9,  8,  7,  6,  5,  4,  3,  2,  1,
     0,  1,
};

/* Whether to negate y-ordinate. */
static const uint8_t recode_neg_6_6[66] = {
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
static void sp_384_ecc_recode_6_6(const sp_digit* k, ecc_recode_384* v)
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
        if (o + 6 < 64) {
            y &= 0x3f;
            n >>= 6;
            o += 6;
        }
        else if (o + 6 == 64) {
            n >>= 6;
            if (++j < 6)
                n = k[j];
            o = 0;
        }
        else if (++j < 6) {
            n = k[j];
            y |= (uint8_t)((n << (64 - o)) & 0x3f);
            o -= 58;
            n >>= o;
        }

        y += (uint8_t)carry;
        v[i].i = recode_index_6_6[y];
        v[i].neg = recode_neg_6_6[y];
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
static void sp_384_get_point_33_6(sp_point_384* r, const sp_point_384* table,
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
    r->y[0] = 0;
    r->y[1] = 0;
    r->y[2] = 0;
    r->y[3] = 0;
    r->y[4] = 0;
    r->y[5] = 0;
    r->z[0] = 0;
    r->z[1] = 0;
    r->z[2] = 0;
    r->z[3] = 0;
    r->z[4] = 0;
    r->z[5] = 0;
    for (i = 1; i < 33; i++) {
        mask = 0 - (i == idx);
        r->x[0] |= mask & table[i].x[0];
        r->x[1] |= mask & table[i].x[1];
        r->x[2] |= mask & table[i].x[2];
        r->x[3] |= mask & table[i].x[3];
        r->x[4] |= mask & table[i].x[4];
        r->x[5] |= mask & table[i].x[5];
        r->y[0] |= mask & table[i].y[0];
        r->y[1] |= mask & table[i].y[1];
        r->y[2] |= mask & table[i].y[2];
        r->y[3] |= mask & table[i].y[3];
        r->y[4] |= mask & table[i].y[4];
        r->y[5] |= mask & table[i].y[5];
        r->z[0] |= mask & table[i].z[0];
        r->z[1] |= mask & table[i].z[1];
        r->z[2] |= mask & table[i].z[2];
        r->z[3] |= mask & table[i].z[3];
        r->z[4] |= mask & table[i].z[4];
        r->z[5] |= mask & table[i].z[5];
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
static int sp_384_ecc_mulmod_win_add_sub_6(sp_point_384* r, const sp_point_384* g,
        const sp_digit* k, int map, int ct, void* heap)
{
#if (!defined(WOLFSSL_SP_SMALL) && !defined(WOLFSSL_SMALL_STACK)) || defined(WOLFSSL_SP_NO_MALLOC)
    sp_point_384 td[33];
    sp_point_384 rtd, pd;
    sp_digit tmpd[2 * 6 * 6];
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

    err = sp_384_point_new_6(heap, rtd, rt);
    if (err == MP_OKAY)
        err = sp_384_point_new_6(heap, pd, p);
#if (defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)) && !defined(WOLFSSL_SP_NO_MALLOC)
    t = (sp_point_384*)XMALLOC(sizeof(sp_point_384) * 33, heap, DYNAMIC_TYPE_ECC);
    if (t == NULL)
        err = MEMORY_E;
    tmp = (sp_digit*)XMALLOC(sizeof(sp_digit) * 2 * 6 * 6, heap,
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
        err = sp_384_mod_mul_norm_6(t[1].x, g->x, p384_mod);
    }
    if (err == MP_OKAY) {
        err = sp_384_mod_mul_norm_6(t[1].y, g->y, p384_mod);
    }
    if (err == MP_OKAY) {
        err = sp_384_mod_mul_norm_6(t[1].z, g->z, p384_mod);
    }

    if (err == MP_OKAY) {
        t[1].infinity = 0;
        /* t[2] ... t[32]  */
        sp_384_proj_point_dbl_n_store_6(t, &t[ 1], 5, 1, tmp);
        sp_384_proj_point_add_6(&t[ 3], &t[ 2], &t[ 1], tmp);
        sp_384_proj_point_dbl_6(&t[ 6], &t[ 3], tmp);
        sp_384_proj_point_add_sub_6(&t[ 7], &t[ 5], &t[ 6], &t[ 1], tmp);
        sp_384_proj_point_dbl_6(&t[10], &t[ 5], tmp);
        sp_384_proj_point_add_sub_6(&t[11], &t[ 9], &t[10], &t[ 1], tmp);
        sp_384_proj_point_dbl_6(&t[12], &t[ 6], tmp);
        sp_384_proj_point_dbl_6(&t[14], &t[ 7], tmp);
        sp_384_proj_point_add_sub_6(&t[15], &t[13], &t[14], &t[ 1], tmp);
        sp_384_proj_point_dbl_6(&t[18], &t[ 9], tmp);
        sp_384_proj_point_add_sub_6(&t[19], &t[17], &t[18], &t[ 1], tmp);
        sp_384_proj_point_dbl_6(&t[20], &t[10], tmp);
        sp_384_proj_point_dbl_6(&t[22], &t[11], tmp);
        sp_384_proj_point_add_sub_6(&t[23], &t[21], &t[22], &t[ 1], tmp);
        sp_384_proj_point_dbl_6(&t[24], &t[12], tmp);
        sp_384_proj_point_dbl_6(&t[26], &t[13], tmp);
        sp_384_proj_point_add_sub_6(&t[27], &t[25], &t[26], &t[ 1], tmp);
        sp_384_proj_point_dbl_6(&t[28], &t[14], tmp);
        sp_384_proj_point_dbl_6(&t[30], &t[15], tmp);
        sp_384_proj_point_add_sub_6(&t[31], &t[29], &t[30], &t[ 1], tmp);

        negy = t[0].y;

        sp_384_ecc_recode_6_6(k, v);

        i = 64;
    #ifndef WC_NO_CACHE_RESISTANT
        if (ct) {
            sp_384_get_point_33_6(rt, t, v[i].i);
            rt->infinity = !v[i].i;
        }
        else
    #endif
        {
            XMEMCPY(rt, &t[v[i].i], sizeof(sp_point_384));
        }
        for (--i; i>=0; i--) {
            sp_384_proj_point_dbl_n_6(rt, 6, tmp);

        #ifndef WC_NO_CACHE_RESISTANT
            if (ct) {
                sp_384_get_point_33_6(p, t, v[i].i);
                p->infinity = !v[i].i;
            }
            else
        #endif
            {
                XMEMCPY(p, &t[v[i].i], sizeof(sp_point_384));
            }
            sp_384_sub_6(negy, p384_mod, p->y);
            sp_384_cond_copy_6(p->y, negy, (sp_digit)0 - v[i].neg);
            sp_384_proj_point_add_6(rt, rt, p, tmp);
        }

        if (map != 0) {
            sp_384_map_6(r, rt, tmp);
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
    sp_384_point_free_6(p, 0, heap);
    sp_384_point_free_6(rt, 0, heap);

    return err;
}

/* A table entry for pre-computed points. */
typedef struct sp_table_entry_384 {
    sp_digit x[6];
    sp_digit y[6];
} sp_table_entry_384;

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
static void sp_384_proj_point_add_qz1_6(sp_point_384* r, const sp_point_384* p,
        const sp_point_384* q, sp_digit* t)
{
    const sp_point_384* ap[2];
    sp_point_384* rp[2];
    sp_digit* t1 = t;
    sp_digit* t2 = t + 2*6;
    sp_digit* t3 = t + 4*6;
    sp_digit* t4 = t + 6*6;
    sp_digit* t5 = t + 8*6;
    sp_digit* x;
    sp_digit* y;
    sp_digit* z;
    int i;

    /* Check double */
    (void)sp_384_sub_6(t1, p384_mod, q->y);
    sp_384_norm_6(t1);
    if ((sp_384_cmp_equal_6(p->x, q->x) & sp_384_cmp_equal_6(p->z, q->z) &
        (sp_384_cmp_equal_6(p->y, q->y) | sp_384_cmp_equal_6(p->y, t1))) != 0) {
        sp_384_proj_point_dbl_6(r, p, t);
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
        for (i=0; i<6; i++) {
            r->x[i] = ap[p->infinity]->x[i];
        }
        for (i=0; i<6; i++) {
            r->y[i] = ap[p->infinity]->y[i];
        }
        for (i=0; i<6; i++) {
            r->z[i] = ap[p->infinity]->z[i];
        }
        r->infinity = ap[p->infinity]->infinity;

        /* U2 = X2*Z1^2 */
        sp_384_mont_sqr_6(t2, z, p384_mod, p384_mp_mod);
        sp_384_mont_mul_6(t4, t2, z, p384_mod, p384_mp_mod);
        sp_384_mont_mul_6(t2, t2, q->x, p384_mod, p384_mp_mod);
        /* S2 = Y2*Z1^3 */
        sp_384_mont_mul_6(t4, t4, q->y, p384_mod, p384_mp_mod);
        /* H = U2 - X1 */
        sp_384_mont_sub_6(t2, t2, x, p384_mod);
        /* R = S2 - Y1 */
        sp_384_mont_sub_6(t4, t4, y, p384_mod);
        /* Z3 = H*Z1 */
        sp_384_mont_mul_6(z, z, t2, p384_mod, p384_mp_mod);
        /* X3 = R^2 - H^3 - 2*X1*H^2 */
        sp_384_mont_sqr_6(t1, t4, p384_mod, p384_mp_mod);
        sp_384_mont_sqr_6(t5, t2, p384_mod, p384_mp_mod);
        sp_384_mont_mul_6(t3, x, t5, p384_mod, p384_mp_mod);
        sp_384_mont_mul_6(t5, t5, t2, p384_mod, p384_mp_mod);
        sp_384_mont_sub_6(x, t1, t5, p384_mod);
        sp_384_mont_dbl_6(t1, t3, p384_mod);
        sp_384_mont_sub_6(x, x, t1, p384_mod);
        /* Y3 = R*(X1*H^2 - X3) - Y1*H^3 */
        sp_384_mont_sub_6(t3, t3, x, p384_mod);
        sp_384_mont_mul_6(t3, t3, t4, p384_mod, p384_mp_mod);
        sp_384_mont_mul_6(t5, t5, y, p384_mod, p384_mp_mod);
        sp_384_mont_sub_6(y, t3, t5, p384_mod);
    }
}

#ifdef FP_ECC
/* Convert the projective point to affine.
 * Ordinates are in Montgomery form.
 *
 * a  Point to convert.
 * t  Temporary data.
 */
static void sp_384_proj_to_affine_6(sp_point_384* a, sp_digit* t)
{
    sp_digit* t1 = t;
    sp_digit* t2 = t + 2 * 6;
    sp_digit* tmp = t + 4 * 6;

    sp_384_mont_inv_6(t1, a->z, tmp);

    sp_384_mont_sqr_6(t2, t1, p384_mod, p384_mp_mod);
    sp_384_mont_mul_6(t1, t2, t1, p384_mod, p384_mp_mod);

    sp_384_mont_mul_6(a->x, a->x, t2, p384_mod, p384_mp_mod);
    sp_384_mont_mul_6(a->y, a->y, t1, p384_mod, p384_mp_mod);
    XMEMCPY(a->z, p384_norm_mod, sizeof(p384_norm_mod));
}

/* Generate the pre-computed table of points for the base point.
 *
 * a      The base point.
 * table  Place to store generated point data.
 * tmp    Temporary data.
 * heap  Heap to use for allocation.
 */
static int sp_384_gen_stripe_table_6(const sp_point_384* a,
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

    err = sp_384_point_new_6(heap, td, t);
    if (err == MP_OKAY) {
        err = sp_384_point_new_6(heap, s1d, s1);
    }
    if (err == MP_OKAY) {
        err = sp_384_point_new_6(heap, s2d, s2);
    }

    if (err == MP_OKAY) {
        err = sp_384_mod_mul_norm_6(t->x, a->x, p384_mod);
    }
    if (err == MP_OKAY) {
        err = sp_384_mod_mul_norm_6(t->y, a->y, p384_mod);
    }
    if (err == MP_OKAY) {
        err = sp_384_mod_mul_norm_6(t->z, a->z, p384_mod);
    }
    if (err == MP_OKAY) {
        t->infinity = 0;
        sp_384_proj_to_affine_6(t, tmp);

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
            sp_384_proj_point_dbl_n_6(t, 48, tmp);
            sp_384_proj_to_affine_6(t, tmp);
            XMEMCPY(table[1<<i].x, t->x, sizeof(table->x));
            XMEMCPY(table[1<<i].y, t->y, sizeof(table->y));
        }

        for (i=1; i<8; i++) {
            XMEMCPY(s1->x, table[1<<i].x, sizeof(table->x));
            XMEMCPY(s1->y, table[1<<i].y, sizeof(table->y));
            for (j=(1<<i)+1; j<(1<<(i+1)); j++) {
                XMEMCPY(s2->x, table[j-(1<<i)].x, sizeof(table->x));
                XMEMCPY(s2->y, table[j-(1<<i)].y, sizeof(table->y));
                sp_384_proj_point_add_qz1_6(t, s1, s2, tmp);
                sp_384_proj_to_affine_6(t, tmp);
                XMEMCPY(table[j].x, t->x, sizeof(table->x));
                XMEMCPY(table[j].y, t->y, sizeof(table->y));
            }
        }
    }

    sp_384_point_free_6(s2, 0, heap);
    sp_384_point_free_6(s1, 0, heap);
    sp_384_point_free_6( t, 0, heap);

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
static void sp_384_get_entry_256_6(sp_point_384* r,
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
    r->y[0] = 0;
    r->y[1] = 0;
    r->y[2] = 0;
    r->y[3] = 0;
    r->y[4] = 0;
    r->y[5] = 0;
    for (i = 1; i < 256; i++) {
        mask = 0 - (i == idx);
        r->x[0] |= mask & table[i].x[0];
        r->x[1] |= mask & table[i].x[1];
        r->x[2] |= mask & table[i].x[2];
        r->x[3] |= mask & table[i].x[3];
        r->x[4] |= mask & table[i].x[4];
        r->x[5] |= mask & table[i].x[5];
        r->y[0] |= mask & table[i].y[0];
        r->y[1] |= mask & table[i].y[1];
        r->y[2] |= mask & table[i].y[2];
        r->y[3] |= mask & table[i].y[3];
        r->y[4] |= mask & table[i].y[4];
        r->y[5] |= mask & table[i].y[5];
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
static int sp_384_ecc_mulmod_stripe_6(sp_point_384* r, const sp_point_384* g,
        const sp_table_entry_384* table, const sp_digit* k, int map,
        int ct, void* heap)
{
#if (!defined(WOLFSSL_SP_SMALL) && !defined(WOLFSSL_SMALL_STACK)) || defined(WOLFSSL_SP_NO_MALLOC)
    sp_point_384 rtd;
    sp_point_384 pd;
    sp_digit td[2 * 6 * 6];
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


    err = sp_384_point_new_6(heap, rtd, rt);
    if (err == MP_OKAY) {
        err = sp_384_point_new_6(heap, pd, p);
    }
#if (defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)) && !defined(WOLFSSL_SP_NO_MALLOC)
    t = (sp_digit*)XMALLOC(sizeof(sp_digit) * 2 * 6 * 6, heap,
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
            y |= (int)(((k[x / 64] >> (x % 64)) & 1) << j);
        }
    #ifndef WC_NO_CACHE_RESISTANT
        if (ct) {
            sp_384_get_entry_256_6(rt, table, y);
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
                y |= (int)(((k[x / 64] >> (x % 64)) & 1) << j);
            }

            sp_384_proj_point_dbl_6(rt, rt, t);
        #ifndef WC_NO_CACHE_RESISTANT
            if (ct) {
                sp_384_get_entry_256_6(p, table, y);
            }
            else
        #endif
            {
                XMEMCPY(p->x, table[y].x, sizeof(table[y].x));
                XMEMCPY(p->y, table[y].y, sizeof(table[y].y));
            }
            p->infinity = !y;
            sp_384_proj_point_add_qz1_6(rt, rt, p, t);
        }

        if (map != 0) {
            sp_384_map_6(r, rt, t);
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
    sp_384_point_free_6(p, 0, heap);
    sp_384_point_free_6(rt, 0, heap);

    return err;
}

#ifdef FP_ECC
#ifndef FP_ENTRIES
    #define FP_ENTRIES 16
#endif

typedef struct sp_cache_384_t {
    sp_digit x[6];
    sp_digit y[6];
    sp_table_entry_384 table[256];
    uint32_t cnt;
    int set;
} sp_cache_384_t;

static THREAD_LS_T sp_cache_384_t sp_cache_384[FP_ENTRIES];
static THREAD_LS_T int sp_cache_384_last = -1;
static THREAD_LS_T int sp_cache_384_inited = 0;

#ifndef HAVE_THREAD_LS
    static volatile int initCacheMutex_384 = 0;
    static wolfSSL_Mutex sp_cache_384_lock;
#endif

static void sp_ecc_get_cache_384(const sp_point_384* g, sp_cache_384_t** cache)
{
    int i, j;
    uint32_t least;

    if (sp_cache_384_inited == 0) {
        for (i=0; i<FP_ENTRIES; i++) {
            sp_cache_384[i].set = 0;
        }
        sp_cache_384_inited = 1;
    }

    /* Compare point with those in cache. */
    for (i=0; i<FP_ENTRIES; i++) {
        if (!sp_cache_384[i].set)
            continue;

        if (sp_384_cmp_equal_6(g->x, sp_cache_384[i].x) &
                           sp_384_cmp_equal_6(g->y, sp_cache_384[i].y)) {
            sp_cache_384[i].cnt++;
            break;
        }
    }

    /* No match. */
    if (i == FP_ENTRIES) {
        /* Find empty entry. */
        i = (sp_cache_384_last + 1) % FP_ENTRIES;
        for (; i != sp_cache_384_last; i=(i+1)%FP_ENTRIES) {
            if (!sp_cache_384[i].set) {
                break;
            }
        }

        /* Evict least used. */
        if (i == sp_cache_384_last) {
            least = sp_cache_384[0].cnt;
            for (j=1; j<FP_ENTRIES; j++) {
                if (sp_cache_384[j].cnt < least) {
                    i = j;
                    least = sp_cache_384[i].cnt;
                }
            }
        }

        XMEMCPY(sp_cache_384[i].x, g->x, sizeof(sp_cache_384[i].x));
        XMEMCPY(sp_cache_384[i].y, g->y, sizeof(sp_cache_384[i].y));
        sp_cache_384[i].set = 1;
        sp_cache_384[i].cnt = 1;
    }

    *cache = &sp_cache_384[i];
    sp_cache_384_last = i;
}
#endif /* FP_ECC */

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
static int sp_384_ecc_mulmod_6(sp_point_384* r, const sp_point_384* g, const sp_digit* k,
        int map, int ct, void* heap)
{
#ifndef FP_ECC
    return sp_384_ecc_mulmod_win_add_sub_6(r, g, k, map, ct, heap);
#else
    sp_digit tmp[2 * 6 * 7];
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
            sp_384_gen_stripe_table_6(g, cache->table, tmp, heap);

#ifndef HAVE_THREAD_LS
        wc_UnLockMutex(&sp_cache_384_lock);
#endif /* HAVE_THREAD_LS */

        if (cache->cnt < 2) {
            err = sp_384_ecc_mulmod_win_add_sub_6(r, g, k, map, ct, heap);
        }
        else {
            err = sp_384_ecc_mulmod_stripe_6(r, g, cache->table, k,
                    map, ct, heap);
        }
    }

    return err;
#endif
}

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
    sp_digit kd[6];
#endif
    sp_point_384* point;
    sp_digit* k = NULL;
    int err = MP_OKAY;

    err = sp_384_point_new_6(heap, p, point);
#if (defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)) && !defined(WOLFSSL_SP_NO_MALLOC)
    if (err == MP_OKAY) {
        k = (sp_digit*)XMALLOC(sizeof(sp_digit) * 6, heap,
                                                              DYNAMIC_TYPE_ECC);
        if (k == NULL)
            err = MEMORY_E;
    }
#else
    k = kd;
#endif
    if (err == MP_OKAY) {
        sp_384_from_mp(k, 6, km);
        sp_384_point_from_ecc_point_6(point, gm);

            err = sp_384_ecc_mulmod_6(point, point, k, map, 1, heap);
    }
    if (err == MP_OKAY) {
        err = sp_384_point_to_ecc_point_6(point, r);
    }

#if (defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)) && !defined(WOLFSSL_SP_NO_MALLOC)
    if (k != NULL) {
        XFREE(k, heap, DYNAMIC_TYPE_ECC);
    }
#endif
    sp_384_point_free_6(point, 0, heap);

    return err;
}

static const sp_table_entry_384 p384_table[256] = {
    /* 0 */
    { { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
      { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } },
    /* 1 */
    { { 0x3dd0756649c0b528L,0x20e378e2a0d6ce38L,0x879c3afc541b4d6eL,
        0x6454868459a30effL,0x812ff723614ede2bL,0x4d3aadc2299e1513L },
      { 0x23043dad4b03a4feL,0xa1bfa8bf7bb4a9acL,0x8bade7562e83b050L,
        0xc6c3521968f4ffd9L,0xdd8002263969a840L,0x2b78abc25a15c5e9L } },
    /* 2 */
    { { 0x298647532b0c535bL,0x90dd695370506296L,0x038cd6b4216ab9acL,
        0x3df9b7b7be12d76aL,0x13f4d9785f347bdbL,0x222c5c9c13e94489L },
      { 0x5f8e796f2680dc64L,0x120e7cb758352417L,0x254b5d8ad10740b8L,
        0xc38b8efb5337dee6L,0xf688c2e194f02247L,0x7b5c75f36c25bc4cL } },
    /* 3 */
    { { 0xe26a3cc39edffea5L,0x35bbfd1c37d7e9fcL,0xf0e7700d9bde3ef6L,
        0x0380eb471a538f5aL,0x2e9da8bb05bf9eb3L,0xdbb93c731a460c3eL },
      { 0x37dba260f526b605L,0x95d4978efd785537L,0x24ed793aed72a04aL,
        0x2694837776005b1aL,0x99f557b99e681f82L,0xae5f9557d64954efL } },
    /* 4 */
    { { 0x24480c57f26feef9L,0xc31a26943a0e1240L,0x735002c3273e2bc7L,
        0x8c42e9c53ef1ed4cL,0x028babf67f4948e8L,0x6a502f438a978632L },
      { 0xf5f13a46b74536feL,0x1d218babd8a9f0ebL,0x30f36bcc37232768L,
        0xc5317b31576e8c18L,0xef1d57a69bbcb766L,0x917c4930b3e3d4dcL } },
    /* 5 */
    { { 0x11426e2ee349ddd0L,0x9f117ef99b2fc250L,0xff36b480ec0174a6L,
        0x4f4bde7618458466L,0x2f2edb6d05806049L,0x8adc75d119dfca92L },
      { 0xa619d097b7d5a7ceL,0x874275e5a34411e9L,0x5403e0470da4b4efL,
        0x2ebaafd977901d8fL,0x5e63ebcea747170fL,0x12a369447f9d8036L } },
    /* 6 */
    { { 0x28f9c07a4fc52870L,0xce0b37481a53a961L,0xd550fa180e1828d9L,
        0xa24abaf76adb225aL,0xd11ed0a56e58a348L,0xf3d811e6948acb62L },
      { 0x8618dd774c61ed22L,0x0bb747f980b47c9dL,0x22bf796fde6b8559L,
        0xfdfd1c6d680a21e9L,0xc0db15772af2c9ddL,0xa09379e6c1e90f3dL } },
    /* 7 */
    { { 0x386c66efe085c629L,0x5fc2a461095bc89aL,0x1353d631203f4b41L,
        0x7ca1972b7e4bd8f5L,0xb077380aa7df8ce9L,0xd8a90389ee7e4ea3L },
      { 0x1bc74dc7e7b14461L,0xdc2cb0140c9c4f78L,0x52b4b3a684ef0a10L,
        0xbde6ea5d20327fe2L,0xb71ec435660f9615L,0xeede5a04b8ad8173L } },
    /* 8 */
    { { 0x5584cbb3893b9a2dL,0x820c660b00850c5dL,0x4126d8267df2d43dL,
        0xdd5bbbf00109e801L,0x85b92ee338172f1cL,0x609d4f93f31430d9L },
      { 0x1e059a07eadaf9d6L,0x70e6536c0f125fb0L,0xd6220751560f20e7L,
        0xa59489ae7aaf3a9aL,0x7b70e2f664bae14eL,0x0dd0370176d08249L } },
    /* 9 */
    { { 0x4cc13be88510521fL,0x87315ba9f724cc17L,0xb49d83bb353dc263L,
        0x8b677efe0c279257L,0x510a1c1cc93c9537L,0x33e30cd8a4702c99L },
      { 0xf0ffc89d2208353fL,0x0170fa8dced42b2bL,0x090851ed26e2a5f5L,
        0x81276455ecb52c96L,0x0646c4e17fe1adf4L,0x513f047eb0868eabL } },
    /* 10 */
    { { 0xc07611f4df5bdf53L,0x45d331a758b11a6dL,0x58965daf1c4ee394L,
        0xba8bebe75a5878d1L,0xaecc0a1882dd3025L,0xcf2a3899a923eb8bL },
      { 0xf98c9281d24fd048L,0x841bfb598bbb025dL,0xb8ddf8cec9ab9d53L,
        0x538a4cb67fef044eL,0x092ac21f23236662L,0xa919d3850b66f065L } },
    /* 11 */
    { { 0x3db03b4085d480d8L,0x8cd9f4791b287a7dL,0x8f24dc754a8f3baeL,
        0x482eb8003db41892L,0x38bf9eb39c56e0f5L,0x8b9773209a91dc6fL },
      { 0xa31b05b27209cfc2L,0x4c49bf8505b2db70L,0x56462498d619527bL,
        0x3fe510391fac51baL,0xfb04f55eab4b8342L,0xc07c10dc04c6eabfL } },
    /* 12 */
    { { 0xad22fe4cdb32f048L,0x5f23bf91475ed6dfL,0xa50ce0c0aa66b6cbL,
        0xdf627a89f03405c0L,0x3674837df95e2d6aL,0x081c95b6ba42e64eL },
      { 0xeba3e036e71d6cebL,0xb45bcccf6c6b0271L,0x67b47e630684701dL,
        0x60f8f942e712523fL,0x824234725cd47adcL,0x83027d7987649cbbL } },
    /* 13 */
    { { 0xb3929ea63615b0b8L,0xb41441fda54dac41L,0x8995d556b5b6a368L,
        0xa80d4529167ef05eL,0xf6bcb4a16d25a27fL,0x210d6a4c7bd55b68L },
      { 0xf3804abb25351130L,0x1d2df699903e37ebL,0x5f201efc084c25c8L,
        0x31a28c87a1c68e91L,0x81dad253563f62a5L,0x5dd6de70d6c415d4L } },
    /* 14 */
    { { 0x29f470fd846612ceL,0x986f3eecda18d997L,0x6b84c1612f34af86L,
        0x5ef0a40846ddaf8bL,0x14405a00e49e795fL,0x5f491b16aa2f7a37L },
      { 0xc7f07ae4db41b38dL,0xef7d119e18fbfcaaL,0x3a18e07614443b19L,
        0x4356841a79a19926L,0x91f4a91ce2226fbeL,0xdc77248c3cc88721L } },
    /* 15 */
    { { 0xd570ff1ae4b1ec9dL,0x21d23e0ee7eef706L,0x3cde40f4ca19e086L,
        0x7d6523c4cd4bb270L,0x16c1f06cbf13aa6cL,0x5aa7245ad14c4b60L },
      { 0x37f8146744b74de8L,0x839e7a17620a934eL,0xf74d14e8de8b1aa1L,
        0x8789fa51f30d75e2L,0x09b24052c81c261eL,0x654e267833c565eeL } },
    /* 16 */
    { { 0x378205de2f9fbe67L,0xc4afcb837f728e44L,0xdbcec06c682e00f1L,
        0xf2a145c3114d5423L,0xa01d98747a52463eL,0xfc0935b17d717b0aL },
      { 0x9653bc4fd4d01f95L,0x9aa83ea89560ad34L,0xf77943dcaf8e3f3fL,
        0x70774a10e86fe16eL,0x6b62e6f1bf9ffdcfL,0x8a72f39e588745c9L } },
    /* 17 */
    { { 0x73ade4da2341c342L,0xdd326e54ea704422L,0x336c7d983741cef3L,
        0x1eafa00d59e61549L,0xcd3ed892bd9a3efdL,0x03faf26cc5c6c7e4L },
      { 0x087e2fcf3045f8acL,0x14a65532174f1e73L,0x2cf84f28fe0af9a7L,
        0xddfd7a842cdc935bL,0x4c0f117b6929c895L,0x356572d64c8bcfccL } },
    /* 18 */
    { { 0x7ecbac017d8c1bbaL,0x6058f9c390b0f3d5L,0xaee116e3f6197d0fL,
        0xc4dd70684033b128L,0xf084dba6c209b983L,0x97c7c2cf831dbc4aL },
      { 0x2f4e61ddf96010e8L,0xd97e4e20529faa17L,0x4ee6666069d37f20L,
        0xccc139ed3d366d72L,0x690b6ee213488e0fL,0x7cad1dc5f3a6d533L } },
    /* 19 */
    { { 0x660a9a81da57a41fL,0xe74a0412ec0039b6L,0x42343c6b5e1dad15L,
        0x284f3ff546681d4cL,0xb51087f163749e89L,0x070f23cc6f9f2f13L },
      { 0x542211da5d186e14L,0x84748f37fddb0dffL,0x41a3aab4db1f4180L,
        0x25ed667ba6402d0eL,0x2f2924a902f58355L,0x5844ee7cfa44a689L } },
    /* 20 */
    { { 0xfab086073f3b236fL,0x19e9d41d81e221daL,0xf3f6571e3927b428L,
        0x4348a9337550f1f6L,0x7167b996a85e62f0L,0x62d437597f5452bfL },
      { 0xd85feb9ef2955926L,0x440a561f6df78353L,0x389668ec9ca36b59L,
        0x052bf1a1a22da016L,0xbdfbff72f6093254L,0x94e50f28e22209f3L } },
    /* 21 */
    { { 0x90b2e5b33062e8afL,0xa8572375e8a3d369L,0x3fe1b00b201db7b1L,
        0xe926def0ee651aa2L,0x6542c9beb9b10ad7L,0x098e309ba2fcbe74L },
      { 0x779deeb3fff1d63fL,0x23d0e80a20bfd374L,0x8452bb3b8768f797L,
        0xcf75bb4d1f952856L,0x8fe6b40029ea3faaL,0x12bd3e4081373a53L } },
    /* 22 */
    { { 0xc023780d104cbba5L,0x6207e747fa35dd4cL,0x35c239281ca9b6a3L,
        0x4ff19be897987b10L,0xb8476bbf8022eee8L,0xaa0a4a14d3bbe74dL },
      { 0x20f94331187d4543L,0x3215387079f6e066L,0x83b0f74eac7e82e1L,
        0xa7748ba2828f06abL,0xc5f0298ac26ef35fL,0x0f0c50708e9a7dbdL } },
    /* 23 */
    { { 0x0c5c244cdef029ddL,0x3dabc687850661b8L,0x9992b865fe11d981L,
        0xe9801b8f6274dbadL,0xe54e6319098da242L,0x9929a91a91a53d08L },
      { 0x37bffd7235285887L,0xbc759425f1418102L,0x9280cc35fd2e6e20L,
        0x735c600cfbc42ee5L,0xb7ad28648837619aL,0xa3627231a778c57bL } },
    /* 24 */
    { { 0xae799b5c91361ed8L,0x47d71b756c63366cL,0x54cdd5211b265a6aL,
        0xe0215a5998d77b74L,0x4424d9b7bab29db0L,0x8b0ffacc7fd9e536L },
      { 0x46d85d1237b5d9efL,0x5b106d62bfa91747L,0xed0479f85f99ba2dL,
        0x0e6f39231d104de4L,0x83a84c8425e8983fL,0xa9507e0af8105a70L } },
    /* 25 */
    { { 0xf6c68a6e14cf381cL,0xaf9d27bdc22e31ccL,0x23568d4daa8a5ccbL,
        0xe431eec0e338e4d2L,0xf1a828fe8f52ad1fL,0xdb6a0579e86acd80L },
      { 0x2885672e4507832aL,0x73fc275f887e5289L,0x65f8027805610d08L,
        0x8d9b4554075ff5b0L,0x3a8e8fb109f712b5L,0x39f0ac862ebe9cf2L } },
    /* 26 */
    { { 0xd8fabf784c52edf5L,0xdcd737e5a589ae53L,0x94918bf0d791ab17L,
        0xb5fbd956bcff06c9L,0xf6d3032edca46d45L,0x2cdff7e141a3e486L },
      { 0x6674b3ba61f47ec8L,0x8a882163eef84608L,0xa257c7054c687f90L,
        0xe30cb2edf6cdf227L,0x2c4c64ca7f6ea846L,0x186fa17ccc6bcd3cL } },
    /* 27 */
    { { 0x48a3f5361dfcb91eL,0x83595e13646d358aL,0xbd15827b91128798L,
        0x3ce612b82187757aL,0x873150a161bd7372L,0xf4684530b662f568L },
      { 0x8833950b401896f6L,0xe11cb89a77f3e090L,0xb2f12cac48e7f4a5L,
        0x313dd769f606677eL,0xfdcf08b316579f93L,0x6429cec946b8f22bL } },
    /* 28 */
    { { 0x4984dd54bb75f9a4L,0x4aef06b929d3b570L,0xb5f84ca23d6e4c1eL,
        0x24c61c11b083ef35L,0xce4a7392392ca9ffL,0x865d65176730a800L },
      { 0xca3dfe76722b4a2bL,0x12c04bf97b083e0eL,0x803ce5b51b86b8a5L,
        0x3fc7632d6a7e3e0cL,0xc89970c2c81adbe4L,0x3cbcd3ad120e16b1L } },
    /* 29 */
    { { 0xfbfb4cc7ec30ce93L,0x10ed6c7db72720a2L,0xec675bf747b55500L,
        0x90725903333ff7c3L,0xc7c3973e5075bfc0L,0xb049ecb007acf31bL },
      { 0xb4076eaf4f58839cL,0x101896daa2b05e4fL,0x3f6033b0ab40c66eL,
        0x19ee9eebc8d864baL,0xeb6cf15547bf6d2aL,0x8e5a9663f826477dL } },
    /* 30 */
    { { 0x69e62fddf7fbd5e1L,0x38ecfe5476912b1dL,0x845a3d56d1da3bfbL,
        0x0494950e1c86f0d4L,0x83cadbf93bc36ce8L,0x41fce5724fccc8d1L },
      { 0x05f939c28332c144L,0xb17f248b0871e46eL,0x3d8534e266e8aff6L,
        0x1d06f1dc3b85c629L,0xdb06a32ea3131b73L,0xf295184d8b3f64e5L } },
    /* 31 */
    { { 0xd9653ff736ddc103L,0x25f43e3795ef606fL,0x09e301fcfe06dce8L,
        0x85af234130b6eebfL,0x79b12b530ff56b20L,0x9b4fb499fe9a3c6bL },
      { 0x0154f89251d27ac2L,0xd33167e356ca5389L,0x7828ec1fafc065a6L,
        0x0959a2587f746c9bL,0xb18f1be30c44f837L,0xa7946117c4132fdbL } },
    /* 32 */
    { { 0xc0426b775e3c647bL,0xbfcbd9398cf05348L,0x31d312e3172c0d3dL,
        0x5f49fde6ee754737L,0x895530f06da7ee61L,0xcf281b0ae8b3a5fbL },
      { 0xfd14973541b8a543L,0x41a625a73080dd30L,0xe2baae07653908cfL,
        0xc3d01436ba02a278L,0xa0d0222e7b21b8f8L,0xfdc270e9d7ec1297L } },
    /* 33 */
    { { 0x00873c0cbc7f41d6L,0xd976113e1b7ad641L,0x2a536ff4238443fbL,
        0x030d00e241e62e45L,0x532e98675f545fc6L,0xcd0331088e91208cL },
      { 0xd1a04c999797612cL,0xd4393e02eea674e2L,0xd56fa69ee19742a1L,
        0xdd2ab48085f0590eL,0xa5cefc5248a2243dL,0x48cc67b654383f41L } },
    /* 34 */
    { { 0x4e50430efc14ab48L,0x195b7f4f26706a74L,0x2fe8a228cc881ff6L,
        0xb1b968e2d945013dL,0x936aa5794b92162bL,0x4fb766b7364e754aL },
      { 0x13f93bca31e1ff7fL,0x696eb5cace4f2691L,0xff754bf8a2b09e02L,
        0x58f13c9ce58e3ff8L,0xb757346f1678c0b0L,0xd54200dba86692b3L } },
    /* 35 */
    { { 0x9a030bbd6dda1265L,0xf7b4f3fce89718ddL,0xa6a4931f936065b8L,
        0xbce72d875f72241cL,0x6cbb51cb65775857L,0xc71618154e993675L },
      { 0xe81a0f792ee32189L,0xef2fab26277dc0b2L,0x9e64f6feb71f469fL,
        0xb448ce33dfdaf859L,0x3f5c1c4cbe6b5df1L,0xfb8dfb001de45f7bL } },
    /* 36 */
    { { 0xc7345fa74d5bb921L,0x5c7e04be4d2b667eL,0x47ed3a80282d7a3eL,
        0x5c2777f87e47b2a4L,0x89b3b10008488e2eL,0x9aad77c2b2eb5b45L },
      { 0xd681bca7daac34aeL,0x2452e4e526afb326L,0x0c88792441a1ee14L,
        0x743b04d4c2407adeL,0xcb5e999bfc17a2acL,0x4dca2f824a701a06L } },
    /* 37 */
    { { 0x68e31ca61127bc1aL,0xa3edd59b17ead3beL,0x67b6b645e25f5a15L,
        0x76221794a420e15eL,0x794fd83b4b1e872eL,0x7cab3f03b2dece1bL },
      { 0x7119bf15ca9b3586L,0xa55459244d250bd7L,0x173633eacc6bcf24L,
        0x9bd308c2b1b6f884L,0x3bae06f5447d38c3L,0x54dcc135f341fe1cL } },
    /* 38 */
    { { 0x56d3598d943caf0dL,0xce044ea9225ff133L,0x9edf6a7c563fadeaL,
        0x632eb94473e8dc27L,0x814b467e3190dcabL,0x2d4f4f316dbb1e31L },
      { 0x8d69811ca143b7caL,0x4ec1ac32de7cf950L,0x223ab5fd37b5fe82L,
        0xe82616e49390f1d9L,0xabff4b2075804610L,0x11b9be15875b08f0L } },
    /* 39 */
    { { 0x4ae31a3d3bbe682cL,0xbc7c5d2674eef2ddL,0x92afd10a3c47dd40L,
        0xec7e0a3bc14ab9e1L,0x6a6c3dd1b2e495e4L,0x085ee5e9309bcd85L },
      { 0xf381a9088c2e67fdL,0x32083a80e261eaf2L,0x0fcd6a4996deee15L,
        0xe3b8fb035e524c79L,0x8dc360d91d5b08b9L,0x3a06e2c87f26719fL } },
    /* 40 */
    { { 0x5cd9f5a87237cac0L,0x93f0b59d43586794L,0x4384a764e94f6c4eL,
        0x8304ed2bb62782d3L,0x0b8db8b3cde06015L,0x4336dd535dbe190fL },
      { 0x5744355392ab473aL,0x031c7275be5ed046L,0x3e78678c21909aa4L,
        0x4ab7e04f99202ddbL,0x2648d2066977e635L,0xd427d184093198beL } },
    /* 41 */
    { { 0x822848f50f9b5a31L,0xbb003468baadb62aL,0x233a04723357559cL,
        0x49ef688079aee843L,0xa89867a0aeb9e1e3L,0xc151931b1f6f9a55L },
      { 0xd264eb0bad74251eL,0x37b9b2634abf295eL,0xb600921b04960d10L,
        0x0de53dbc4da77dc0L,0x01d9bab3d2b18697L,0xad54ec7af7156ddfL } },
    /* 42 */
    { { 0x8e74dc3579efdc58L,0x456bd3694ff68ddbL,0x724e74ccd32096a5L,
        0xe41cff42386783d0L,0xa04c7f217c70d8a4L,0x41199d2fe61a19a2L },
      { 0xd389a3e029c05dd2L,0x535f2a6be7e3fda9L,0x26ecf72d7c2b4df8L,
        0x678275f4fe745294L,0x6319c9cc9d23f519L,0x1e05a02d88048fc4L } },
    /* 43 */
    { { 0x75cc8e2ed4d5ffe8L,0xf8bb4896dbea17f2L,0x35059790cee3cb4aL,
        0x4c06ee85a47c6165L,0xf98fff2592935d2fL,0x34c4a57232ffd7c7L },
      { 0xc4b14806ea0376a2L,0x2ea5e7504f115e02L,0x532d76e21e55d7c0L,
        0x68dc9411f31044daL,0x9272e46571b77993L,0xadaa38bb93a8cfd5L } },
    /* 44 */
    { { 0x4bf0c7127d4ed72aL,0xda0e9264ba1f79a3L,0x48c0258bf4c39ea4L,
        0xa5394ed82a715138L,0x4af511cebf06c660L,0xfcebceefec5c37cdL },
      { 0xf23b75aa779ae8c1L,0xdeff59ccad1e606eL,0xf3f526fd22755c82L,
        0x64c5ab44bb32cefdL,0xa96e11a2915bdefdL,0xab19746a1143813eL } },
    /* 45 */
    { { 0x43c78585ec837d7dL,0xca5b6fbcb8ee0ba4L,0x34e924d9d5dbb5eeL,
        0x3f4fa104bb4f1ca5L,0x15458b72398640f7L,0x4231faa9d7f407eaL },
      { 0x53e0661ef96e6896L,0x554e4c69d03b0f9dL,0xd4fcb07b9c7858d1L,
        0x7e95279352cb04faL,0x5f5f15748974e7f7L,0x2e3fa5586b6d57c8L } },
    /* 46 */
    { { 0x42cd48036a9951a8L,0xa8b15b8842792ad0L,0x18e8bcf9abb29a73L,
        0xbfd9a092409933e8L,0x760a3594efb88dc4L,0x1441886340724458L },
      { 0x162a56ee99caedc7L,0x8fb12ecd91d101c9L,0xea671967393202daL,
        0x1aac8c4aa4ccd796L,0x7db050361cf185a8L,0x0c9f86cd8cfd095aL } },
    /* 47 */
    { { 0x9a72814710b2a556L,0x767ca964327b70b2L,0x04ed9e125e3799b7L,
        0x6781d2dc22a3eb2aL,0x5bd116eb0d9450acL,0xeccac1fca7ebe08aL },
      { 0xde68444fdc2d6e94L,0x3621f42935ecf21bL,0x14e2d54329e03a2cL,
        0x53e42cd57d3e7f0aL,0xbba26c0973ed00b9L,0x00297c39c57d2272L } },
    /* 48 */
    { { 0x3aaaab10b8243a7dL,0x6eeef93e8fa58c5bL,0xf866fca39ae7f764L,
        0x64105a2661ab04d3L,0xa3578d8a03945d66L,0xb08cd3e4791b848cL },
      { 0x45edc5f8756d2411L,0xd4a790d9a755128cL,0xc2cf096349e5f6a0L,
        0xc66d267df649beaaL,0x3ce6d9688467039eL,0x50046c6b42f7816fL } },
    /* 49 */
    { { 0x92ae160266425043L,0x1ff66afdf08db890L,0x386f5a7f8f162ce5L,
        0x18d2dea0fcf5598fL,0x78372b3a1a8ca18eL,0xdf0d20eb8cd0e6f7L },
      { 0x7edd5e1d75bb4045L,0x252a47ceb96d94b7L,0xbdb293582c626776L,
        0x853c394340dd1031L,0x9dc9becf7d5f47fdL,0x27c2302fbae4044aL } },
    /* 50 */
    { { 0x2d1d208a8f2d49ceL,0x0d91aa02162df0a2L,0x9c5cce8709a07f65L,
        0xdf07238b84339012L,0x5028e2c8419442cdL,0x2dcbd35872062abaL },
      { 0xb5fbc3cbe4680967L,0x2a7bc6459f92d72cL,0x806c76e1116c369dL,
        0x5c50677a3177e8d8L,0x753739eb4569df57L,0x2d481ef636c3f40bL } },
    /* 51 */
    { { 0x1a2d39fdfea1103eL,0xeaae559295f81b17L,0xdbd0aa18f59b264aL,
        0x90c39c1acb592ee0L,0xdf62f80d9750cca3L,0xda4d8283df97cc6cL },
      { 0x0a6dd3461e201067L,0x1531f85969fb1f6bL,0x4895e5521d60121fL,
        0x0b21aab04c041c91L,0x9d896c46bcc1ccf8L,0xd24da3b33141bde7L } },
    /* 52 */
    { { 0x575a053753b0a354L,0x392ff2f40c6ddcd8L,0x0b8e8cff56157b94L,
        0x073e57bd3b1b80d1L,0x2a75e0f03fedee15L,0x752380e4aa8e6f19L },
      { 0x1f4e227c6558ffe9L,0x3a34861819ec5415L,0xab382d5ef7997085L,
        0x5e6deaffddc46ac2L,0xe5144078fc8d094cL,0xf674fe51f60e37c6L } },
    /* 53 */
    { { 0x6fb87ae5af63408fL,0xa39c36a9cd75a737L,0x7833313fcf4c618dL,
        0xfbcd4482f034c88dL,0x4469a76139b35288L,0x77a711c566b5d9c9L },
      { 0x4a695dc7944f8d65L,0xe6da5f65161aaba8L,0x8654e9c324601669L,
        0xbc8b93f528ae7491L,0x5f1d1e838f5580d8L,0x8ccf9a1acea32cc8L } },
    /* 54 */
    { { 0x28ab110c7196fee2L,0x75799d63874c8945L,0xa262934829aedaddL,
        0x9714cc7b2be88ff4L,0xf71293cfd58d60d6L,0xda6b6cb332a564e9L },
      { 0xf43fddb13dd821c2L,0xf2f2785f90dd323dL,0x91246419048489f8L,
        0x61660f26d24c6749L,0x961d9e8cc803c15cL,0x631c6158faadc4c9L } },
    /* 55 */
    { { 0xacf2ebe0fd752366L,0xb93c340e139be88bL,0x98f664850f20179eL,
        0x14820254ff1da785L,0x5278e2764f85c16eL,0xa246ee457aab1913L },
      { 0x43861eb453763b33L,0xc49f03fc45c0bc0dL,0xafff16bcad6b1ea1L,
        0xce33908b6fd49c99L,0x5c51e9bff7fde8c3L,0x076a7a39ff142c5eL } },
    /* 56 */
    { { 0x04639dfe9e338d10L,0x8ee6996ff42b411bL,0x960461d1a875cef2L,
        0x1057b6d695b4d0baL,0x27639252a906e0bcL,0x2c19f09ae1c20f8aL },
      { 0x5b8fc3f0eef4c43dL,0xe2e1b1a807a84aa9L,0x5f455528835d2bdbL,
        0x0f4aee4d207132ddL,0xe9f8338c3907f675L,0x7a874dc90e0531f0L } },
    /* 57 */
    { { 0x84b22d4597c27050L,0xbd0b8df759e70bf8L,0xb4d6740579738b9bL,
        0x47f4d5f5cd917c4fL,0x9099c4ce13ce6e33L,0x942bfd39521d0f8bL },
      { 0x5028f0f6a43b566dL,0xaf6e866921bff7deL,0x83f6f856c44232cdL,
        0x65680579f915069aL,0xd12095a2ecfecb85L,0xcf7f06aedb01ba16L } },
    /* 58 */
    { { 0x0f56e3c48ef96c80L,0xd521f2b33ddb609cL,0x2be941027dc1450dL,
        0x2d21a07102a91fe2L,0x2e6f74fa1efa37deL,0x9a9a90b8156c28a1L },
      { 0xc54ea9ea9dc7dfcbL,0xc74e66fc2c2c1d62L,0x9f23f96749d3e067L,
        0x1c7c3a4654dd38adL,0xc70058845946cee3L,0x8985636845cc045dL } },
    /* 59 */
    { { 0x29da7cd4fce73946L,0x8f697db523168563L,0x8e235e9ccba92ec6L,
        0x55d4655f9f91d3eaL,0xf3689f23aa50a6cdL,0xdcf21c2621e6a1a0L },
      { 0xcffbc82e61b818bfL,0xc74a2f96da47a243L,0x234e980a8bc1a0cfL,
        0xf35fd6b57929cb6dL,0x81468e12efe17d6cL,0xddea6ae558b2dafbL } },
    /* 60 */
    { { 0x294de8877e787b2eL,0x258acc1f39a9310dL,0x92d9714aac14265dL,
        0x18b5591c708b48a0L,0x27cc6bb0e1abbf71L,0xc0581fa3568307b9L },
      { 0x9e0f58a3f24d4d58L,0xfebe9bb8e0ce2327L,0x91fd6a419d1be702L,
        0x9a7d8a45facac993L,0xabc0a08c9e50d66dL,0x02c342f706498201L } },
    /* 61 */
    { { 0xccd71407157bdbc2L,0x72fa89c6ad0e1605L,0xb1d3da2bb92a015fL,
        0x8ad9e7cda0a3fe56L,0x160edcbd24f06737L,0x79d4db3361275be6L },
      { 0xd3d31fd95f3497c4L,0x8cafeaee04192fb0L,0xe13ca74513a50af3L,
        0x188261678c85aae5L,0xce06cea89eb556ffL,0x2eef1995bdb549f3L } },
    /* 62 */
    { { 0x8ed7d3eb50596edcL,0xaa359362905243a2L,0xa212c2c2a4b6d02bL,
        0x611fd727c4fbec68L,0x8a0b8ff7b84f733dL,0xd85a6b905f0daf0eL },
      { 0x60e899f5d4091cf7L,0x4fef2b672eff2768L,0xc1f195cb10c33964L,
        0x8275d36993626a8fL,0xc77904f40d6c840aL,0x88d8b7fd7a868acdL } },
    /* 63 */
    { { 0x85f237237bd98425L,0xd4463992c70b154eL,0xcbb00ee296687a2eL,
        0x905fdbf7c83214fdL,0x2019d29313593684L,0x0428c393ef51218eL },
      { 0x40c7623f981e909aL,0x925133857be192daL,0x48fe480f4010907eL,
        0xdd7a187c3120b459L,0xc9d7702da1fd8f3cL,0x66e4753be358efc5L } },
    /* 64 */
    { { 0x070d34e116973cf4L,0x20aee08b7e4f34f7L,0x269af9b95eb8ad29L,
        0xdde0a036a6a45ddaL,0xa18b528e63df41e0L,0x03cc71b2a260df2aL },
      { 0x24a6770aa06b1dd7L,0x5bfa9c119d2675d3L,0x73c1e2a196844432L,
        0x3660558d131a6cf0L,0xb0289c832ee79454L,0xa6aefb01c6d8ddcdL } },
    /* 65 */
    { { 0xba1464b401ab5245L,0x9b8d0b6dc48d93ffL,0x939867dc93ad272cL,
        0xbebe085eae9fdc77L,0x73ae5103894ea8bdL,0x740fc89a39ac22e1L },
      { 0x5e28b0a328e23b23L,0x2352722ee13104d0L,0xf4667a18b0a2640dL,
        0xac74a72e49bb37c3L,0x79f734f0e81e183aL,0xbffe5b6c3fd9c0ebL } },
    /* 66 */
    { { 0xb1a358f5c6a2123fL,0x927b2d95fe28df6dL,0x89702753f199d2f9L,
        0x0a73754c1a3f82dcL,0x063d029d777affe1L,0x5439817edae6d34dL },
      { 0xf7979eef6b8b83c4L,0x615cb2149d945682L,0x8f0e4facc5e57eaeL,
        0x042b89b8113047ddL,0x888356dc93f36508L,0xbf008d185fd1f32fL } },
    /* 67 */
    { { 0x8012aa244e8068dbL,0xc72cc641a5729a47L,0x3c33df2c43f0691dL,
        0xfa0573471d92145fL,0xaefc0f2fb97f7946L,0x813d75cb2f8121bfL },
      { 0x05613c724383bba6L,0xa924ce70a4224b3fL,0xe59cecbe5f2179a6L,
        0x78e2e8aa79f62b61L,0x3ac2cc3b53ad8079L,0x55518d71d8f4fa96L } },
    /* 68 */
    { { 0x03cf292200623f3bL,0x095c71115f29ebffL,0x42d7224780aa6823L,
        0x044c7ba17458c0b0L,0xca62f7ef0959ec20L,0x40ae2ab7f8ca929fL },
      { 0xb8c5377aa927b102L,0x398a86a0dc031771L,0x04908f9dc216a406L,
        0xb423a73a918d3300L,0x634b0ff1e0b94739L,0xe29de7252d69f697L } },
    /* 69 */
    { { 0x744d14008435af04L,0x5f255b1dfec192daL,0x1f17dc12336dc542L,
        0x5c90c2a7636a68a8L,0x960c9eb77704ca1eL,0x9de8cf1e6fb3d65aL },
      { 0xc60fee0d511d3d06L,0x466e2313f9eb52c7L,0x743c0f5f206b0914L,
        0x42f55bac2191aa4dL,0xcefc7c8fffebdbc2L,0xd4fa6081e6e8ed1cL } },
    /* 70 */
    { { 0xb5e405d3b0ab9645L,0xaeec7f98d5f1f711L,0x8ad42311585c2a6eL,
        0x045acb9e512c6944L,0xae106c4ea90db1c6L,0xb89f33d5898e6563L },
      { 0x43b07cd97fed2ce4L,0xf9934e17dd815b20L,0x6778d4d50a81a349L,
        0x9e616ade52918061L,0xfa06db06d7e67112L,0x1da23cf188488091L } },
    /* 71 */
    { { 0x821c46b342f2c4b5L,0x931513ef66059e47L,0x7030ae4366f50cd1L,
        0x43b536c943e7b127L,0x006258cf5fca5360L,0xe4e3ee796b557abfL },
      { 0xbb6b390024c8b22fL,0x2eb5e2c1fcbf1054L,0x937b18c9567492afL,
        0xf09432e4acf53957L,0x585f5a9d1dbf3a56L,0xf86751fdbe0887cfL } },
    /* 72 */
    { { 0x157399cb9d10e0b2L,0x1c0d595660dc51b7L,0x1d496b8a1f583090L,
        0x6658bc2688590484L,0x88c08ab703213f28L,0x8d2e0f737ae58de4L },
      { 0x9b79bc95486cfee6L,0x036a26c7e9e5bc57L,0x1ad03601cd8ae97aL,
        0x06907f87ff3a0494L,0x078f4bbf2c7eb584L,0xe3731bf57e8d0a5aL } },
    /* 73 */
    { { 0x72f2282be1cd0abeL,0xd4f9015e87efefa2L,0x9d1898066c3834bdL,
        0x9c8cdcc1b8a29cedL,0x0601b9f4fee82ebcL,0x371052bc7206a756L },
      { 0x76fa109246f32562L,0xdaad534c17351bb4L,0xc3d64c37b3636bb5L,
        0x038a8c5145d54e00L,0x301e618032c09e7cL,0x9764eae795735151L } },
    /* 74 */
    { { 0x8791b19fcbd5256aL,0x4007e0f26ca13a3bL,0x03b794604cf06904L,
        0xb18a9c22b6c17589L,0xa1cb7d7d81d45908L,0x6e13fa9d21bb68f1L },
      { 0x47183c62a71e6e16L,0x5cf0ef8ee18749edL,0x2c9c7f9b2e5ed409L,
        0x042eeacce6e117e1L,0xb86d481613fb5a7fL,0xea1cf0edc9e5feb1L } },
    /* 75 */
    { { 0x6e6573c9cea4cc9bL,0x5417961dafcec8f3L,0x804bf02aa438b6f6L,
        0xb894b03cdcd4ea88L,0xd0f807e93799571fL,0x3466a7f5862156e8L },
      { 0x51e59acd56515664L,0x55b0f93ca3c5eb0bL,0x84a06b026a4279dbL,
        0x5c850579c5fae08eL,0xcf07b8dba663a1a2L,0x49a36bbcf46ffc8dL } },
    /* 76 */
    { { 0xe47f5acc46d93106L,0x65b7ade0aa897c9cL,0x37cf4c9412d7e4beL,
        0xa2ae9b80d4b2caa9L,0x5e7ce09ce60357a3L,0x29f77667c8ecd5f9L },
      { 0xdf6868f5a8a0b1c5L,0x240858cf62978ad8L,0x0f7ac101dc0002a1L,
        0x1d28a9d7ffe9aa05L,0x744984d65b962c97L,0xa8a7c00b3d28c8b2L } },
    /* 77 */
    { { 0x7c58a852ae11a338L,0xa78613f1d1af96e7L,0x7e9767d25355cc73L,
        0x6ba37009792a2de6L,0x7d60f618124386b2L,0xab09b53111157674L },
      { 0x95a0484198eb9dd0L,0xe6c17acc15070328L,0xafc6da45489c6e49L,
        0xab45a60abb211530L,0xc58d65927d7ea933L,0xa3ef3c65095642c6L } },
    /* 78 */
    { { 0x89d420e9df010879L,0x9d25255d39576179L,0x9cdefd50e39513b6L,
        0xe4efe45bd5d1c313L,0xc0149de73f7af771L,0x55a6b4f4340ab06bL },
      { 0xf1325251ebeaf771L,0x2ab44128878d4288L,0xfcd5832e18e05afeL,
        0xef52a348cc1fb62bL,0x2bd08274c1c4792aL,0x345c5846877c6dc7L } },
    /* 79 */
    { { 0xde15ceb0bea65e90L,0x0987f72b2416d99cL,0x44db578dfd863decL,
        0xf617b74bac6a3578L,0x9e62bd7adb48e999L,0x877cae61eab1a1beL },
      { 0x23adddaa3a358610L,0x2fc4d6d1325e2b07L,0x897198f51585754eL,
        0xf741852cb392b584L,0x9927804cb55f7de1L,0xe9e6c4ed1aa8efaeL } },
    /* 80 */
    { { 0x867db63998683186L,0xfb5cf424ddcc4ea9L,0xcc9a7ffed4f0e7bdL,
        0x7c57f71c7a779f7eL,0x90774079d6b25ef2L,0x90eae903b4081680L },
      { 0xdf2aae5e0ee1fcebL,0x3ff1da24e86c1a1fL,0x80f587d6ca193edfL,
        0xa5695523dc9b9d6aL,0x7b84090085920303L,0x1efa4dfcba6dbdefL } },
    /* 81 */
    { { 0xfbd838f9e0540015L,0x2c323946c39077dcL,0x8b1fb9e6ad619124L,
        0x9612440c0ca62ea8L,0x9ad9b52c2dbe00ffL,0xf52abaa1ae197643L },
      { 0xd0e898942cac32adL,0xdfb79e4262a98f91L,0x65452ecf276f55cbL,
        0xdb1ac0d27ad23e12L,0xf68c5f6ade4986f0L,0x389ac37b82ce327dL } },
    /* 82 */
    { { 0x511188b4f8e60f5bL,0x7fe6701548aa2adaL,0xdb333cb8381abca2L,
        0xb15e6d9ddaf3fc97L,0x4b24f6eb36aabc03L,0xc59789df72a748b4L },
      { 0x26fcb8a529cf5279L,0x7a3c6bfc01ad9a6cL,0x866cf88d4b8bac9bL,
        0xf4c899899c80d041L,0xf0a0424170add148L,0x5a02f47945d81a41L } },
    /* 83 */
    { { 0xfa5c877cc1c90202L,0xd099d440f8ac7570L,0x428a5b1bd17881f7L,
        0x61e267db5b2501d7L,0xf889bf04f2e4465bL,0x4da3ae0876aa4cb8L },
      { 0x3ef0fe26e3e66861L,0x5e7729533318b86dL,0xc3c35fbc747396dfL,
        0x5115a29c439ffd37L,0xbfc4bd97b2d70374L,0x088630ea56246b9dL } },
    /* 84 */
    { { 0xcd96866db8a9e8c9L,0xa11963b85bb8091eL,0xc7f90d53045b3cd2L,
        0x755a72b580f36504L,0x46f8b39921d3751cL,0x4bffdc9153c193deL },
      { 0xcd15c049b89554e7L,0x353c6754f7a26be6L,0x79602370bd41d970L,
        0xde16470b12b176c0L,0x56ba117540c8809dL,0xe2db35c3e435fb1eL } },
    /* 85 */
    { { 0xd71e4aab6328e33fL,0x5486782baf8136d1L,0x07a4995f86d57231L,
        0xf1f0a5bd1651a968L,0xa5dc5b2476803b6dL,0x5c587cbc42dda935L },
      { 0x2b6cdb32bae8b4c0L,0x66d1598bb1331138L,0x4a23b2d25d7e9614L,
        0x93e402a674a8c05dL,0x45ac94e6da7ce82eL,0xeb9f8281e463d465L } },
    /* 86 */
    { { 0x34e0f9d1fecf5b9bL,0xa115b12bf206966aL,0x5591cf3b1eaa0534L,
        0x5f0293cbfb1558f9L,0x1c8507a41bc703a5L,0x92e6b81c862c1f81L },
      { 0xcc9ebc66cdaf24e3L,0x68917ecd72fcfc70L,0x6dc9a9308157ba48L,
        0x5d425c08b06ab2b2L,0x362f8ce736e929c4L,0x09f6f57c62e89324L } },
    /* 87 */
    { { 0x1c7d6b78d29375fbL,0xfabd851ee35d1157L,0xf6f62dcd4243ea47L,
        0x1dd924608fe30b0fL,0x08166dfaffc6e709L,0xc6c4c6930881e6a7L },
      { 0x20368f87d6a53fb0L,0x38718e9f9eb4d1f9L,0x03f08acdafd7e790L,
        0x0835eb4472fe2a1cL,0x7e05090388076e5dL,0x538f765ea638e731L } },
    /* 88 */
    { { 0x0e0249d9c2663b4bL,0xe700ab5b47cd38ddL,0xb192559d2c46559fL,
        0x8f9f74a84bcde66dL,0xad1615233e2aced5L,0xc155c0473dd03a5bL },
      { 0x346a87993be454ebL,0x66ee94db83b7dccdL,0x1f6d8378ab9d2abeL,
        0x4a396dd27733f355L,0x419bd40af53553c2L,0xd0ead98d731dd943L } },
    /* 89 */
    { { 0x908e0b0eec142408L,0x98943cb94114b310L,0x03dbf7d81742b1d7L,
        0xd270df6b693412f4L,0xc50654948f69e20cL,0xa76a90c3697e43a1L },
      { 0xe0fa33844624825aL,0x82e48c0b8acc34c2L,0x7b24bd14e9a14f2bL,
        0x4f5dd5e24db30803L,0x0c77a9e7932da0a3L,0x20db90f274c653dcL } },
    /* 90 */
    { { 0x261179b70e6c5fd9L,0xf8bec1236c982eeaL,0x47683338d4957b7eL,
        0xcc47e6640a72f66aL,0xbd54bf6a1bad9350L,0xdfbf4c6af454e95aL },
      { 0x3f7a7afa6907f4faL,0x7311fae0865ca735L,0x24737ab82a496adaL,
        0x13e425f115feb79bL,0xe9e97c50a1b93c21L,0xb26b6eac4ddd3eb5L } },
    /* 91 */
    { { 0x81cab9f52a2e5f2bL,0xf93caf29bf385ac4L,0xf4bf35c3c909963aL,
        0x081e730074c9143cL,0x3ea57fa8c281b4c5L,0xe497905c9b340741L },
      { 0xf556dd8a55ab3cfbL,0xd444b96b518db6adL,0x34f5425a5ef4b955L,
        0xdda7a3acecd26aa3L,0xb57da11bda655e97L,0x02da3effc2024c70L } },
    /* 92 */
    { { 0xe24b00366481d0d9L,0x3740dbe5818fdfe2L,0xc1fc1f45190fda00L,
        0x329c92803cf27fdeL,0x7435cb536934f43eL,0x2b505a5d7884e8feL },
      { 0x6cfcc6a6711adcc9L,0xf034325c531e21e1L,0xa2f4a9679b2a8a99L,
        0x9d5f38423c21bdffL,0xb25c781131b57d66L,0xdb5344d80b8093b9L } },
    /* 93 */
    { { 0x0d72e667ae50a2f5L,0x9b7f8d8ae4a861d1L,0xa129f70f330df1cbL,
        0xe90aa5d7e04fefc3L,0xff561ecbe72c3ae1L,0x0d8fb428cdb955faL },
      { 0xd2235f73d7663784L,0xc05baec67e2c456aL,0xe5c292e42adbfcccL,
        0x4fd17988efb110d5L,0x27e57734d19d49f3L,0x188ac4ce84f679feL } },
    /* 94 */
    { { 0x7ee344cfa796c53eL,0xbbf6074d0868009bL,0x1f1594f7474a1295L,
        0x66776edcac11632dL,0x1862278b04e2fa5aL,0x52665cf2c854a89aL },
      { 0x7e3764648104ab58L,0x167759137204fd6dL,0x86ca06a544ea1199L,
        0xaa3f765b1c9240ddL,0x5f8501a924746149L,0x7b982e30dcd251d7L } },
    /* 95 */
    { { 0xe44e9efcc15f3060L,0x5ad62f2ea87ebbe6L,0x36499d41c79500d4L,
        0xa66d6dc0336fa9d1L,0xf8afc4955afd3b1fL,0x1d8ccb24e5c9822bL },
      { 0x4031422b79d7584bL,0xc54a0580ea3f20ddL,0x3f837c8f958468c5L,
        0x3d82f110fbea7735L,0x679a87787dffe2fcL,0x48eba63b20704803L } },
    /* 96 */
    { { 0x89b10d41df46e2f6L,0x13ab57f819514367L,0x067372b91d469c87L,
        0x0c195afa4f6c5798L,0xea43a12a272c9acfL,0x9dadd8cb678abdacL },
      { 0xcce56c6be182579aL,0x86febadb2d26c2d8L,0x1c668ee12a44745cL,
        0x580acd8698dc047aL,0x5a2b79cc51b9ec2dL,0x007da6084054f6a0L } },
    /* 97 */
    { { 0x9e3ca35217b00dd0L,0x046779cb0e81a7a6L,0xb999fef3d482d871L,
        0xe6f38134d9233fbcL,0x112c3001f48cd0e0L,0x934e75763c6c66aeL },
      { 0xb44d4fc3d73234dcL,0xfcae2062864eafc1L,0x843afe2526bef21aL,
        0x61355107f3b75fdfL,0x8367a5aa794c2e6bL,0x3d2629b18548a372L } },
    /* 98 */
    { { 0x6230618f437cfaf8L,0x5b8742cb2032c299L,0x949f72472293643aL,
        0xb8040f1a09464f79L,0x049462d24f254143L,0xabd6b522366c7e76L },
      { 0x119b392bd5338f55L,0x1a80a9ce01495a0cL,0xf3118ca7f8d7537eL,
        0xb715adc26bf4b762L,0x24506165a8482b6cL,0xd958d7c696a7c84dL } },
    /* 99 */
    { { 0x9ad8aa87bdc21f31L,0xadb3cab48063e58cL,0xefd86283b07dd7b8L,
        0xc7b9b7621be7c6b4L,0x2ef58741015582deL,0xc970c52e299addf3L },
      { 0x78f02e2a22f24d66L,0xefec1d1074cc100aL,0xaf2a6a3909316e1aL,
        0xce7c22055849dd49L,0x9c1fe75c96bffc4cL,0xcad98fd27ba06ec0L } },
    /* 100 */
    { { 0xed76e2d0b648b73eL,0xa9f92ce51cfd285eL,0xa8c86c062ed13de1L,
        0x1d3a574ea5191a93L,0x385cdf8b1ad1b8bfL,0xbbecc28a47d2cfe3L },
      { 0x98d326c069cec548L,0x4f5bc1ddf240a0b2L,0x241a706229057236L,
        0x0fc6e9c5c68294a4L,0x4d04838ba319f17aL,0x8b612cf19ffc1c6fL } },
    /* 101 */
    { { 0x9bb0b5014c3830ebL,0x3d08f83c8ee0d0c5L,0xa4a6264279ba9389L,
        0x5d5d40449cbc2914L,0xae9eb83e074c46f0L,0x63bb758f74ead7d6L },
      { 0x1c40d2eac6bb29e0L,0x95aa2d874b02f41eL,0x9298917553cb199aL,
        0xdd91bafe51584f6dL,0x3715efb931a1aaecL,0xc1b6ae5b46780f9eL } },
    /* 102 */
    { { 0xcded3e4b42772f41L,0x3a700d5d3bcb79d1L,0x4430d50e80feee60L,
        0x444ef1fcf5e5d4bbL,0xc660194fe6e358ffL,0xe68a2f326a91b43cL },
      { 0x5842775c977fe4d2L,0x78fdef5c7e2a41ebL,0x5f3bec02ff8df00eL,
        0xf4b840cd5852525dL,0x0870483a4e6988bdL,0x39499e39cc64b837L } },
    /* 103 */
    { { 0xfc05de80b08df5feL,0x0c12957c63ba0362L,0xea379414d5cf1428L,
        0xc559132a54ef6216L,0x33d5f12fb9e65cf8L,0x09c602781695d663L },
      { 0x3ac1ced461f7a2fbL,0xdd838444d4f5eeb8L,0x82a38c6c8318fcadL,
        0x315be2e5e9f1a864L,0x317b5771442daf47L,0x81b5904a95aa5f9eL } },
    /* 104 */
    { { 0x6b6b1c508b21d232L,0x87f3dbc08c2cba75L,0xa7e74b46ae9f0fafL,
        0x036a0985bb7b8079L,0x4f185b908d974a25L,0x5aa7cef0d9af5ec9L },
      { 0xe0566a7057dcfffcL,0x6ea311dab8453225L,0x72ea1a8d23368aa9L,
        0xed9b208348cd552dL,0xb987967cc80ea435L,0xad735c756c104173L } },
    /* 105 */
    { { 0xaea85ab3cee76ef4L,0x44997444af1d2b93L,0x0851929beacb923fL,
        0xb080b59051e3bc0cL,0xc4ee1d8659be68a2L,0xf00de21964b26cdaL },
      { 0x8d7fb5c0f2e90d4dL,0x00e219a777d9ec64L,0xc4e6febd5d1c491cL,
        0x080e37541a8f4585L,0x4a9b86c848d2af9cL,0x2ed70db6b6679851L } },
    /* 106 */
    { { 0xaee44116586f25cbL,0xf7b6861fa0fcf70fL,0x55d2cd2018a350e8L,
        0x861bf3e592dc286fL,0x9ab18ffa6226aba7L,0xd15827bea9857b03L },
      { 0x26c1f54792e6acefL,0x422c63c8ac1fbac3L,0xa2d8760dfcbfd71dL,
        0x35f6a539b2511224L,0xbaa88fa1048d1a21L,0x49f1abe9ebf999dbL } },
    /* 107 */
    { { 0x16f9f4f4f7492b73L,0xcf28ec1ecb392b1aL,0x45b130d469ca6ffcL,
        0x28ba8d40b72efa58L,0xace987c75ca066f5L,0x3e3992464ad022ebL },
      { 0x63a2d84e752555bbL,0xaaa93b4a9c2ae394L,0xcd80424ec89539caL,
        0x6d6b5a6daa119a99L,0xbd50334c379f2629L,0x899e925eef3cc7d3L } },
    /* 108 */
    { { 0xb7ff3651bf825dc4L,0x0f741cc440b9c462L,0x771ff5a95cc4fb5bL,
        0xcb9e9c9b47fd56feL,0xbdf053db5626c0d3L,0xa97ce675f7e14098L },
      { 0x68afe5a36c934f5eL,0x6cd5e148ccefc46fL,0xc7758570d7a88586L,
        0x49978f5edd558d40L,0xa1d5088a64ae00c1L,0x58f2a720f1d65bb2L } },
    /* 109 */
    { { 0x66fdda4a3e4daedbL,0x38318c1265d1b052L,0x28d910a24c4bbf5cL,
        0x762fe5c478a9cd14L,0x08e5ebaad2cc0aeeL,0xd2cdf257ca0c654cL },
      { 0x48f7c58b08b717d2L,0x3807184a386cd07aL,0x3240f626ae7d0112L,
        0x03e9361bc43917b0L,0xf261a87620aea018L,0x53f556a47e1e6372L } },
    /* 110 */
    { { 0xc84cee562f512a90L,0x24b3c0041b0ea9f1L,0x0ee15d2de26cc1eaL,
        0xd848762cf0c9ef7dL,0x1026e9c5d5341435L,0x8f5b73dcfdb16b31L },
      { 0x1f69bef2d2c75d95L,0x8d33d581be064ddaL,0x8c024c1257ed35e6L,
        0xf8d435f9c309c281L,0xfd295061d6960193L,0x66618d78e9e49541L } },
    /* 111 */
    { { 0x571cfd458ce382deL,0x175806eede900ddeL,0x6184996534aba3b5L,
        0xe899778ade7aec95L,0xe8f00f6eff4aa97fL,0xae971cb5010b0c6dL },
      { 0x1827eebc3af788f1L,0xd46229ffe413fe2dL,0x8a15455b4741c9b4L,
        0x5f02e690f8e424ebL,0x40a1202edae87712L,0x49b3bda264944f6dL } },
    /* 112 */
    { { 0xd63c6067035b2d69L,0xb507150d6bed91b0L,0x1f35f82f7afb39b2L,
        0xb9bd9c0116012b66L,0x00d97960ed0a5f50L,0xed7054512716f7c9L },
      { 0x1576eff4127abdb4L,0x6850d698f01e701cL,0x9fa7d7493fc87e2fL,
        0x0b6bcc6fb0ce3e48L,0xf4fbe1f5f7d8c1c0L,0xcf75230e02719cc6L } },
    /* 113 */
    { { 0x6761d6c2722d94edL,0xd1ec3f213718820eL,0x65a40b7025d0e7c6L,
        0xd67f830ebaf3cf31L,0x633b3807b93ea430L,0x17faa0ea0bc96c69L },
      { 0xe6bf3482df866b98L,0x205c1ee9a9db52d4L,0x51ef9bbdff9ab869L,
        0x3863dad175eeb985L,0xef216c3bd3cf442aL,0x3fb228e3f9c8e321L } },
    /* 114 */
    { { 0x94f9b70c0760ac07L,0xf3c9ccae9d79bf4dL,0x73cea084c5ffc83dL,
        0xef50f943dc49c38eL,0xf467a2aebc9e7330L,0x5ee534b644ea7fbaL },
      { 0x20cb627203609e7fL,0x0984435562fdc9f0L,0xaf5c8e580f1457f7L,
        0xd1f50a6cb4b25941L,0x77cb247c2ec82395L,0xa5f3e1e5da3dca33L } },
    /* 115 */
    { { 0x023489d67d85fa94L,0x0ba405372db9ce47L,0x0fdf7a1faed7aad1L,
        0xa57b0d739a4ccb40L,0x48fcec995b18967cL,0xf30b5b6eb7274d24L },
      { 0x7ccb4773c81c5338L,0xb85639e6a3ed6bd0L,0x7d9df95f1d56eadaL,
        0xe256d57f0a1607adL,0x6da7ffdc957574d6L,0x65f8404601c7a8c4L } },
    /* 116 */
    { { 0x8d45d0cbcba1e7f1L,0xef0a08c002b55f64L,0x771ca31b17e19892L,
        0xe1843ecb4885907eL,0x67797ebc364ce16aL,0x816d2b2d8df4b338L },
      { 0xe870b0e539aa8671L,0x9f0db3e4c102b5f5L,0x342966591720c697L,
        0x0ad4c89e613c0d2aL,0x1af900b2418ddd61L,0xe087ca72d336e20eL } },
    /* 117 */
    { { 0x222831ffaba10079L,0x0dc5f87b6d64fff2L,0x445479073e8cb330L,
        0xe815aaa2702a33fbL,0x338d6b2e5fba3215L,0x0f7535cb79f549c8L },
      { 0x471ecd972ee95923L,0x1e868b37c6d1c09fL,0x2bc7b8ecc666ef4eL,
        0xf5416589808a4bfcL,0xf23e9ee23fbc4d2eL,0x4357236c2d75125bL } },
    /* 118 */
    { { 0xfe176d95ba9cdb1bL,0x45a1ca012f82791eL,0x97654af24de4cca2L,
        0xbdbf9d0e5cc4bcb9L,0xf6a7df50ad97ac0aL,0xc52112b061359fd6L },
      { 0x696d9ce34f05eae3L,0x903adc02e943ac2bL,0xa90753470848be17L,
        0x1e20f1702a3973e5L,0xe1aacc1c6feb67e9L,0x2ca0ac32e16bc6b9L } },
    /* 119 */
    { { 0xffea12e4ef871eb5L,0x94c2f25da8bf0a7aL,0x4d1e4c2a78134eaaL,
        0x11ed16fb0360fb10L,0x4029b6db85fc11beL,0x5e9f7ab7f4d390faL },
      { 0x5076d72f30646612L,0xa0afed1ddda1d0d8L,0x2902225785a1d103L,
        0xcb499e174e276bcdL,0x16d1da7151246c3dL,0xc72d56d3589a0443L } },
    /* 120 */
    { { 0xdf5ffc74dae5bb45L,0x99068c4a261bd6dcL,0xdc0afa7aaa98ec7bL,
        0xedd2ee00f121e96dL,0x163cc7be1414045cL,0xb0b1bbce335af50eL },
      { 0xd440d78501a06293L,0xcdebab7c6552e644L,0x48cb8dbc8c757e46L,
        0x81f9cf783cabe3cbL,0xddd02611b123f59aL,0x3dc7b88eeeb3784dL } },
    /* 121 */
    { { 0xe1b8d398c4741456L,0xa9dfa9026032a121L,0x1cbfc86d1263245bL,
        0xf411c7625244718cL,0x96521d5405b0fc54L,0x1afab46edbaa4985L },
      { 0xa75902ba8674b4adL,0x486b43ad5ad87d12L,0x72b1c73636e0d099L,
        0x39890e07bb6cd6d6L,0x8128999c59bace4eL,0xd8da430b7b535e33L } },
    /* 122 */
    { { 0x39f65642c6b75791L,0x050947a621806bfbL,0x0ca3e3701362ef84L,
        0x9bc60aed8c3d2391L,0x9b488671732e1ddcL,0x12d10d9ea98ee077L },
      { 0xb6f2822d3651b7dcL,0x6345a5ba80abd138L,0x62033262472d3c84L,
        0xd54a1d40acc57527L,0x6ea46b3a424447cbL,0x5bc410572fb1a496L } },
    /* 123 */
    { { 0xe70c57a3a751cd0eL,0x190d8419eba3c7d6L,0xb1c3bee79d47d55aL,
        0xda941266f912c6d8L,0x12e9aacc407a6ad6L,0xd6ce5f116e838911L },
      { 0x063ca97b70e1f2ceL,0xa3e47c728213d434L,0xa016e24184df810aL,
        0x688ad7b0dfd881a4L,0xa37d99fca89bf0adL,0xd8e3f339a23c2d23L } },
    /* 124 */
    { { 0xbdf53163750bed6fL,0x808abc3283e68b0aL,0x85a366275bb08a33L,
        0xf72a3a0f6b0e4abeL,0xf7716d19faf0c6adL,0x22dcc0205379b25fL },
      { 0x7400bf8df9a56e11L,0x6cb8bad756a47f21L,0x7c97176f7a6eb644L,
        0xe8fd84f7d1f5b646L,0x98320a9444ddb054L,0x07071ba31dde86f5L } },
    /* 125 */
    { { 0x6fdfa0e598f8fcb9L,0x89cec8e094d0d70cL,0xa0899397106d20a8L,
        0x915bfb9aba8acc9cL,0x1370c94b5507e01cL,0x83246a608a821ffbL },
      { 0xa8273a9fbe3c378fL,0x7e54478935a25be9L,0x6cfa49724dd929d7L,
        0x987fed9d365bd878L,0x4982ac945c29a7aeL,0x4589a5d75ddd7ec5L } },
    /* 126 */
    { { 0x9fabb174a95540a9L,0x7cfb886f0162c5b0L,0x17be766bea3dee18L,
        0xff7da41fe88e624cL,0xad0b71eb8b919c38L,0x86a522e0f31ff9a9L },
      { 0xbc8e6f72868bc259L,0x6130c6383ccef9e4L,0x09f1f4549a466555L,
        0x8e6c0f0919b2bfb4L,0x945c46c90ca7bb22L,0xacd871684dafb67bL } },
    /* 127 */
    { { 0x090c72ca10c53841L,0xc20ae01b55a4fcedL,0x03f7ebd5e10234adL,
        0xb3f42a6a85892064L,0xbdbc30c0b4a14722L,0x971bc4378ca124ccL },
      { 0x6f79f46d517ff2ffL,0x6a9c96e2ecba947bL,0x5e79f2f462925122L,
        0x30a96bb16a4e91f1L,0x1147c9232d4c72daL,0x65bc311f5811e4dfL } },
    /* 128 */
    { { 0x87c7dd7d139b3239L,0x8b57824e4d833baeL,0xbcbc48789fff0015L,
        0x8ffcef8b909eaf1aL,0x9905f4eef1443a78L,0x020dd4a2e15cbfedL },
      { 0xca2969eca306d695L,0xdf940cadb93caf60L,0x67f7fab787ea6e39L,
        0x0d0ee10ff98c4fe5L,0xc646879ac19cb91eL,0x4b4ea50c7d1d7ab4L } },
    /* 129 */
    { { 0x19e409457a0db57eL,0xe6017cad9a8c9702L,0xdbf739e51be5cff9L,
        0x3646b3cda7a938a2L,0x0451108568350dfcL,0xad3bd6f356e098b5L },
      { 0x935ebabfee2e3e3eL,0xfbd01702473926cbL,0x7c735b029e9fb5aaL,
        0xc52a1b852e3feff0L,0x9199abd3046b405aL,0xe306fcec39039971L } },
    /* 130 */
    { { 0xd6d9aec823e4712cL,0x7ca8376cc3c198eeL,0xe6d8318731bebd8aL,
        0xed57aff3d88bfef3L,0x72a645eecf44edc7L,0xd4e63d0b5cbb1517L },
      { 0x98ce7a1cceee0ecfL,0x8f0126335383ee8eL,0x3b879078a6b455e8L,
        0xcbcd3d96c7658c06L,0x721d6fe70783336aL,0xf21a72635a677136L } },
    /* 131 */
    { { 0x19d8b3cd9586ba11L,0xd9e0aeb28a5c0480L,0xe4261dbf2230ef5cL,
        0x095a9dee02e6bf09L,0x8963723c80dc7784L,0x5c97dbaf145157b1L },
      { 0x97e744344bc4503eL,0x0fb1cb3185a6b370L,0x3e8df2becd205d4bL,
        0x497dd1bcf8f765daL,0x92ef95c76c988a1aL,0x3f924baa64dc4cfaL } },
    /* 132 */
    { { 0x6bf1b8dd7268b448L,0xd4c28ba1efd79b94L,0x2fa1f8c8e4e3551fL,
        0x769e3ad45c9187a9L,0x28843b4d40326c0dL,0xfefc809450d5d669L },
      { 0x30c85bfd90339366L,0x4eeb56f15ccf6c3aL,0x0e72b14928ccd1dcL,
        0x73ee85b5f2ce978eL,0xcdeb2bf33165bb23L,0x8106c9234e410abfL } },
    /* 133 */
    { { 0xc8df01617d02f4eeL,0x8a78154718e21225L,0x4ea895eb6acf9e40L,
        0x8b000cb56e5a633dL,0xf31d86d57e981ffbL,0xf5c8029c4475bc32L },
      { 0x764561ce1b568973L,0x2f809b81a62996ecL,0x9e513d64da085408L,
        0xc27d815de61ce309L,0x0da6ff99272999e0L,0xbd284779fead73f7L } },
    /* 134 */
    { { 0x6033c2f99b1cdf2bL,0x2a99cf06bc5fa151L,0x7d27d25912177b3bL,
        0xb1f15273c4485483L,0x5fd57d81102e2297L,0x3d43e017c7f6acb7L },
      { 0x41a8bb0b3a70eb28L,0x67de2d8e3e80b06bL,0x09245a4170c28de5L,
        0xad7dbcb1a7b26023L,0x70b08a352cbc6c1eL,0xb504fb669b33041fL } },
    /* 135 */
    { { 0xa8e85ab5f97a27c2L,0x6ac5ec8bc10a011bL,0x55745533ffbcf161L,
        0x01780e8565790a60L,0xe451bf8599ee75b0L,0x8907a63b39c29881L },
      { 0x76d46738260189edL,0x284a443647bd35cbL,0xd74e8c4020cab61eL,
        0x6264bf8c416cf20aL,0xfa5a6c955fd820ceL,0xfa7154d0f24bb5fcL } },
    /* 136 */
    { { 0x18482cec9b3f5034L,0x962d445acd9e68fdL,0x266fb1d695746f23L,
        0xc66ade5a58c94a4bL,0xdbbda826ed68a5b6L,0x05664a4d7ab0d6aeL },
      { 0xbcd4fe51025e32fcL,0x61a5aebfa96df252L,0xd88a07e231592a31L,
        0x5d9d94de98905517L,0x96bb40105fd440e7L,0x1b0c47a2e807db4cL } },
    /* 137 */
    { { 0x5c2a6ac808223878L,0xba08c269e65a5558L,0xd22b1b9b9bbc27fdL,
        0x919171bf72b9607dL,0x9ab455f9e588dc58L,0x6d54916e23662d93L },
      { 0x8da8e9383b1de0c1L,0xa84d186a804f278fL,0xbf4988ccd3461695L,
        0xf5eae3bee10eb0cbL,0x1ff8b68fbf2a66edL,0xa68daf67c305b570L } },
    /* 138 */
    { { 0xc1004cff44b2e045L,0x91b5e1364b1c05d4L,0x53ae409088a48a07L,
        0x73fb2995ea11bb1aL,0x320485703d93a4eaL,0xcce45de83bfc8a5fL },
      { 0xaff4a97ec2b3106eL,0x9069c630b6848b4fL,0xeda837a6ed76241cL,
        0x8a0daf136cc3f6cfL,0x199d049d3da018a8L,0xf867c6b1d9093ba3L } },
    /* 139 */
    { { 0xe4d42a5656527296L,0xae26c73dce71178dL,0x70a0adac6c251664L,
        0x813483ae5dc0ae1dL,0x7574eacddaab2dafL,0xc56b52dcc2d55f4fL },
      { 0x872bc16795f32923L,0x4be175815bdd2a89L,0x9b57f1e7a7699f00L,
        0x5fcd9c723ac2de02L,0x83af3ba192377739L,0xa64d4e2bfc50b97fL } },
    /* 140 */
    { { 0x2172dae20e552b40L,0x62f49725d34d52e8L,0x7930ee4007958f98L,
        0x56da2a90751fdd74L,0xf1192834f53e48c3L,0x34d2ac268e53c343L },
      { 0x1073c21813111286L,0x201dac14da9d9827L,0xec2c29dbee95d378L,
        0x9316f1191f3ee0b1L,0x7890c9f0544ce71cL,0xd77138af27612127L } },
    /* 141 */
    { { 0x78045e6d3b4ad1cdL,0xcd86b94e4aa49bc1L,0x57e51f1dfd677a16L,
        0xd9290935fa613697L,0x7a3f959334f4d893L,0x8c9c248b5d5fcf9bL },
      { 0x9f23a4826f70d4e9L,0x1727345463190ae9L,0x4bdd7c135b081a48L,
        0x1e2de38928d65271L,0x0bbaaa25e5841d1fL,0xc4c18a79746772e5L } },
    /* 142 */
    { { 0x10ee2681593375acL,0x4f3288be7dd5e113L,0x9a97b2fb240f3538L,
        0xfa11089f1de6b1e2L,0x516da5621351bc58L,0x573b61192dfa85b5L },
      { 0x89e966836cba7df5L,0xf299be158c28ab40L,0xe91c9348ad43fcbfL,
        0xe9bbc7cc9a1cefb3L,0xc8add876738b2775L,0x6e3b1f2e775eaa01L } },
    /* 143 */
    { { 0x0365a888b677788bL,0x634ae8c43fd6173cL,0x304987619e498dbeL,
        0x08c43e6dc8f779abL,0x068ae3844c09aca9L,0x2380c70b2018d170L },
      { 0xcf77fbc3a297c5ecL,0xdacbc853ca457948L,0x3690de04336bec7eL,
        0x26bbac6414eec461L,0xd1c23c7e1f713abfL,0xf08bbfcde6fd569eL } },
    /* 144 */
    { { 0x5f8163f484770ee3L,0x0e0c7f94744a1706L,0x9c8f05f7e1b2d46dL,
        0x417eafe7d01fd99aL,0x2ba15df511440e5bL,0xdc5c552a91a6fbcfL },
      { 0x86271d74a270f721L,0x32c0a075a004485bL,0x9d1a87e38defa075L,
        0xb590a7acbf0d20feL,0x430c41c28feda1f5L,0x454d287958f6ec24L } },
    /* 145 */
    { { 0x52b7a6357c525435L,0x3d9ef57f37c4bdbcL,0x2bb93e9edffcc475L,
        0xf7b8ba987710f3beL,0x42ee86da21b727deL,0x55ac3f192e490d01L },
      { 0x487e3a6ec0c1c390L,0x036fb345446cde7bL,0x089eb276496ae951L,
        0xedfed4d971ed1234L,0x661b0dd5900f0b46L,0x11bd6f1b8582f0d3L } },
    /* 146 */
    { { 0x5cf9350f076bc9d1L,0x15d903becf3cd2c3L,0x21cfc8c225af031cL,
        0xe0ad32488b1cc657L,0xdd9fb96370014e87L,0xf0f3a5a1297f1658L },
      { 0xbb908fbaf1f703aaL,0x2f9cc4202f6760baL,0x00ceec6666a38b51L,
        0x4deda33005d645daL,0xb9cf5c72f7de3394L,0xaeef65021ad4c906L } },
    /* 147 */
    { { 0x0583c8b17a19045dL,0xae7c3102d052824cL,0x2a234979ff6cfa58L,
        0xfe9dffc962c733c0L,0x3a7fa2509c0c4b09L,0x516437bb4fe21805L },
      { 0x9454e3d5c2a23ddbL,0x0726d887289c104eL,0x8977d9184fd15243L,
        0xc559e73f6d7790baL,0x8fd3e87d465af85fL,0xa2615c745feee46bL } },
    /* 148 */
    { { 0xc8d607a84335167dL,0x8b42d804e0f5c887L,0x5f9f13df398d11f9L,
        0x5aaa508720740c67L,0x83da9a6aa3d9234bL,0xbd3a5c4e2a54bad1L },
      { 0xdd13914c2db0f658L,0x29dcb66e5a3f373aL,0xbfd62df55245a72bL,
        0x19d1802391e40847L,0xd9df74dbb136b1aeL,0x72a06b6b3f93bc5bL } },
    /* 149 */
    { { 0x6da19ec3ad19d96fL,0xb342daa4fb2a4099L,0x0e61633a662271eaL,
        0x3bcece81ce8c054bL,0x7cc8e0618bd62dc6L,0xae189e19ee578d8bL },
      { 0x73e7a25ddced1eedL,0xc1257f0a7875d3abL,0x2cb2d5a21cfef026L,
        0xd98ef39bb1fdf61cL,0xcd8e6f6924e83e6cL,0xd71e7076c7b7088bL } },
    /* 150 */
    { { 0x339368309d4245bfL,0x22d962172ac2953bL,0xb3bf5a8256c3c3cdL,
        0x50c9be910d0699e8L,0xec0944638f366459L,0x6c056dba513b7c35L },
      { 0x687a6a83045ab0e3L,0x8d40b57f445c9295L,0x0f345048a16f5954L,
        0x64b5c6393d8f0a87L,0x106353a29f71c5e2L,0xdd58b475874f0dd4L } },
    /* 151 */
    { { 0x67ec084f62230c72L,0xf14f6cca481385e3L,0xf58bb4074cda7774L,
        0xe15011b1aa2dbb6bL,0xd488369d0c035ab1L,0xef83c24a8245f2fdL },
      { 0xfb57328f9fdc2538L,0x79808293191fe46aL,0xe28f5c4432ede548L,
        0x1b3cda99ea1a022cL,0x39e639b73df2ec7fL,0x77b6272b760e9a18L } },
    /* 152 */
    { { 0x2b1d51bda65d56d5L,0x3a9b71f97ea696e0L,0x95250ecc9904f4c4L,
        0x8bc4d6ebe75774b7L,0x0e343f8aeaeeb9aaL,0xc473c1d1930e04cbL },
      { 0x282321b1064cd8aeL,0xf4b4371e5562221cL,0xc1cc81ecd1bf1221L,
        0xa52a07a9e2c8082fL,0x350d8e59ba64a958L,0x29e4f3de6fb32c9aL } },
    /* 153 */
    { { 0x0aa9d56cba89aaa5L,0xf0208ac0c4c6059eL,0x7400d9c6bd6ddca4L,
        0xb384e475f2c2f74aL,0x4c1061fcb1562dd3L,0x3924e2482e153b8dL },
      { 0xf38b8d98849808abL,0x29bf3260a491aa36L,0x85159ada88220edeL,
        0x8b47915bbe5bc422L,0xa934d72ed7300967L,0xc4f303982e515d0dL } },
    /* 154 */
    { { 0xe3e9ee421b1de38bL,0xa124e25a42636760L,0x90bf73c090165b1aL,
        0x21802a34146434c5L,0x54aa83f22e1fa109L,0x1d4bd03ced9c51e9L },
      { 0xc2d96a38798751e6L,0xed27235f8c3507f5L,0xb5fb80e2c8c24f88L,
        0xf873eefad37f4f78L,0x7229fd74f224ba96L,0x9dcd91999edd7149L } },
    /* 155 */
    { { 0xee9f81a64e94f22aL,0xe5609892f71ec341L,0x6c818ddda998284eL,
        0x9fd472953b54b098L,0x47a6ac030e8a7cc9L,0xde684e5eb207a382L },
      { 0x4bdd1ecd2b6b956bL,0x09084414f01b3583L,0xe2f80b3255233b14L,
        0x5a0fec54ef5ebc5eL,0x74cf25e6bf8b29a2L,0x1c757fa07f29e014L } },
    /* 156 */
    { { 0x1bcb5c4aeb0fdfe4L,0xd7c649b3f0899367L,0xaef68e3f05bc083bL,
        0x57a06e46a78aa607L,0xa2136ecc21223a44L,0x89bd648452f5a50bL },
      { 0x724411b94455f15aL,0x23dfa97008a9c0fdL,0x7b0da4d16db63befL,
        0x6f8a7ec1fb162443L,0xc1ac9ceee98284fbL,0x085a582b33566022L } },
    /* 157 */
    { { 0x15cb61f9ec1f138aL,0x11c9a230668f0c28L,0xac829729df93f38fL,
        0xcef256984048848dL,0x3f686da02bba8fbfL,0xed5fea78111c619aL },
      { 0x9b4f73bcd6d1c833L,0x5095160686e7bf80L,0xa2a73508042b1d51L,
        0x9ef6ea495fb89ec2L,0xf1008ce95ef8b892L,0x78a7e6849ae8568bL } },
    /* 158 */
    { { 0x3fe83a7c10470cd8L,0x92734682f86df000L,0xb5dac06bda9409b5L,
        0x1e7a966094939c5fL,0xdec6c1505cc116dcL,0x1a52b40866bac8ccL },
      { 0x5303a3656e864045L,0x45eae72a9139efc1L,0x83bec6466f31d54fL,
        0x2fb4a86f6e958a6dL,0x6760718e4ff44030L,0x008117e3e91ae0dfL } },
    /* 159 */
    { { 0x5d5833ba384310a2L,0xbdfb4edc1fd6c9fcL,0xb9a4f102849c4fb8L,
        0xe5fb239a581c1e1fL,0xba44b2e7d0a9746dL,0x78f7b7683bd942b9L },
      { 0x076c8ca1c87607aeL,0x82b23c2ed5caaa7eL,0x6a581f392763e461L,
        0xca8a5e4a3886df11L,0xc87e90cf264e7f22L,0x04f74870215cfcfcL } },
    /* 160 */
    { { 0x5285d116141d161cL,0x67cd2e0e93c4ed17L,0x12c62a647c36187eL,
        0xf5329539ed2584caL,0xc4c777c442fbbd69L,0x107de7761bdfc50aL },
      { 0x9976dcc5e96beebdL,0xbe2aff95a865a151L,0x0e0a9da19d8872afL,
        0x5e357a3da63c17ccL,0xd31fdfd8e15cc67cL,0xc44bbefd7970c6d8L } },
    /* 161 */
    { { 0x703f83e24c0c62f1L,0x9b1e28ee4e195572L,0x6a82858bfe26ccedL,
        0xd381c84bc43638faL,0x94f72867a5ba43d8L,0x3b4a783d10b82743L },
      { 0xee1ad7b57576451eL,0xc3d0b59714b6b5c8L,0x3dc30954fcacc1b8L,
        0x55df110e472c9d7bL,0x97c86ed702f8a328L,0xd043341388dc098fL } },
    /* 162 */
    { { 0x1a60d1522ca8f2feL,0x61640948491bd41fL,0x6dae29a558dfe035L,
        0x9a615bea278e4863L,0xbbdb44779ad7c8e5L,0x1c7066302ceac2fcL },
      { 0x5e2b54c699699b4bL,0xb509ca6d239e17e8L,0x728165feea063a82L,
        0x6b5e609db6a22e02L,0x12813905b26ee1dfL,0x07b9f722439491faL } },
    /* 163 */
    { { 0x1592ec1448ff4e49L,0x3e4e9f176d644129L,0x7acf82881156acc0L,
        0x5aa34ba8bb092b0bL,0xcd0f90227d38393dL,0x416724ddea4f8187L },
      { 0x3c4e641cc0139e73L,0xe0fe46cf91e4d87dL,0xedb3c792cab61f8aL,
        0x4cb46de4d3868753L,0xe449c21d20f1098aL,0x5e5fd059f5b8ea6eL } },
    /* 164 */
    { { 0x7fcadd4675856031L,0x89c7a4cdeaf2fbd0L,0x1af523ce7a87c480L,
        0xe5fc109561d9ae90L,0x3fb5864fbcdb95f5L,0xbeb5188ebb5b2c7dL },
      { 0x3d1563c33ae65825L,0x116854c40e57d641L,0x11f73d341942ebd3L,
        0x24dc5904c06955b3L,0x8a0d4c83995a0a62L,0xfb26b86d5d577b7dL } },
    /* 165 */
    { { 0xc53108e7c686ae17L,0x9090d739d1c1da56L,0x4583b0139aec50aeL,
        0xdd9a088ba49a6ab2L,0x28192eeaf382f850L,0xcc8df756f5fe910eL },
      { 0x877823a39cab7630L,0x64984a9afb8e7fc1L,0x5448ef9c364bfc16L,
        0xbbb4f871c44e2a9aL,0x901a41ab435c95e9L,0xc6c23e5faaa50a06L } },
    /* 166 */
    { { 0xb78016c19034d8ddL,0x856bb44b0b13e79bL,0x85c6409ab3241a05L,
        0x8d2fe19a2d78ed21L,0xdcc7c26d726eddf2L,0x3ccaff5f25104f04L },
      { 0x397d7edc6b21f843L,0xda88e4dde975de4cL,0x5273d3964f5ab69eL,
        0x537680e39aae6cc0L,0xf749cce53e6f9461L,0x021ddbd9957bffd3L } },
    /* 167 */
    { { 0x7b64585f777233cfL,0xfe6771f60942a6f0L,0x636aba7adfe6eef0L,
        0x63bbeb5686038029L,0xacee5842de8fcf36L,0x48d9aa99d4a20524L },
      { 0xcff7a74c0da5e57aL,0xc232593ce549d6c9L,0x68504bccf0f2287bL,
        0x6d7d098dbc8360b5L,0xeac5f1495b402f41L,0x61936f11b87d1bf1L } },
    /* 168 */
    { { 0xaa9da167b8153a9dL,0xa49fe3ac9e83ecf0L,0x14c18f8e1b661384L,
        0x61c24dab38434de1L,0x3d973c3a283dae96L,0xc99baa0182754fc9L },
      { 0x477d198f4c26b1e3L,0x12e8e186a7516202L,0x386e52f6362addfaL,
        0x31e8f695c3962853L,0xdec2af136aaedb60L,0xfcfdb4c629cf74acL } },
    /* 169 */
    { { 0x6b3ee958cca40298L,0xc3878153f2f5d195L,0x0c565630ed2eae5bL,
        0xd089b37e3a697cf2L,0xc2ed2ac7ad5029eaL,0x7e5cdfad0f0dda6aL },
      { 0xf98426dfd9b86202L,0xed1960b14335e054L,0x1fdb02463f14639eL,
        0x17f709c30db6c670L,0xbfc687ae773421e1L,0x13fefc4a26c1a8acL } },
    /* 170 */
    { { 0xe361a1987ffa0a5fL,0xf4b26102c63fe109L,0x264acbc56c74e111L,
        0x4af445fa77abebafL,0x448c4fdd24cddb75L,0x0b13157d44506eeaL },
      { 0x22a6b15972e9993dL,0x2c3c57e485e5ecbeL,0xa673560bfd83e1a1L,
        0x6be23f82c3b8c83bL,0x40b13a9640bbe38eL,0x66eea033ad17399bL } },
    /* 171 */
    { { 0x49fc6e95b4c6c693L,0xefc735de36af7d38L,0xe053343d35fe42fcL,
        0xf0aa427c6a9ab7c3L,0xc79f04364a0fcb24L,0x1628724393ebbc50L },
      { 0x5c3d6bd016927e1eL,0x40158ed2673b984cL,0xa7f86fc84cd48b9aL,
        0x1643eda660ea282dL,0x45b393eae2a1beedL,0x664c839e19571a94L } },
    /* 172 */
    { { 0x5774575027eeaf94L,0x2875c925ea99e1e7L,0xc127e7ba5086adeaL,
        0x765252a086fe424fL,0x1143cc6c2b6c0281L,0xc9bb2989d671312dL },
      { 0x880c337c51acb0a5L,0xa3710915d3c60f78L,0x496113c09262b6edL,
        0x5d25d9f89ce48182L,0x53b6ad72b3813586L,0x0ea3bebc4c0e159cL } },
    /* 173 */
    { { 0xcaba450ac5e49beaL,0x684e54157c05da59L,0xa2e9cab9de7ac36cL,
        0x4ca79b5f2e6f957bL,0xef7b024709b817b1L,0xeb3049907d89df0fL },
      { 0x508f730746fe5096L,0x695810e82e04eaafL,0x88ef1bd93512f76cL,
        0x776613513ebca06bL,0xf7d4863accf158b7L,0xb2a81e4494ee57daL } },
    /* 174 */
    { { 0xff288e5b6d53e6baL,0xa90de1a914484ea2L,0x2fadb60ced33c8ecL,
        0x579d6ef328b66a40L,0x4f2dd6ddec24372dL,0xe9e33fc91d66ec7dL },
      { 0x110899d2039eab6eL,0xa31a667a3e97bb5eL,0x6200166dcfdce68eL,
        0xbe83ebae5137d54bL,0x085f7d874800acdfL,0xcf4ab1330c6f8c86L } },
    /* 175 */
    { { 0x03f65845931e08fbL,0x6438551e1506e2c0L,0x5791f0dc9c36961fL,
        0x68107b29e3dcc916L,0x83242374f495d2caL,0xd8cfb6636ee5895bL },
      { 0x525e0f16a0349b1bL,0x33cd2c6c4a0fab86L,0x46c12ee82af8dda9L,
        0x7cc424ba71e97ad3L,0x69766ddf37621eb0L,0x95565f56a5f0d390L } },
    /* 176 */
    { { 0xe0e7bbf21a0f5e94L,0xf771e1151d82d327L,0x10033e3dceb111faL,
        0xd269744dd3426638L,0xbdf2d9da00d01ef6L,0x1cb80c71a049ceafL },
      { 0x17f183289e21c677L,0x6452af0519c8f98bL,0x35b9c5f780b67997L,
        0x5c2e1cbe40f8f3d4L,0x43f9165666d667caL,0x9faaa059cf9d6e79L } },
    /* 177 */
    { { 0x8ad246180a078fe6L,0xf6cc73e6464fd1ddL,0x4d2ce34dc3e37448L,
        0x624950c5e3271b5fL,0x62910f5eefc5af72L,0x8b585bf8aa132bc6L },
      { 0x11723985a839327fL,0x34e2d27d4aac252fL,0x402f59ef6296cc4eL,
        0x00ae055c47053de9L,0xfc22a97228b4f09bL,0xa9e86264fa0c180eL } },
    /* 178 */
    { { 0x0b7b6224bc310eccL,0x8a1a74f167fa14edL,0x87dd09607214395cL,
        0xdf1b3d09f5c91128L,0x39ff23c686b264a8L,0xdc2d49d03e58d4c5L },
      { 0x2152b7d3a9d6f501L,0xf4c32e24c04094f7L,0xc6366596d938990fL,
        0x084d078f94fb207fL,0xfd99f1d7328594cbL,0x36defa64cb2d96b3L } },
    /* 179 */
    { { 0x4619b78113ed7cbeL,0x95e500159784bd0eL,0x2a32251c2c7705feL,
        0xa376af995f0dd083L,0x55425c6c0361a45bL,0x812d2cef1f291e7bL },
      { 0xccf581a05fd94972L,0x26e20e39e56dc383L,0x0093685d63dbfbf0L,
        0x1fc164cc36b8c575L,0xb9c5ab81390ef5e7L,0x40086beb26908c66L } },
    /* 180 */
    { { 0xe5e54f7937e3c115L,0x69b8ee8cc1445a8aL,0x79aedff2b7659709L,
        0xe288e1631b46fbe6L,0xdb4844f0d18d7bb7L,0xe0ea23d048aa6424L },
      { 0x714c0e4ef3d80a73L,0x87a0aa9e3bd64f98L,0x8844b8a82ec63080L,
        0xe0ac9c30255d81a3L,0x86151237455397fcL,0x0b9794642f820155L } },
    /* 181 */
    { { 0x127a255a4ae03080L,0x232306b4580a89fbL,0x04e8cd6a6416f539L,
        0xaeb70dee13b02a0eL,0xa3038cf84c09684aL,0xa710ec3c28e433eeL },
      { 0x77a72567681b1f7dL,0x86fbce952fc28170L,0xd3408683f5735ac8L,
        0x3a324e2a6bd68e93L,0x7ec74353c027d155L,0xab60354cd4427177L } },
    /* 182 */
    { { 0x32a5342aef4c209dL,0x2ba7527408d62704L,0x4bb4af6fc825d5feL,
        0x1c3919ced28e7ff1L,0x1dfc2fdcde0340f6L,0xc6580baf29f33ba9L },
      { 0xae121e7541d442cbL,0x4c7727fd3a4724e4L,0xe556d6a4524f3474L,
        0x87e13cc7785642a2L,0x182efbb1a17845fdL,0xdcec0cf14e144857L } },
    /* 183 */
    { { 0x1cb89541e9539819L,0xc8cb3b4f9d94dbf1L,0x1d353f63417da578L,
        0xb7a697fb8053a09eL,0x8d841731c35d8b78L,0x85748d6fb656a7a9L },
      { 0x1fd03947c1859c5dL,0x6ce965c1535d22a2L,0x1966a13e0ca3aadcL,
        0x9802e41d4fb14effL,0xa9048cbb76dd3fcdL,0x89b182b5e9455bbaL } },
    /* 184 */
    { { 0xd777ad6a43360710L,0x841287ef55e9936bL,0xbaf5c67004a21b24L,
        0xf2c0725f35ad86f1L,0x338fa650c707e72eL,0x2bf8ed2ed8883e52L },
      { 0xb0212cf4b56e0d6aL,0x50537e126843290cL,0xd8b184a198b3dc6fL,
        0xd2be9a350210b722L,0x407406db559781eeL,0x5a78d5910bc18534L } },
    /* 185 */
    { { 0x4d57aa2ad748b02cL,0xbe5b3451a12b3b95L,0xadca7a4564711258L,
        0x597e091a322153dbL,0xf327100632eb1eabL,0xbd9adcba2873f301L },
      { 0xd1dc79d138543f7fL,0x00022092921b1fefL,0x86db3ef51e5df8edL,
        0x888cae049e6b944aL,0x71bd29ec791a32b4L,0xd3516206a6d1c13eL } },
    /* 186 */
    { { 0x2ef6b95255924f43L,0xd2f401ae4f9de8d5L,0xfc73e8d7adc68042L,
        0x627ea70c0d9d1bb4L,0xc3bb3e3ebbf35679L,0x7e8a254ad882dee4L },
      { 0x08906f50b5924407L,0xf14a0e61a1ad444aL,0xaa0efa2165f3738eL,
        0xd60c7dd6ae71f161L,0x9e8390faf175894dL,0xd115cd20149f4c00L } },
    /* 187 */
    { { 0x2f2e2c1da52abf77L,0xc2a0dca554232568L,0xed423ea254966dccL,
        0xe48c93c7cd0dd039L,0x1e54a225176405c7L,0x1efb5b1670d58f2eL },
      { 0xa751f9d994fb1471L,0xfdb31e1f67d2941dL,0xa6c74eb253733698L,
        0xd3155d1189a0f64aL,0x4414cfe4a4b8d2b6L,0x8d5a4be8f7a8e9e3L } },
    /* 188 */
    { { 0x5c96b4d452669e98L,0x4547f9228fd42a03L,0xcf5c1319d285174eL,
        0x805cd1ae064bffa0L,0x50e8bc4f246d27e7L,0xf89ef98fd5781e11L },
      { 0xb4ff95f6dee0b63fL,0xad850047222663a4L,0x026918604d23ce9cL,
        0x3e5309ce50019f59L,0x27e6f72269a508aeL,0xe9376652267ba52cL } },
    /* 189 */
    { { 0xa04d289cc0368708L,0xc458872f5e306e1dL,0x76fa23de33112feaL,
        0x718e39746efde42eL,0xf0c98cdc1d206091L,0x5fa3ca6214a71987L },
      { 0xeee8188bdcaa9f2aL,0x312cc732589a860dL,0xf9808dd6c63aeb1fL,
        0x70fd43db4ea62b53L,0x2c2bfe34890b6e97L,0x105f863cfa426aa6L } },
    /* 190 */
    { { 0x0b29795db38059adL,0x5686b77e90647ea0L,0xeff0470edb473a3eL,
        0x278d2340f9b6d1e2L,0xebbff95bbd594ec7L,0xf4b72334d3a7f23dL },
      { 0x2a285980a5a83f0bL,0x0786c41a9716a8b3L,0x138901bd22511812L,
        0xd1b55221e2fede6eL,0x0806e264df4eb590L,0x6c4c897e762e462eL } },
    /* 191 */
    { { 0xd10b905fb4b41d9dL,0x826ca4664523a65bL,0x535bbd13b699fa37L,
        0x5b9933d773bc8f90L,0x9332d61fcd2118adL,0x158c693ed4a65fd0L },
      { 0x4ddfb2a8e6806e63L,0xe31ed3ecb5de651bL,0xf9460e51819bc69aL,
        0x6229c0d62c76b1f8L,0xbb78f231901970a3L,0x31f3820f9cee72b8L } },
    /* 192 */
    { { 0xe931caf2c09e1c72L,0x0715f29812990cf4L,0x33aad81d943262d8L,
        0x5d292b7a73048d3fL,0xb152aaa4dc7415f6L,0xc3d10fd90fd19587L },
      { 0xf76b35c575ddadd0L,0x9f5f4a511e7b694cL,0x2f1ab7ebc0663025L,
        0x01c9cc87920260b0L,0xc4b1f61a05d39da6L,0x6dcd76c4eb4a9c4eL } },
    /* 193 */
    { { 0x0ba0916ffdc83f01L,0x354c8b449553e4f9L,0xa6cc511affc5e622L,
        0xb954726ae95be787L,0xcb04811575b41a62L,0xfa2ae6cdebfde989L },
      { 0x6376bbc70f24659aL,0x13a999fd4c289c43L,0xc7134184ec9abd8bL,
        0x28c02bf6a789ab04L,0xff841ebcd3e526ecL,0x442b191e640893a8L } },
    /* 194 */
    { { 0x4cac6c62fa2b6e20L,0x97f29e9bf6d69861L,0x228ab1dbbc96d12dL,
        0x6eb913275e8e108dL,0xd4b3d4d140771245L,0x61b20623ca8a803aL },
      { 0x2c2f3b41a6a560b1L,0x879e1d403859fcf4L,0x7cdb5145024dbfc3L,
        0x55d08f153bfa5315L,0x2f57d773aa93823aL,0xa97f259cc6a2c9a2L } },
    /* 195 */
    { { 0xc306317be58edbbbL,0x25ade51c79dfdf13L,0x6b5beaf116d83dd6L,
        0xe8038a441dd8f925L,0x7f00143cb2a87b6bL,0xa885d00df5b438deL },
      { 0xe9f76790cf9e48bdL,0xf0bdf9f0a5162768L,0x0436709fad7b57cbL,
        0x7e151c12f7c15db7L,0x3514f0225d90ee3bL,0x2e84e8032c361a8dL } },
    /* 196 */
    { { 0x2277607d563ec8d8L,0xa661811fe3934cb7L,0x3ca72e7af58fd5deL,
        0x7989da0462294c6aL,0x88b3708bf6bbefe9L,0x0d524cf753ed7c82L },
      { 0x69f699ca2f30c073L,0xf0fa264b9dc1dcf3L,0x44ca456805f0aaf6L,
        0x0f5b23c7d19b9bafL,0x39193f41eabd1107L,0x9e3e10ad2a7c9b83L } },
    /* 197 */
    { { 0xa90824f0d4ae972fL,0x43eef02bc6e846e7L,0x7e46061229d2160aL,
        0x29a178acfe604e91L,0x23056f044eb184b2L,0x4fcad55feb54cdf4L },
      { 0xa0ff96f3ae728d15L,0x8a2680c6c6a00331L,0x5f84cae07ee52556L,
        0x5e462c3ac5a65dadL,0x5d2b81dfe2d23f4fL,0x6e47301bc5b1eb07L } },
    /* 198 */
    { { 0x77411d68af8219b9L,0xcb883ce651b1907aL,0x25c87e57101383b5L,
        0x9c7d9859982f970dL,0xaa6abca5118305d2L,0x725fed2f9013a5dbL },
      { 0x487cdbafababd109L,0xc0f8cf5687586528L,0xa02591e68ad58254L,
        0xc071b1d1debbd526L,0x927dfe8b961e7e31L,0x55f895f99263dfe1L } },
    /* 199 */
    { { 0xf899b00db175645bL,0x51f3a627b65b4b92L,0xa2f3ac8db67399efL,
        0xe717867fe400bc20L,0x42cc90201967b952L,0x3d5967513ecd1de1L },
      { 0xd41ebcdedb979775L,0x99ba61bc6a2e7e88L,0x039149a5321504f2L,
        0xe7dc231427ba2fadL,0x9f556308b57d8368L,0x2b6d16c957da80a7L } },
    /* 200 */
    { { 0x84af5e76279ad982L,0x9bb4c92d9c8b81a6L,0xd79ad44e0e698e67L,
        0xe8be9048265fc167L,0xf135f7e60c3a4cccL,0xa0a10d38b8863a33L },
      { 0xe197247cd386efd9L,0x0eefd3f9b52346c2L,0xc22415f978607bc8L,
        0xa2a8f862508674ceL,0xa72ad09ec8c9d607L,0xcd9f0ede50fa764fL } },
    /* 201 */
    { { 0x063391c7d1a46d4dL,0x2df51c119eb01693L,0xc5849800849e83deL,
        0x48fd09aa8ad08382L,0xa405d873aa742736L,0xee49e61ee1f9600cL },
      { 0xd76676be48c76f73L,0xd9c100f601274b2aL,0x110bb67c83f8718dL,
        0xec85a42002fc0d73L,0xc0449e1e744656adL,0x28ce737637d9939bL } },
    /* 202 */
    { { 0x97e9af7244544ac7L,0xf2c658d5ba010426L,0x732dec39fb3adfbdL,
        0xd12faf91a2df0b07L,0x8ac267252171e208L,0xf820cdc85b24fa54L },
      { 0x307a6eea94f4cf77L,0x18c783d2944a33c6L,0x4b939d4c0b741ac5L,
        0x1d7acd153ffbb6e4L,0x06a248587a255e44L,0x14fbc494ce336d50L } },
    /* 203 */
    { { 0x9b920c0c51584e3cL,0xc7733c59f7e54027L,0xe24ce13988422bbeL,
        0x11ada812523bd6abL,0xde068800b88e6defL,0x7b872671fe8c582dL },
      { 0x4e746f287de53510L,0x492f8b99f7971968L,0x1ec80bc77d928ac2L,
        0xb3913e48432eb1b5L,0xad08486632028f6eL,0x122bb8358fc2f38bL } },
    /* 204 */
    { { 0x0a9f3b1e3b0b29c3L,0x837b64324fa44151L,0xb9905c9217b28ea7L,
        0xf39bc93798451750L,0xcd383c24ce8b6da1L,0x299f57db010620b2L },
      { 0x7b6ac39658afdce3L,0xa15206b33d05ef47L,0xa0ae37e2b9bb02ffL,
        0x107760ab9db3964cL,0xe29de9a067954beaL,0x446a1ad8431c3f82L } },
    /* 205 */
    { { 0xc6fecea05c6b8195L,0xd744a7c5f49e71b9L,0xa8e96acc177a7ae7L,
        0x1a05746c358773a7L,0xa416214637567369L,0xaa0217f787d1c971L },
      { 0x61e9d15877fd3226L,0x0f6f2304e4f600beL,0xa9c4cebc7a6dff07L,
        0xd15afa0109f12a24L,0x2bbadb228c863ee9L,0xa28290e4e5eb8c78L } },
    /* 206 */
    { { 0x55b87fa03e9de330L,0x12b26066195c145bL,0xe08536e0a920bef0L,
        0x7bff6f2c4d195adcL,0x7f319e9d945f4187L,0xf9848863f892ce47L },
      { 0xd0efc1d34fe37657L,0x3c58de825cf0e45aL,0x626ad21a8b0ccbbeL,
        0xd2a31208af952fc5L,0x81791995eb437357L,0x5f19d30f98e95d4fL } },
    /* 207 */
    { { 0x72e83d9a0e6865bbL,0x22f5af3bf63456a6L,0x409e9c73463c8d9eL,
        0x40e9e578dfe6970eL,0x876b6efa711b91caL,0x895512cf942625a3L },
      { 0x84c8eda8cb4e462bL,0x84c0154a4412e7c8L,0x04325db1ceb7b71fL,
        0x1537dde366f70877L,0xf3a093991992b9acL,0xa7316606d498ae77L } },
    /* 208 */
    { { 0x13990d2fcad260f5L,0x76c3be29eec0e8c0L,0x7dc5bee00f7bd7d5L,
        0x9be167d2efebda4bL,0xcce3dde69122b87eL,0x75a28b0982b5415cL },
      { 0xf6810bcde84607a6L,0xc6d581286f4dbf0dL,0xfead577d1b4dafebL,
        0x9bc440b2066b28ebL,0x53f1da978b17e84bL,0x0459504bcda9a575L } },
    /* 209 */
    { { 0x13e39a02329e5836L,0x2c9e7d51f717269dL,0xc5ac58d6f26c963bL,
        0x3b0c6c4379967bf5L,0x60bbea3f55908d9dL,0xd84811e7f07c9ad1L },
      { 0xfe7609a75bd20e4aL,0xe4325dd20a70baa8L,0x3711f370b3600386L,
        0x97f9562fd0924302L,0x040dc0c34acc4436L,0xfd6d725cde79cdd4L } },
    /* 210 */
    { { 0xb3efd0e3cf13eafbL,0x21009cbb5aa0ae5fL,0xe480c55379022279L,
        0x755cf334b2fc9a6dL,0x8564a5bf07096ae7L,0xddd649d0bd238139L },
      { 0xd0de10b18a045041L,0x6e05b413c957d572L,0x5c5ff8064e0fb25cL,
        0xd933179b641162fbL,0x42d48485e57439f9L,0x70c5bd0a8a8d72aaL } },
    /* 211 */
    { { 0xa767173897bdf646L,0xaa1485b4ab329f7cL,0xce3e11d6f8f25fdfL,
        0x76a3fc7ec6221824L,0x045f281ff3924740L,0x24557d4e96d13a9aL },
      { 0x875c804bdd4c27cdL,0x11c5f0f40f5c7feaL,0xac8c880bdc55ff7eL,
        0x2acddec51103f101L,0x38341a21f99faa89L,0xc7b67a2cce9d6b57L } },
    /* 212 */
    { { 0x9a0d724f8e357586L,0x1d7f4ff5df648da0L,0x9c3e6c9bfdee62a5L,
        0x0499cef00389b372L,0xe904050d98eab879L,0xe8eef1b66c051617L },
      { 0xebf5bfebc37e3ca9L,0x7c5e946da4e0b91dL,0x790973142c4bea28L,
        0x81f6c109ee67b2b7L,0xaf237d9bdafc5edeL,0xd2e602012abb04c7L } },
    /* 213 */
    { { 0x6156060c8a4f57bfL,0xf9758696ff11182aL,0x8336773c6296ef00L,
        0x9c054bceff666899L,0xd6a11611719cd11cL,0x9824a641dbe1acfaL },
      { 0x0b7b7a5fba89fd01L,0xf8d3b809889f79d8L,0xc5e1ea08f578285cL,
        0x7ac74536ae6d8288L,0x5d37a2007521ef5fL,0x5ecc4184b260a25dL } },
    /* 214 */
    { { 0xddcebb19a708c8d3L,0xe63ed04fc63f81ecL,0xd045f5a011873f95L,
        0x3b5ad54479f276d5L,0x81272a3d425ae5b3L,0x8bfeb50110ce1605L },
      { 0x4233809c888228bfL,0x4bd82acfb2aff7dfL,0x9c68f1800cbd4a7fL,
        0xfcd771246b44323dL,0x60c0fcf6891db957L,0xcfbb4d8904da8f7fL } },
    /* 215 */
    { { 0x9a6a5df93b26139aL,0x3e076a83b2cc7eb8L,0x47a8e82d5a964bcdL,
        0x8a4e2a39b9278d6bL,0x93506c98e4443549L,0x06497a8ff1e0d566L },
      { 0x3dee8d992b1efa05L,0x2da63ca845393e33L,0xa4af7277cf0579adL,
        0xaf4b46393236d8eaL,0x6ccad95b32b617f5L,0xce76d8b8b88bb124L } },
    /* 216 */
    { { 0x63d2537a083843dcL,0x89eb35141e4153b4L,0x5175ebc4ea9afc94L,
        0x7a6525808ed1aed7L,0x67295611d85e8297L,0x8dd2d68bb584b73dL },
      { 0x237139e60133c3a4L,0x9de838ab4bd278eaL,0xe829b072c062fcd9L,
        0x70730d4f63ba8706L,0x6080483fd3cd05ecL,0x872ab5b80c85f84dL } },
    /* 217 */
    { { 0xfc0776d3999d4d49L,0xa3eb59deec3f45e7L,0xbc990e440dae1fc1L,
        0x33596b1ea15371ffL,0xd447dcb29bc7ab25L,0xcd5b63e935979582L },
      { 0xae3366fa77d1ff11L,0x59f28f05edee6903L,0x6f43fed1a4433bf2L,
        0x15409c9bdf9ce00eL,0x21b5cdedaca9c5dcL,0xf9f3359582d7bdb4L } },
    /* 218 */
    { { 0x959443789422c792L,0x239ea923c958b8bfL,0x4b61a247df076541L,
        0x4d29ce85bb9fc544L,0x9a692a670b424559L,0x6e0ca5a00e486900L },
      { 0x6b79a78285b3beceL,0x41f35e39c61f9892L,0xff82099aae747f82L,
        0x58c8ae3fd0ca59d6L,0x4ac930e299406b5fL,0x2ce04eb99df24243L } },
    /* 219 */
    { { 0x4366b9941ac37b82L,0xff0c728d25b04d83L,0x1f55136119c47b7cL,
        0xdbf2d5edbeff13e7L,0xf78efd51e12a683dL,0x82cd85b9989cf9c4L },
      { 0xe23c6db6e0cb5d37L,0x818aeebd72ee1a15L,0x8212aafd28771b14L,
        0x7bc221d91def817dL,0xdac403a29445c51fL,0x711b051712c3746bL } },
    /* 220 */
    { { 0x0ed9ed485ea99eccL,0xf799500db8cab5e1L,0xa8ec87dcb570cbdcL,
        0x52cfb2c2d35dfaecL,0x8d31fae26e4d80a4L,0xe6a37dc9dcdeabe5L },
      { 0x5d365a341deca452L,0x09a5f8a50d68b44eL,0x59238ea5a60744b1L,
        0xf2fedc0dbb4249e9L,0xe395c74ea909b2e3L,0xe156d1a539388250L } },
    /* 221 */
    { { 0xd796b3d047181ae9L,0xbaf44ba844197808L,0xe693309434cf3facL,
        0x41aa6adec3bd5c46L,0x4fda75d8eed947c6L,0xacd9d4129ea5a525L },
      { 0x65cc55a3d430301bL,0x3c9a5bcf7b52ea49L,0x22d319cf159507f0L,
        0x2ee0b9b5de74a8ddL,0x20c26a1e877ac2b6L,0x387d73da92e7c314L } },
    /* 222 */
    { { 0x13c4833e8cd3fdacL,0x76fcd473332e5b8eL,0xff671b4be2fe1fd3L,
        0x4d734e8b5d98d8ecL,0xb1ead3c6514bbc11L,0xd14ca8587b390494L },
      { 0x95a443af5d2d37e9L,0x73c6ea7300464622L,0xa44aeb4b15755044L,
        0xba3f8575fab58feeL,0x9779dbc9dc680a6fL,0xe1ee5f5a7b37ddfcL } },
    /* 223 */
    { { 0xcd0b464812d29f46L,0x93295b0b0ed53137L,0xbfe2609480bef6c9L,
        0xa656578854248b00L,0x69c43fca80e7f9c4L,0x2190837bbe141ea1L },
      { 0x875e159aa1b26cfbL,0x90ca9f877affe852L,0x15e6550d92ca598eL,
        0xe3e0945d1938ad11L,0xef7636bb366ef937L,0xb6034d0bb39869e5L } },
    /* 224 */
    { { 0x4d255e3026d8356eL,0xf83666edd314626fL,0x421ddf61d0c8ed64L,
        0x96e473c526677b61L,0xdad4af7e9e9b18b3L,0xfceffd4aa9393f75L },
      { 0x843138a111c731d5L,0x05bcb3a1b2f141d9L,0x20e1fa95617b7671L,
        0xbefce81288ccec7bL,0x582073dc90f1b568L,0xf572261a1f055cb7L } },
    /* 225 */
    { { 0xf314827736973088L,0xc008e70886a9f980L,0x1b795947e046c261L,
        0xdf1e6a7dca76bca0L,0xabafd88671acddf0L,0xff7054d91364d8f4L },
      { 0x2cf63547e2260594L,0x468a5372d73b277eL,0xc7419e24ef9bd35eL,
        0x2b4a1c2024043cc3L,0xa28f047a890b39cdL,0xdca2cea146f9a2e3L } },
    /* 226 */
    { { 0xab78873653277538L,0xa734e225cf697738L,0x66ee1d1e6b22e2c1L,
        0x2c615389ebe1d212L,0xf36cad4002bb0766L,0x120885c33e64f207L },
      { 0x59e77d5690fbfec2L,0xf9e781aad7a574aeL,0x801410b05d045e53L,
        0xd3b5f0aaa91b5f0eL,0xb3d1df007fbb3521L,0x11c4b33ec72bee9aL } },
    /* 227 */
    { { 0xd32b983283c3a7f3L,0x8083abcf88d8a354L,0xdeb1640450f4ec5aL,
        0x18d747f0641e2907L,0x4e8978aef1bbf03eL,0x932447dc88a0cd89L },
      { 0x561e0febcf3d5897L,0xfc3a682f13600e6dL,0xc78b9d73d16a6b73L,
        0xe713feded29bf580L,0x0a22522308d69e5cL,0x3a924a571ff7fda4L } },
    /* 228 */
    { { 0xfb64554cb4093beeL,0xa6d65a25a58c6ec0L,0x4126994d43d0ed37L,
        0xa5689a5155152d44L,0xb8e5ea8c284caa8dL,0x33f05d4fd1f25538L },
      { 0xe0fdfe091b615d6eL,0x2ded7e8f705507daL,0xdd5631e517bbcc80L,
        0x4f87453e267fd11fL,0xc6da723fff89d62dL,0x55cbcae2e3cda21dL } },
    /* 229 */
    { { 0x336bc94e6b4e84f3L,0x728630314ef72c35L,0x6d85fdeeeeb57f99L,
        0x7f4e3272a42ece1bL,0x7f86cbb536f0320aL,0xf09b6a2b923331e6L },
      { 0x21d3ecf156778435L,0x2977ba998323b2d2L,0x6a1b57fb1704bc0fL,
        0xd777cf8b389f048aL,0x9ce2174fac6b42cdL,0x404e2bff09e6c55aL } },
    /* 230 */
    { { 0x9b9b135e204c5ddbL,0x9dbfe0443eff550eL,0x35eab4bfec3be0f6L,
        0x8b4c3f0d0a43e56fL,0x4c1c66730e73f9b3L,0x92ed38bd2c78c905L },
      { 0xc7003f6aa386e27cL,0xb9c4f46faced8507L,0xea024ec859df5464L,
        0x4af96152429572eaL,0x279cd5e2e1fc1194L,0xaa376a03281e358cL } },
    /* 231 */
    { { 0x078592233cdbc95cL,0xaae1aa6aef2e337aL,0xc040108d472a8544L,
        0x80c853e68d037b7dL,0xd221315c8c7eee24L,0x195d38568ee47752L },
      { 0xd4b1ba03dacd7fbeL,0x4b5ac61ed3e0c52bL,0x68d3c0526aab7b52L,
        0xf0d7248c660e3feaL,0xafdb3f893145efb4L,0xa73fd9a38f40936dL } },
    /* 232 */
    { { 0x891b9ef3bb1b17ceL,0x14023667c6127f31L,0x12b2e58d305521fdL,
        0x3a47e449e3508088L,0xe49fc84bff751507L,0x4023f7225310d16eL },
      { 0xa608e5edb73399faL,0xf12632d8d532aa3eL,0x13a2758e845e8415L,
        0xae4b6f851fc2d861L,0x3879f5b1339d02f2L,0x446d22a680d99ebdL } },
    /* 233 */
    { { 0x0f5023024be164f1L,0x8d09d2d688b81920L,0x514056f1984aceffL,
        0xa5c4ddf075e9e80dL,0x38cb47e6df496a93L,0x899e1d6b38df6bf7L },
      { 0x69e87e88b59eb2a6L,0x280d9d639b47f38bL,0x599411ea3654e955L,
        0xcf8dd4fd969aa581L,0xff5c2baf530742a7L,0xa43915361a373085L } },
    /* 234 */
    { { 0x6ace72a3a8a4bdd2L,0xc656cdd1b68ef702L,0xd4a33e7e90c4dad8L,
        0x4aece08a9d951c50L,0xea8005ae085d68e6L,0xfdd7a7d76f7502b8L },
      { 0xce6fb0a698d6fa45L,0x228f86721104eb8cL,0xd23d8787da09d7dcL,
        0x5521428b2ae93065L,0x95faba3dea56c366L,0xedbe50390a88aca5L } },
    /* 235 */
    { { 0xd64da0adbfb26c82L,0xe5d70b3c952c2f9cL,0xf5e8f365f7e77f68L,
        0x7234e00208f2d695L,0xfaf900eed12e7be6L,0x27dc69344acf734eL },
      { 0x80e4ff5ec260a46aL,0x7da5ebce2dc31c28L,0x485c5d73ca69f552L,
        0xcdfb6b2969cc84c2L,0x031c5afeed6d4ecaL,0xc7bbf4c822247637L } },
    /* 236 */
    { { 0x9d5b72c749fe01b2L,0x34785186793a91b8L,0xa3ba3c54cf460438L,
        0x73e8e43d3ab21b6fL,0x50cde8e0be57b8abL,0x6488b3a7dd204264L },
      { 0xa9e398b3dddc4582L,0x1698c1a95bec46feL,0x7f1446ef156d3843L,
        0x3fd25dd8770329a2L,0x05b1221a2c710668L,0x65b2dc2aa72ee6cfL } },
    /* 237 */
    { { 0x21a885f7cd021d63L,0x3f344b15fea61f08L,0xad5ba6ddc5cf73e6L,
        0x154d0d8f227a8b23L,0x9b74373cdc559311L,0x4feab71598620fa1L },
      { 0x5098938e7d9ec924L,0x84d54a5e6d47e550L,0x1a2d1bdc1b617506L,
        0x99fe1782615868a4L,0x171da7803005a924L,0xa70bf5ed7d8f79b6L } },
    /* 238 */
    { { 0x0bc1250dfe2216c5L,0x2c37e2507601b351L,0xb6300175d6f06b7eL,
        0x4dde8ca18bfeb9b7L,0x4f210432b82f843dL,0x8d70e2f9b1ac0afdL },
      { 0x25c73b78aae91abbL,0x0230dca3863028f2L,0x8b923ecfe5cf30b7L,
        0xed754ec25506f265L,0x8e41b88c729a5e39L,0xee67cec2babf889bL } },
    /* 239 */
    { { 0xe183acf51be46c65L,0x9789538fe7565d7aL,0x87873391d9627b4eL,
        0xbf4ac4c19f1d9187L,0x5db99f634691f5c8L,0xa68df80374a1fb98L },
      { 0x3c448ed1bf92b5faL,0xa098c8413e0bdc32L,0x8e74cd5579bf016cL,
        0x5df0d09c115e244dL,0x9418ad013410b66eL,0x8b6124cb17a02130L } },
    /* 240 */
    { { 0x425ec3afc26e3392L,0xc07f8470a1722e00L,0xdcc28190e2356b43L,
        0x4ed97dffb1ef59a6L,0xc22b3ad1c63028c1L,0x070723c268c18988L },
      { 0x70da302f4cf49e7dL,0xc5e87c933f12a522L,0x74acdd1d18594148L,
        0xad5f73abca74124cL,0xe72e4a3ed69fd478L,0x615938687b117cc3L } },
    /* 241 */
    { { 0x7b7b9577a9aa0486L,0x6e41fb35a063d557L,0xb017d5c7da9047d7L,
        0x8c74828068a87ba9L,0xab45fa5cdf08ad93L,0xcd9fb2174c288a28L },
      { 0x595446425747843dL,0x34d64c6ca56111e3L,0x12e47ea14bfce8d5L,
        0x17740e056169267fL,0x5c49438eeed03fb5L,0x9da30add4fc3f513L } },
    /* 242 */
    { { 0xc4e85282ccfa5200L,0x2707608f6a19b13dL,0xdcb9a53df5726e2fL,
        0x612407c9e9427de5L,0x3e5a17e1d54d582aL,0xb99877de655ae118L },
      { 0x6f0e972b015254deL,0x92a56db1f0a6f7c5L,0xd297e4e1a656f8b2L,
        0x99fe0052ad981983L,0xd3652d2f07cfed84L,0xc784352e843c1738L } },
    /* 243 */
    { { 0x6ee90af07e9b2d8aL,0xac8d701857cf1964L,0xf6ed903171f28efcL,
        0x7f70d5a96812b20eL,0x27b557f4f1c61eeeL,0xf1c9bd57c6263758L },
      { 0x5cf7d0142a1a6194L,0xdd614e0b1890ab84L,0x3ef9de100e93c2a6L,
        0xf98cf575e0cd91c5L,0x504ec0c614befc32L,0xd0513a666279d68cL } },
    /* 244 */
    { { 0xa8eadbada859fb6aL,0xcf8346e7db283666L,0x7b35e61a3e22e355L,
        0x293ece2c99639c6bL,0xfa0162e256f241c8L,0xd2e6c7b9bf7a1ddaL },
      { 0xd0de625340075e63L,0x2405aa61f9ec8286L,0x2237830a8fe45494L,
        0x4fd01ac7364e9c8cL,0x4d9c3d21904ba750L,0xd589be14af1b520bL } },
    /* 245 */
    { { 0x13576a4f4662e53bL,0x35ec2f51f9077676L,0x66297d1397c0af97L,
        0xed3201fe9e598b58L,0x49bc752a5e70f604L,0xb54af535bb12d951L },
      { 0x36ea4c2b212c1c76L,0x18f5bbc7eb250dfdL,0xa0d466cc9a0a1a46L,
        0x52564da4dac2d917L,0x206559f48e95fab5L,0x7487c1909ca67a33L } },
    /* 246 */
    { { 0x75abfe37dde98e9cL,0x99b90b262a411199L,0x1b410996dcdb1f7cL,
        0xab346f118b3b5675L,0x04852193f1f8ae1eL,0x1ec4d2276b8b98c1L },
      { 0xba3bc92645452baaL,0x387d1858acc4a572L,0x9478eff6e51f171eL,
        0xf357077d931e1c00L,0xffee77cde54c8ca8L,0xfb4892ff551dc9a4L } },
    /* 247 */
    { { 0x5b1bdad02db8dff8L,0xd462f4fd5a2285a2L,0x1d6aad8eda00b461L,
        0x43fbefcf41306d1bL,0x428e86f36a13fe19L,0xc8b2f11817f89404L },
      { 0x762528aaf0d51afbL,0xa3e2fea4549b1d06L,0x86fad8f2ea3ddf66L,
        0x0d9ccc4b4fbdd206L,0xcde97d4cc189ff5aL,0xc36793d6199f19a6L } },
    /* 248 */
    { { 0xea38909b51b85197L,0xffb17dd0b4c92895L,0x0eb0878b1ddb3f3fL,
        0xb05d28ffc57cf0f2L,0xd8bde2e71abd57e2L,0x7f2be28dc40c1b20L },
      { 0x6554dca2299a2d48L,0x5130ba2e8377982dL,0x8863205f1071971aL,
        0x15ee62827cf2825dL,0xd4b6c57f03748f2bL,0xa9e3f4da430385a0L } },
    /* 249 */
    { { 0x33eb7cec83fbc9c6L,0x24a311c74541777eL,0xc81377f74f0767fcL,
        0x12adae364ab702daL,0xb7fcb6db2a779696L,0x4a6fb28401cea6adL },
      { 0x5e8b1d2acdfc73deL,0xd0efae8d1b02fd32L,0x3f99c190d81d8519L,
        0x3c18f7fafc808971L,0x41f713e751b7ae7bL,0x0a4b3435f07fc3f8L } },
    /* 250 */
    { { 0x7dda3c4c019b7d2eL,0x631c8d1ad4dc4b89L,0x5489cd6e1cdb313cL,
        0xd44aed104c07bb06L,0x8f97e13a75f000d1L,0x0e9ee64fdda5df4dL },
      { 0xeaa99f3b3e346910L,0x622f6921fa294ad7L,0x22aaa20d0d0b2fe9L,
        0x4fed2f991e5881baL,0x9af3b2d6c1571802L,0x919e67a8dc7ee17cL } },
    /* 251 */
    { { 0xc724fe4c76250533L,0x8a2080e57d817ef8L,0xa2afb0f4172c9751L,
        0x9b10cdeb17c0702eL,0xbf3975e3c9b7e3e9L,0x206117df1cd0cdc5L },
      { 0xfb049e61be05ebd5L,0xeb0bb55c16c782c0L,0x13a331b8ab7fed09L,
        0xf6c58b1d632863f0L,0x6264ef6e4d3b6195L,0x92c51b639a53f116L } },
    /* 252 */
    { { 0xa57c7bc8288b364dL,0x4a562e087b41e5c4L,0x699d21c6698a9a11L,
        0xa4ed9581f3f849b9L,0xa223eef39eb726baL,0x13159c23cc2884f9L },
      { 0x73931e583a3f4963L,0x965003890ada6a81L,0x3ee8a1c65ab2950bL,
        0xeedf4949775fab52L,0x63d652e14f2671b6L,0xfed4491c3c4e2f55L } },
    /* 253 */
    { { 0x335eadc3f4eb453eL,0x5ff74b63cadd1a5bL,0x6933d0d75d84a91aL,
        0x9ca3eeb9b49ba337L,0x1f6faccec04c15b8L,0x4ef19326dc09a7e4L },
      { 0x53d2d3243dca3233L,0x0ee40590a2259d4bL,0x18c22edb5546f002L,
        0x9242980109ea6b71L,0xaada0addb0e91e61L,0x5fe53ef499963c50L } },
    /* 254 */
    { { 0x372dd06b90c28c65L,0x1765242c119ce47dL,0xc041fb806b22fc82L,
        0x667edf07b0a7ccc1L,0xc79599e71261beceL,0xbc69d9ba19cff22aL },
      { 0x009d77cd13c06819L,0x635a66aee282b79dL,0x4edac4a6225b1be8L,
        0x57d4f4e4524008f9L,0xee299ac5b056af84L,0xcc38444c3a0bc386L } },
    /* 255 */
    { { 0x490643b1cd4c2356L,0x740a4851750547beL,0x643eaf29d4944c04L,
        0xba572479299a98a0L,0x48b29f16ee05fdf9L,0x33fb4f61089b2d7bL },
      { 0x86704902a950f955L,0x97e1034dfedc3ddfL,0x211320b605fbb6a2L,
        0x23d7b93f432299bbL,0x1fe1a0578590e4a3L,0x8e1d0586f58c0ce6L } },
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
static int sp_384_ecc_mulmod_base_6(sp_point_384* r, const sp_digit* k,
        int map, int ct, void* heap)
{
    return sp_384_ecc_mulmod_stripe_6(r, &p384_base, p384_table,
                                      k, map, ct, heap);
}

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
    sp_digit kd[6];
#endif
    sp_point_384* point;
    sp_digit* k = NULL;
    int err = MP_OKAY;

    err = sp_384_point_new_6(heap, p, point);
#if (defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)) && !defined(WOLFSSL_SP_NO_MALLOC)
    if (err == MP_OKAY) {
        k = (sp_digit*)XMALLOC(sizeof(sp_digit) * 6, heap,
                                                              DYNAMIC_TYPE_ECC);
        if (k == NULL) {
            err = MEMORY_E;
        }
    }
#else
    k = kd;
#endif
    if (err == MP_OKAY) {
        sp_384_from_mp(k, 6, km);

            err = sp_384_ecc_mulmod_base_6(point, k, map, 1, heap);
    }
    if (err == MP_OKAY) {
        err = sp_384_point_to_ecc_point_6(point, r);
    }

#if (defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)) && !defined(WOLFSSL_SP_NO_MALLOC)
    if (k != NULL) {
        XFREE(k, heap, DYNAMIC_TYPE_ECC);
    }
#endif
    sp_384_point_free_6(point, 0, heap);

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
static int sp_384_iszero_6(const sp_digit* a)
{
    return (a[0] | a[1] | a[2] | a[3] | a[4] | a[5]) == 0;
}

#endif /* WOLFSSL_VALIDATE_ECC_KEYGEN || HAVE_ECC_SIGN || HAVE_ECC_VERIFY */
/* Add 1 to a. (a = a + 1)
 *
 * a  A single precision integer.
 */
static void sp_384_add_one_6(sp_digit* a)
{
    __asm__ __volatile__ (
        "ldp	x1, x2, [%[a], 0]\n\t"
        "adds	x1, x1, #1\n\t"
        "ldr	x3, [%[a], 16]\n\t"
        "adcs	x2, x2, xzr\n\t"
        "ldr	x4, [%[a], 24]\n\t"
        "adcs	x3, x3, xzr\n\t"
        "stp	x1, x2, [%[a], 0]\n\t"
        "adcs	x4, x4, xzr\n\t"
        "stp	x3, x4, [%[a], 16]\n\t"
        "ldp	x1, x2, [%[a], 32]\n\t"
        "adcs	x1, x1, xzr\n\t"
        "adcs	x2, x2, xzr\n\t"
        "stp	x1, x2, [%[a], 32]\n\t"
        :
        : [a] "r" (a)
        : "memory", "x1", "x2", "x3", "x4"
    );
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
    int i, j;
    byte* d;

    for (i = n - 1,j = 0; i >= 7; i -= 8) {
        r[j]  = ((sp_digit)a[i - 0] <<  0) |
                ((sp_digit)a[i - 1] <<  8) |
                ((sp_digit)a[i - 2] << 16) |
                ((sp_digit)a[i - 3] << 24) |
                ((sp_digit)a[i - 4] << 32) |
                ((sp_digit)a[i - 5] << 40) |
                ((sp_digit)a[i - 6] << 48) |
                ((sp_digit)a[i - 7] << 56);
        j++;
    }

    if (i >= 0) {
        r[j] = 0;

        d = (byte*)r;
        switch (i) {
            case 6: d[n - 1 - 6] = a[6]; //fallthrough
            case 5: d[n - 1 - 5] = a[5]; //fallthrough
            case 4: d[n - 1 - 4] = a[4]; //fallthrough
            case 3: d[n - 1 - 3] = a[3]; //fallthrough
            case 2: d[n - 1 - 2] = a[2]; //fallthrough
            case 1: d[n - 1 - 1] = a[1]; //fallthrough
            case 0: d[n - 1 - 0] = a[0]; //fallthrough
        }
        j++;
    }

    for (; j < size; j++) {
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
static int sp_384_ecc_gen_k_6(WC_RNG* rng, sp_digit* k)
{
    int err;
    byte buf[48];

    do {
        err = wc_RNG_GenerateBlock(rng, buf, sizeof(buf));
        if (err == 0) {
            sp_384_from_bin(k, 6, buf, (int)sizeof(buf));
            if (sp_384_cmp_6(k, p384_order2) < 0) {
                sp_384_add_one_6(k);
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
    sp_digit kd[6];
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

    err = sp_384_point_new_6(heap, p, point);
#ifdef WOLFSSL_VALIDATE_ECC_KEYGEN
    if (err == MP_OKAY) {
        err = sp_384_point_new_6(heap, inf, infinity);
    }
#endif
#if (defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)) && !defined(WOLFSSL_SP_NO_MALLOC)
    if (err == MP_OKAY) {
        k = (sp_digit*)XMALLOC(sizeof(sp_digit) * 6, heap,
                                                              DYNAMIC_TYPE_ECC);
        if (k == NULL) {
            err = MEMORY_E;
        }
    }
#else
    k = kd;
#endif

    if (err == MP_OKAY) {
        err = sp_384_ecc_gen_k_6(rng, k);
    }
    if (err == MP_OKAY) {
            err = sp_384_ecc_mulmod_base_6(point, k, 1, 1, NULL);
    }

#ifdef WOLFSSL_VALIDATE_ECC_KEYGEN
    if (err == MP_OKAY) {
            err = sp_384_ecc_mulmod_6(infinity, point, p384_order, 1, 1, NULL);
    }
    if (err == MP_OKAY) {
        if (sp_384_iszero_6(point->x) || sp_384_iszero_6(point->y)) {
            err = ECC_INF_E;
        }
    }
#endif

    if (err == MP_OKAY) {
        err = sp_384_to_mp(k, priv);
    }
    if (err == MP_OKAY) {
        err = sp_384_point_to_ecc_point_6(point, pub);
    }

#if (defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)) && !defined(WOLFSSL_SP_NO_MALLOC)
    if (k != NULL) {
        XFREE(k, heap, DYNAMIC_TYPE_ECC);
    }
#endif
#ifdef WOLFSSL_VALIDATE_ECC_KEYGEN
    sp_384_point_free_6(infinity, 1, heap);
#endif
    sp_384_point_free_6(point, 1, heap);

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
    int i, j;

    for (i = 5, j = 0; i >= 0; i--) {
        a[j++] = r[i] >> 56;
        a[j++] = r[i] >> 48;
        a[j++] = r[i] >> 40;
        a[j++] = r[i] >> 32;
        a[j++] = r[i] >> 24;
        a[j++] = r[i] >> 16;
        a[j++] = r[i] >> 8;
        a[j++] = r[i] >> 0;
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
    sp_digit kd[6];
#endif
    sp_point_384* point = NULL;
    sp_digit* k = NULL;
    int err = MP_OKAY;

    if (*outLen < 48U) {
        err = BUFFER_E;
    }

    if (err == MP_OKAY) {
        err = sp_384_point_new_6(heap, p, point);
    }
#if (defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)) && !defined(WOLFSSL_SP_NO_MALLOC)
    if (err == MP_OKAY) {
        k = (sp_digit*)XMALLOC(sizeof(sp_digit) * 6, heap,
                                                              DYNAMIC_TYPE_ECC);
        if (k == NULL)
            err = MEMORY_E;
    }
#else
    k = kd;
#endif

    if (err == MP_OKAY) {
        sp_384_from_mp(k, 6, priv);
        sp_384_point_from_ecc_point_6(point, pub);
            err = sp_384_ecc_mulmod_6(point, point, k, 1, 1, heap);
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
    sp_384_point_free_6(point, 0, heap);

    return err;
}
#endif /* HAVE_ECC_DHE */

#if defined(HAVE_ECC_SIGN) || defined(HAVE_ECC_VERIFY)
#endif
#if defined(HAVE_ECC_SIGN) || defined(HAVE_ECC_VERIFY)
/* Sub b from a into a. (a -= b)
 *
 * a  A single precision integer and result.
 * b  A single precision integer.
 */
static sp_digit sp_384_sub_in_place_6(sp_digit* a, const sp_digit* b)
{
    __asm__ __volatile__ (
        "ldp	x2, x3, [%[a], 0]\n\t"
        "ldp	x6, x7, [%[b], 0]\n\t"
        "subs	x2, x2, x6\n\t"
        "ldp	x4, x5, [%[a], 16]\n\t"
        "sbcs	x3, x3, x7\n\t"
        "ldp	x8, x9, [%[b], 16]\n\t"
        "sbcs	x4, x4, x8\n\t"
        "stp	x2, x3, [%[a], 0]\n\t"
        "sbcs	x5, x5, x9\n\t"
        "stp	x4, x5, [%[a], 16]\n\t"
        "ldr		x2, [%[a], 32]\n\t"
        "ldr		x3, [%[a], 40]\n\t"
        "ldr		x6, [%[b], 32]\n\t"
        "ldr		x7, [%[b], 40]\n\t"
        "sbcs	x2, x2, x6\n\t"
        "sbcs	x3, x3, x7\n\t"
        "str		x2, [%[a], 32]\n\t"
        "str		x3, [%[a], 40]\n\t"
        "csetm	%[a], cc\n\t"
        : [a] "+r" (a)
        : [b] "r" (b)
        : "memory", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9"
    );

    return (sp_digit)a;
}

/* Mul a by digit b into r. (r = a * b)
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * b  A single precision digit.
 */
static void sp_384_mul_d_6(sp_digit* r, const sp_digit* a,
        sp_digit b)
{
#ifdef WOLFSSL_SP_SMALL
    __asm__ __volatile__ (
        "# A[0] * B\n\t"
        "ldr	x8, [%[a]]\n\t"
        "mul	x5, %[b], x8\n\t"
        "umulh	x3, %[b], x8\n\t"
        "mov	x4, 0\n\t"
        "str	x5, [%[r]]\n\t"
        "mov	x5, 0\n\t"
        "mov	x9, #8\n\t"
        "1:\n\t"
        "ldr	x8, [%[a], x9]\n\t"
        "mul	x6, %[b], x8\n\t"
        "umulh	x7, %[b], x8\n\t"
        "adds	x3, x3, x6\n\t"
        "adcs	x4, x4, x7\n\t"
        "adc	x5, xzr, xzr\n\t"
        "str	x3, [%[r], x9]\n\t"
        "mov	x3, x4\n\t"
        "mov	x4, x5\n\t"
        "mov	x5, #0\n\t"
        "add	x9, x9, #8\n\t"
        "cmp	x9, 48\n\t"
        "b.lt	1b\n\t"
        "str	x3, [%[r], 48]\n\t"
        :
        : [r] "r" (r), [a] "r" (a), [b] "r" (b)
        : "memory", "x3", "x4", "x5", "x6", "x7", "x8", "x9"
    );
#else
    __asm__ __volatile__ (
        "# A[0] * B\n\t"
        "ldp	x8, x9, [%[a]]\n\t"
        "mul	x3, %[b], x8\n\t"
        "umulh	x4, %[b], x8\n\t"
        "mov	x5, 0\n\t"
        "# A[1] * B\n\t"
        "str	x3, [%[r]]\n\t"
        "mov	x3, 0\n\t"
        "mul	x6, %[b], x9\n\t"
        "umulh	x7, %[b], x9\n\t"
        "adds	x4, x4, x6\n\t"
        "# A[2] * B\n\t"
        "ldp	x8, x9, [%[a], 16]\n\t"
        "str	x4, [%[r], 8]\n\t"
        "mov	x4, 0\n\t"
        "mul	x6, %[b], x8\n\t"
        "adcs	x5, x5, x7\n\t"
        "umulh	x7, %[b], x8\n\t"
        "adc	x3, xzr, xzr\n\t"
        "adds	x5, x5, x6\n\t"
        "# A[3] * B\n\t"
        "str	x5, [%[r], 16]\n\t"
        "mov	x5, 0\n\t"
        "mul	x6, %[b], x9\n\t"
        "adcs	x3, x3, x7\n\t"
        "umulh	x7, %[b], x9\n\t"
        "adc	x4, xzr, xzr\n\t"
        "adds	x3, x3, x6\n\t"
        "# A[4] * B\n\t"
        "ldp	x8, x9, [%[a], 32]\n\t"
        "str	x3, [%[r], 24]\n\t"
        "mov	x3, 0\n\t"
        "mul	x6, %[b], x8\n\t"
        "adcs	x4, x4, x7\n\t"
        "umulh	x7, %[b], x8\n\t"
        "adc	x5, xzr, xzr\n\t"
        "adds	x4, x4, x6\n\t"
        "# A[5] * B\n\t"
        "str	x4, [%[r], 32]\n\t"
        "mul	x6, %[b], x9\n\t"
        "adcs	x5, x5, x7\n\t"
        "umulh	x7, %[b], x9\n\t"
        "adc	x3, xzr, xzr\n\t"
        "adds	x5, x5, x6\n\t"
        "adc	x3, x3, x7\n\t"
        "stp	x5, x3, [%[r], 40]\n\t"
        :
        : [r] "r" (r), [a] "r" (a), [b] "r" (b)
        : "memory", "x3", "x4", "x5", "x6", "x7", "x8", "x9"
    );
#endif
}

/* Divide the double width number (d1|d0) by the dividend. (d1|d0 / div)
 *
 * d1   The high order half of the number to divide.
 * d0   The low order half of the number to divide.
 * div  The dividend.
 * returns the result of the division.
 */
static sp_digit div_384_word_6(sp_digit d1, sp_digit d0, sp_digit div)
{
    sp_digit r;

    __asm__ __volatile__ (
        "lsr	x5, %[div], 32\n\t"
        "add	x5, x5, 1\n\t"

        "udiv	x3, %[d1], x5\n\t"
        "lsl	x6, x3, 32\n\t"
        "mul	x4, %[div], x6\n\t"
        "umulh	x3, %[div], x6\n\t"
        "subs	%[d0], %[d0], x4\n\t"
        "sbc	%[d1], %[d1], x3\n\t"

        "udiv	x3, %[d1], x5\n\t"
        "lsl	x3, x3, 32\n\t"
        "add	x6, x6, x3\n\t"
        "mul	x4, %[div], x3\n\t"
        "umulh	x3, %[div], x3\n\t"
        "subs	%[d0], %[d0], x4\n\t"
        "sbc	%[d1], %[d1], x3\n\t"

        "lsr	x3, %[d0], 32\n\t"
        "orr	x3, x3, %[d1], lsl 32\n\t"

        "udiv	x3, x3, x5\n\t"
        "add	x6, x6, x3\n\t"
        "mul	x4, %[div], x3\n\t"
        "umulh	x3, %[div], x3\n\t"
        "subs	%[d0], %[d0], x4\n\t"
        "sbc	%[d1], %[d1], x3\n\t"

        "lsr	x3, %[d0], 32\n\t"
        "orr	x3, x3, %[d1], lsl 32\n\t"

        "udiv	x3, x3, x5\n\t"
        "add	x6, x6, x3\n\t"
        "mul	x4, %[div], x3\n\t"
        "sub	%[d0], %[d0], x4\n\t"

        "udiv	x3, %[d0], %[div]\n\t"
        "add	%[r], x6, x3\n\t"

        : [r] "=r" (r)
        : [d1] "r" (d1), [d0] "r" (d0), [div] "r" (div)
        : "x3", "x4", "x5", "x6"
    );

    return r;
}

/* AND m into each word of a and store in r.
 *
 * r  A single precision integer.
 * a  A single precision integer.
 * m  Mask to AND against each digit.
 */
static void sp_384_mask_6(sp_digit* r, const sp_digit* a, sp_digit m)
{
#ifdef WOLFSSL_SP_SMALL
    int i;

    for (i=0; i<6; i++) {
        r[i] = a[i] & m;
    }
#else
    r[0] = a[0] & m;
    r[1] = a[1] & m;
    r[2] = a[2] & m;
    r[3] = a[3] & m;
    r[4] = a[4] & m;
    r[5] = a[5] & m;
#endif
}

/* Divide d in a and put remainder into r (m*d + r = a)
 * m is not calculated as it is not needed at this time.
 *
 * a  Number to be divided.
 * d  Number to divide with.
 * m  Multiplier result.
 * r  Remainder from the division.
 * returns MP_OKAY indicating success.
 */
static WC_INLINE int sp_384_div_6(const sp_digit* a, const sp_digit* d, sp_digit* m,
        sp_digit* r)
{
    sp_digit t1[12], t2[7];
    sp_digit div, r1;
    int i;

    (void)m;

    div = d[5];
    XMEMCPY(t1, a, sizeof(*t1) * 2 * 6);
    for (i=5; i>=0; i--) {
        sp_digit hi = t1[6 + i] - (t1[6 + i] == div);
        r1 = div_384_word_6(hi, t1[6 + i - 1], div);

        sp_384_mul_d_6(t2, d, r1);
        t1[6 + i] += sp_384_sub_in_place_6(&t1[i], t2);
        t1[6 + i] -= t2[6];
        sp_384_mask_6(t2, d, t1[6 + i]);
        t1[6 + i] += sp_384_add_6(&t1[i], &t1[i], t2);
        sp_384_mask_6(t2, d, t1[6 + i]);
        t1[6 + i] += sp_384_add_6(&t1[i], &t1[i], t2);
    }

    r1 = sp_384_cmp_6(t1, d) >= 0;
    sp_384_cond_sub_6(r, t1, d, (sp_digit)0 - r1);

    return MP_OKAY;
}

/* Reduce a modulo m into r. (r = a mod m)
 *
 * r  A single precision number that is the reduced result.
 * a  A single precision number that is to be reduced.
 * m  A single precision number that is the modulus to reduce with.
 * returns MP_OKAY indicating success.
 */
static WC_INLINE int sp_384_mod_6(sp_digit* r, const sp_digit* a, const sp_digit* m)
{
    return sp_384_div_6(a, m, NULL, r);
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
static void sp_384_mont_mul_order_6(sp_digit* r, const sp_digit* a, const sp_digit* b)
{
    sp_384_mul_6(r, a, b);
    sp_384_mont_reduce_order_6(r, p384_order, p384_mp_order);
}

/* Square number mod the order of P384 curve. (r = a * a mod order)
 *
 * r  Result of the squaring.
 * a  Number to square.
 */
static void sp_384_mont_sqr_order_6(sp_digit* r, const sp_digit* a)
{
    sp_384_sqr_6(r, a);
    sp_384_mont_reduce_order_6(r, p384_order, p384_mp_order);
}

#ifndef WOLFSSL_SP_SMALL
/* Square number mod the order of P384 curve a number of times.
 * (r = a ^ n mod order)
 *
 * r  Result of the squaring.
 * a  Number to square.
 */
static void sp_384_mont_sqr_n_order_6(sp_digit* r, const sp_digit* a, int n)
{
    int i;

    sp_384_mont_sqr_order_6(r, a);
    for (i=1; i<n; i++) {
        sp_384_mont_sqr_order_6(r, r);
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

static void sp_384_mont_inv_order_6(sp_digit* r, const sp_digit* a,
        sp_digit* td)
{
#ifdef WOLFSSL_SP_SMALL
    sp_digit* t = td;
    int i;

    XMEMCPY(t, a, sizeof(sp_digit) * 6);
    for (i=382; i>=0; i--) {
        sp_384_mont_sqr_order_6(t, t);
        if ((p384_order_minus_2[i / 64] & ((sp_int_digit)1 << (i % 64))) != 0) {
            sp_384_mont_mul_order_6(t, t, a);
        }
    }
    XMEMCPY(r, t, sizeof(sp_digit) * 6U);
#else
    sp_digit* t = td;
    sp_digit* t2 = td + 2 * 6;
    sp_digit* t3 = td + 4 * 6;
    int i;

    /* t = a^2 */
    sp_384_mont_sqr_order_6(t, a);
    /* t = a^3 = t * a */
    sp_384_mont_mul_order_6(t, t, a);
    /* t2= a^c = t ^ 2 ^ 2 */
    sp_384_mont_sqr_n_order_6(t2, t, 2);
    /* t = a^f = t2 * t */
    sp_384_mont_mul_order_6(t, t2, t);
    /* t2= a^f0 = t ^ 2 ^ 4 */
    sp_384_mont_sqr_n_order_6(t2, t, 4);
    /* t = a^ff = t2 * t */
    sp_384_mont_mul_order_6(t, t2, t);
    /* t2= a^ff00 = t ^ 2 ^ 8 */
    sp_384_mont_sqr_n_order_6(t2, t, 8);
    /* t3= a^ffff = t2 * t */
    sp_384_mont_mul_order_6(t3, t2, t);
    /* t2= a^ffff0000 = t3 ^ 2 ^ 16 */
    sp_384_mont_sqr_n_order_6(t2, t3, 16);
    /* t = a^ffffffff = t2 * t3 */
    sp_384_mont_mul_order_6(t, t2, t3);
    /* t2= a^ffffffff0000 = t ^ 2 ^ 16  */
    sp_384_mont_sqr_n_order_6(t2, t, 16);
    /* t = a^ffffffffffff = t2 * t3 */
    sp_384_mont_mul_order_6(t, t2, t3);
    /* t2= a^ffffffffffff000000000000 = t ^ 2 ^ 48  */
    sp_384_mont_sqr_n_order_6(t2, t, 48);
    /* t= a^fffffffffffffffffffffffff = t2 * t */
    sp_384_mont_mul_order_6(t, t2, t);
    /* t2= a^ffffffffffffffffffffffff000000000000000000000000 */
    sp_384_mont_sqr_n_order_6(t2, t, 96);
    /* t2= a^ffffffffffffffffffffffffffffffffffffffffffffffff = t2 * t */
    sp_384_mont_mul_order_6(t2, t2, t);
    for (i=191; i>=1; i--) {
        sp_384_mont_sqr_order_6(t2, t2);
        if (((sp_digit)p384_order_low[i / 64] & ((sp_int_digit)1 << (i % 64))) != 0) {
            sp_384_mont_mul_order_6(t2, t2, a);
        }
    }
    sp_384_mont_sqr_order_6(t2, t2);
    sp_384_mont_mul_order_6(r, t2, a);
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
    sp_digit ed[2*6];
    sp_digit xd[2*6];
    sp_digit kd[2*6];
    sp_digit rd[2*6];
    sp_digit td[3 * 2*6];
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

    err = sp_384_point_new_6(heap, p, point);
#if (defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)) && !defined(WOLFSSL_SP_NO_MALLOC)
    if (err == MP_OKAY) {
        d = (sp_digit*)XMALLOC(sizeof(sp_digit) * 7 * 2 * 6, heap,
                                                              DYNAMIC_TYPE_ECC);
        if (d == NULL) {
            err = MEMORY_E;
        }
    }
#endif

    if (err == MP_OKAY) {
#if (defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)) && !defined(WOLFSSL_SP_NO_MALLOC)
        e = d + 0 * 6;
        x = d + 2 * 6;
        k = d + 4 * 6;
        r = d + 6 * 6;
        tmp = d + 8 * 6;
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
    }

    for (i = SP_ECC_MAX_SIG_GEN; err == MP_OKAY && i > 0; i--) {
        sp_384_from_mp(x, 6, priv);

        /* New random point. */
        if (km == NULL || mp_iszero(km)) {
            err = sp_384_ecc_gen_k_6(rng, k);
        }
        else {
            sp_384_from_mp(k, 6, km);
            mp_zero(km);
        }
        if (err == MP_OKAY) {
                err = sp_384_ecc_mulmod_base_6(point, k, 1, 1, NULL);
        }

        if (err == MP_OKAY) {
            /* r = point->x mod order */
            XMEMCPY(r, point->x, sizeof(sp_digit) * 6U);
            sp_384_norm_6(r);
            c = sp_384_cmp_6(r, p384_order);
            sp_384_cond_sub_6(r, r, p384_order, 0L - (sp_digit)(c >= 0));
            sp_384_norm_6(r);

            /* Conv k to Montgomery form (mod order) */
                sp_384_mul_6(k, k, p384_norm_order);
            err = sp_384_mod_6(k, k, p384_order);
        }
        if (err == MP_OKAY) {
            sp_384_norm_6(k);
            /* kInv = 1/k mod order */
                sp_384_mont_inv_order_6(kInv, k, tmp);
            sp_384_norm_6(kInv);

            /* s = r * x + e */
                sp_384_mul_6(x, x, r);
            err = sp_384_mod_6(x, x, p384_order);
        }
        if (err == MP_OKAY) {
            sp_384_norm_6(x);
            sp_384_from_bin(e, 6, hash, (int)hashLen);
            carry = sp_384_add_6(s, e, x);
            sp_384_cond_sub_6(s, s, p384_order, 0 - carry);
            sp_384_norm_6(s);
            c = sp_384_cmp_6(s, p384_order);
            sp_384_cond_sub_6(s, s, p384_order, 0L - (sp_digit)(c >= 0));
            sp_384_norm_6(s);

            /* s = s * k^-1 mod order */
                sp_384_mont_mul_order_6(s, s, kInv);
            sp_384_norm_6(s);

            /* Check that signature is usable. */
            if (sp_384_iszero_6(s) == 0) {
                break;
            }
        }
#ifdef WOLFSSL_ECDSA_SET_K_ONE_LOOP
        i = 1;
#endif
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
        XMEMSET(d, 0, sizeof(sp_digit) * 8 * 6);
        XFREE(d, heap, DYNAMIC_TYPE_ECC);
    }
#else
    XMEMSET(e, 0, sizeof(sp_digit) * 2U * 6U);
    XMEMSET(x, 0, sizeof(sp_digit) * 2U * 6U);
    XMEMSET(k, 0, sizeof(sp_digit) * 2U * 6U);
    XMEMSET(r, 0, sizeof(sp_digit) * 2U * 6U);
    XMEMSET(r, 0, sizeof(sp_digit) * 2U * 6U);
    XMEMSET(tmp, 0, sizeof(sp_digit) * 3U * 2U * 6U);
#endif
    sp_384_point_free_6(point, 1, heap);

    return err;
}
#endif /* HAVE_ECC_SIGN */

#ifndef WOLFSSL_SP_SMALL
/* Divide the number by 2 mod the modulus. (r = a / 2 % m)
 *
 * r  Result of division by 2.
 * a  Number to divide.
 * m  Modulus.
 */
static void sp_384_div2_mod_6(sp_digit* r, const sp_digit* a,
    const sp_digit* m)
{
    __asm__ __volatile__ (
        "ldr     x3, [%[a], 0]\n\t"
        "ldr     x4, [%[a], 8]\n\t"
        "ldr     x5, [%[a], 16]\n\t"
        "ldr     x6, [%[a], 24]\n\t"
        "ldr     x7, [%[a], 32]\n\t"
        "ldr     x8, [%[a], 40]\n\t"
        "ldr     x9, [%[m], 0]\n\t"
        "ldr     x10, [%[m], 8]\n\t"
        "ldr     x11, [%[m], 16]\n\t"
        "ldr     x12, [%[m], 24]\n\t"
        "ldr     x13, [%[m], 32]\n\t"
        "ldr     x14, [%[m], 40]\n\t"
        "ands      x15, x3, 1\n\t"
        "b.eq      1f\n\t"
        "adds      x3, x3, x9\n\t"
        "adcs    x4, x4, x10\n\t"
        "adcs    x5, x5, x11\n\t"
        "adcs    x6, x6, x12\n\t"
        "adcs    x7, x7, x13\n\t"
        "adcs    x8, x8, x14\n\t"
        "cset      x15, cs\n\t"
        "\n1:\n\t"
        "lsr       x3, x3, 1\n\t"
        "lsr     x10, x4, 1\n\t"
        "lsr     x11, x5, 1\n\t"
        "lsr     x12, x6, 1\n\t"
        "lsr     x13, x7, 1\n\t"
        "lsr     x14, x8, 1\n\t"
        "orr       x3, x3, x4, lsl 63\n\t"
        "orr     x4, x10, x5, lsl 63\n\t"
        "orr     x5, x11, x6, lsl 63\n\t"
        "orr     x6, x12, x7, lsl 63\n\t"
        "orr     x7, x13, x8, lsl 63\n\t"
        "orr       x8, x14, x15, lsl 63\n\t"
        "str     x3, [%[r], 0]\n\t"
        "str     x4, [%[r], 8]\n\t"
        "str     x5, [%[r], 16]\n\t"
        "str     x6, [%[r], 24]\n\t"
        "str     x7, [%[r], 32]\n\t"
        "str     x8, [%[r], 40]\n\t"
        :
        : [r] "r" (r), [a] "r" (a), [m] "r" (m)
        : "memory", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15"
    );
}

static int sp_384_num_bits_64_6(sp_digit n)
{
    int64_t r = -1;

    __asm__ __volatile__ (
        "mov	x1, 64\n\t"
        "clz	%[r], %[n]\n\t"
        "sub	%[r], x1, %[r]"
        : [r] "+r" (r)
        : [n] "r" (n)
        : "x1"
    );

    return r + 1;
}

static int sp_384_num_bits_6(const sp_digit* a)
{
    int i;
    int r = 0;

    for (i=5; i>=0; i--) {
        if (a[i] != 0) {
            r = sp_384_num_bits_64_6(a[i]);
            r += i * 64;
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
 */
static int sp_384_mod_inv_6(sp_digit* r, const sp_digit* a, const sp_digit* m)
{
    sp_digit u[6];
    sp_digit v[6];
    sp_digit b[6];
    sp_digit d[6];
    int ut, vt;
    sp_digit o;

    XMEMCPY(u, m, sizeof(u));
    XMEMCPY(v, a, sizeof(v));

    ut = sp_384_num_bits_6(u);
    vt = sp_384_num_bits_6(v);

    XMEMSET(b, 0, sizeof(b));
    if ((v[0] & 1) == 0) {
        sp_384_rshift1_6(v, v);
        XMEMCPY(d, m, sizeof(u));
        d[0] += 1;
        sp_384_rshift1_6(d, d);
        vt--;

        while ((v[0] & 1) == 0) {
            sp_384_rshift1_6(v, v);
            sp_384_div2_mod_6(d, d, m);
            vt--;
        }
    }
    else {
        XMEMSET(d+1, 0, sizeof(d)-sizeof(sp_digit));
        d[0] = 1;
    }

    while (ut > 1 && vt > 1) {
        if (ut > vt || (ut == vt && sp_384_cmp_6(u, v) >= 0)) {
            sp_384_sub_6(u, u, v);
            o = sp_384_sub_6(b, b, d);
            if (o != 0)
                sp_384_add_6(b, b, m);
            ut = sp_384_num_bits_6(u);

            do {
                sp_384_rshift1_6(u, u);
                sp_384_div2_mod_6(b, b, m);
                ut--;
            }
            while (ut > 0 && (u[0] & 1) == 0);
        }
        else {
            sp_384_sub_6(v, v, u);
            o = sp_384_sub_6(d, d, b);
            if (o != 0)
                sp_384_add_6(d, d, m);
            vt = sp_384_num_bits_6(v);

            do {
                sp_384_rshift1_6(v, v);
                sp_384_div2_mod_6(d, d, m);
                vt--;
            }
            while (vt > 0 && (v[0] & 1) == 0);
        }
    }

    if (ut == 1)
        XMEMCPY(r, b, sizeof(b));
    else
        XMEMCPY(r, d, sizeof(d));

    return MP_OKAY;
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
    sp_digit u1d[2*6];
    sp_digit u2d[2*6];
    sp_digit sd[2*6];
    sp_digit tmpd[2*6 * 5];
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

    err = sp_384_point_new_6(heap, p1d, p1);
    if (err == MP_OKAY) {
        err = sp_384_point_new_6(heap, p2d, p2);
    }
#if (defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)) && !defined(WOLFSSL_SP_NO_MALLOC)
    if (err == MP_OKAY) {
        d = (sp_digit*)XMALLOC(sizeof(sp_digit) * 16 * 6, heap,
                                                              DYNAMIC_TYPE_ECC);
        if (d == NULL) {
            err = MEMORY_E;
        }
    }
#endif

    if (err == MP_OKAY) {
#if (defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)) && !defined(WOLFSSL_SP_NO_MALLOC)
        u1  = d + 0 * 6;
        u2  = d + 2 * 6;
        s   = d + 4 * 6;
        tmp = d + 6 * 6;
#else
        u1 = u1d;
        u2 = u2d;
        s  = sd;
        tmp = tmpd;
#endif

        if (hashLen > 48U) {
            hashLen = 48U;
        }

        sp_384_from_bin(u1, 6, hash, (int)hashLen);
        sp_384_from_mp(u2, 6, r);
        sp_384_from_mp(s, 6, sm);
        sp_384_from_mp(p2->x, 6, pX);
        sp_384_from_mp(p2->y, 6, pY);
        sp_384_from_mp(p2->z, 6, pZ);

#ifndef WOLFSSL_SP_SMALL
        {
            sp_384_mod_inv_6(s, s, p384_order);
        }
#endif /* !WOLFSSL_SP_SMALL */
        {
            sp_384_mul_6(s, s, p384_norm_order);
        }
        err = sp_384_mod_6(s, s, p384_order);
    }
    if (err == MP_OKAY) {
        sp_384_norm_6(s);
#ifdef WOLFSSL_SP_SMALL
        {
            sp_384_mont_inv_order_6(s, s, tmp);
            sp_384_mont_mul_order_6(u1, u1, s);
            sp_384_mont_mul_order_6(u2, u2, s);
        }

#else
        {
            sp_384_mont_mul_order_6(u1, u1, s);
            sp_384_mont_mul_order_6(u2, u2, s);
        }

#endif /* WOLFSSL_SP_SMALL */
            err = sp_384_ecc_mulmod_base_6(p1, u1, 0, 0, heap);
    }
    if ((err == MP_OKAY) && sp_384_iszero_6(p1->z)) {
        p1->infinity = 1;
    }
    if (err == MP_OKAY) {
            err = sp_384_ecc_mulmod_6(p2, p2, u2, 0, 0, heap);
    }
    if ((err == MP_OKAY) && sp_384_iszero_6(p2->z)) {
        p2->infinity = 1;
    }

    if (err == MP_OKAY) {
        {
            sp_384_proj_point_add_6(p1, p1, p2, tmp);
            if (sp_384_iszero_6(p1->z)) {
                if (sp_384_iszero_6(p1->x) && sp_384_iszero_6(p1->y)) {
                    sp_384_proj_point_dbl_6(p1, p2, tmp);
                }
                else {
                    /* Y ordinate is not used from here - don't set. */
                    p1->x[0] = 0;
                    p1->x[1] = 0;
                    p1->x[2] = 0;
                    p1->x[3] = 0;
                    p1->x[4] = 0;
                    p1->x[5] = 0;
                    XMEMCPY(p1->z, p384_norm_mod, sizeof(p384_norm_mod));
                }
            }
        }

        /* (r + n*order).z'.z' mod prime == (u1.G + u2.Q)->x' */
        /* Reload r and convert to Montgomery form. */
        sp_384_from_mp(u2, 6, r);
        err = sp_384_mod_mul_norm_6(u2, u2, p384_mod);
    }

    if (err == MP_OKAY) {
        /* u1 = r.z'.z' mod prime */
        sp_384_mont_sqr_6(p1->z, p1->z, p384_mod, p384_mp_mod);
        sp_384_mont_mul_6(u1, u2, p1->z, p384_mod, p384_mp_mod);
        *res = (int)(sp_384_cmp_6(p1->x, u1) == 0);
        if (*res == 0) {
            /* Reload r and add order. */
            sp_384_from_mp(u2, 6, r);
            carry = sp_384_add_6(u2, u2, p384_order);
            /* Carry means result is greater than mod and is not valid. */
            if (carry == 0) {
                sp_384_norm_6(u2);

                /* Compare with mod and if greater or equal then not valid. */
                c = sp_384_cmp_6(u2, p384_mod);
                if (c < 0) {
                    /* Convert to Montogomery form */
                    err = sp_384_mod_mul_norm_6(u2, u2, p384_mod);
                    if (err == MP_OKAY) {
                        /* u1 = (r + 1*order).z'.z' mod prime */
                        sp_384_mont_mul_6(u1, u2, p1->z, p384_mod,
                                                                  p384_mp_mod);
                        *res = (int)(sp_384_cmp_6(p1->x, u1) == 0);
                    }
                }
            }
        }
    }

#if (defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)) && !defined(WOLFSSL_SP_NO_MALLOC)
    if (d != NULL)
        XFREE(d, heap, DYNAMIC_TYPE_ECC);
#endif
    sp_384_point_free_6(p1, 0, heap);
    sp_384_point_free_6(p2, 0, heap);

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
static int sp_384_ecc_is_point_6(sp_point_384* point, void* heap)
{
#if (defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)) && !defined(WOLFSSL_SP_NO_MALLOC)
    sp_digit* d = NULL;
#else
    sp_digit t1d[2*6];
    sp_digit t2d[2*6];
#endif
    sp_digit* t1;
    sp_digit* t2;
    int err = MP_OKAY;

#if (defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)) && !defined(WOLFSSL_SP_NO_MALLOC)
    d = (sp_digit*)XMALLOC(sizeof(sp_digit) * 6 * 4, heap, DYNAMIC_TYPE_ECC);
    if (d == NULL) {
        err = MEMORY_E;
    }
#endif
    (void)heap;

    if (err == MP_OKAY) {
#if (defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)) && !defined(WOLFSSL_SP_NO_MALLOC)
        t1 = d + 0 * 6;
        t2 = d + 2 * 6;
#else
        t1 = t1d;
        t2 = t2d;
#endif

        sp_384_sqr_6(t1, point->y);
        (void)sp_384_mod_6(t1, t1, p384_mod);
        sp_384_sqr_6(t2, point->x);
        (void)sp_384_mod_6(t2, t2, p384_mod);
        sp_384_mul_6(t2, t2, point->x);
        (void)sp_384_mod_6(t2, t2, p384_mod);
        (void)sp_384_sub_6(t2, p384_mod, t2);
        sp_384_mont_add_6(t1, t1, t2, p384_mod);

        sp_384_mont_add_6(t1, t1, point->x, p384_mod);
        sp_384_mont_add_6(t1, t1, point->x, p384_mod);
        sp_384_mont_add_6(t1, t1, point->x, p384_mod);

        if (sp_384_cmp_6(t1, p384_b) != 0) {
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

    err = sp_384_point_new_6(NULL, pubd, pub);
    if (err == MP_OKAY) {
        sp_384_from_mp(pub->x, 6, pX);
        sp_384_from_mp(pub->y, 6, pY);
        sp_384_from_bin(pub->z, 6, one, (int)sizeof(one));

        err = sp_384_ecc_is_point_6(pub, NULL);
    }

    sp_384_point_free_6(pub, 0, NULL);

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
    sp_digit privd[6];
    sp_point_384 pubd;
    sp_point_384 pd;
#endif
    sp_digit* priv = NULL;
    sp_point_384* pub;
    sp_point_384* p = NULL;
    byte one[1] = { 1 };
    int err;

    err = sp_384_point_new_6(heap, pubd, pub);
    if (err == MP_OKAY) {
        err = sp_384_point_new_6(heap, pd, p);
    }
#if (defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)) && !defined(WOLFSSL_SP_NO_MALLOC)
    if (err == MP_OKAY && privm) {
        priv = (sp_digit*)XMALLOC(sizeof(sp_digit) * 6, heap,
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

        sp_384_from_mp(pub->x, 6, pX);
        sp_384_from_mp(pub->y, 6, pY);
        sp_384_from_bin(pub->z, 6, one, (int)sizeof(one));
        if (privm)
            sp_384_from_mp(priv, 6, privm);

        /* Check point at infinitiy. */
        if ((sp_384_iszero_6(pub->x) != 0) &&
            (sp_384_iszero_6(pub->y) != 0)) {
            err = ECC_INF_E;
        }
    }

    if (err == MP_OKAY) {
        /* Check range of X and Y */
        if (sp_384_cmp_6(pub->x, p384_mod) >= 0 ||
            sp_384_cmp_6(pub->y, p384_mod) >= 0) {
            err = ECC_OUT_OF_RANGE_E;
        }
    }

    if (err == MP_OKAY) {
        /* Check point is on curve */
        err = sp_384_ecc_is_point_6(pub, heap);
    }

    if (err == MP_OKAY) {
        /* Point * order = infinity */
            err = sp_384_ecc_mulmod_6(p, pub, p384_order, 1, 1, heap);
    }
    if (err == MP_OKAY) {
        /* Check result is infinity */
        if ((sp_384_iszero_6(p->x) == 0) ||
            (sp_384_iszero_6(p->y) == 0)) {
            err = ECC_INF_E;
        }
    }

    if (privm) {
        if (err == MP_OKAY) {
            /* Base * private = point */
                err = sp_384_ecc_mulmod_base_6(p, priv, 1, 1, heap);
        }
        if (err == MP_OKAY) {
            /* Check result is public key */
            if (sp_384_cmp_6(p->x, pub->x) != 0 ||
                sp_384_cmp_6(p->y, pub->y) != 0) {
                err = ECC_PRIV_KEY_E;
            }
        }
    }

#if (defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)) && !defined(WOLFSSL_SP_NO_MALLOC)
    if (priv != NULL) {
        XFREE(priv, heap, DYNAMIC_TYPE_ECC);
    }
#endif
    sp_384_point_free_6(p, 0, heap);
    sp_384_point_free_6(pub, 0, heap);

    return err;
}
#endif
#ifdef WOLFSSL_PUBLIC_ECC_ADD_DBL
/* Add two projective EC points together.
 * (pX, pY, pZ) + (qX, qY, qZ) = (rX, rY, rZ)
 *
 * pX   First EC point's X ordinate.
 * pY   First EC point's Y ordinate.
 * pZ   First EC point's Z ordinate.
 * qX   Second EC point's X ordinate.
 * qY   Second EC point's Y ordinate.
 * qZ   Second EC point's Z ordinate.
 * rX   Resultant EC point's X ordinate.
 * rY   Resultant EC point's Y ordinate.
 * rZ   Resultant EC point's Z ordinate.
 * returns MEMORY_E if dynamic memory allocation fails and MP_OKAY otherwise.
 */
int sp_ecc_proj_add_point_384(mp_int* pX, mp_int* pY, mp_int* pZ,
                              mp_int* qX, mp_int* qY, mp_int* qZ,
                              mp_int* rX, mp_int* rY, mp_int* rZ)
{
#if (!defined(WOLFSSL_SP_SMALL) && !defined(WOLFSSL_SMALL_STACK)) || defined(WOLFSSL_SP_NO_MALLOC)
    sp_digit tmpd[2 * 6 * 5];
    sp_point_384 pd;
    sp_point_384 qd;
#endif
    sp_digit* tmp = NULL;
    sp_point_384* p;
    sp_point_384* q = NULL;
    int err;

    err = sp_384_point_new_6(NULL, pd, p);
    if (err == MP_OKAY) {
        err = sp_384_point_new_6(NULL, qd, q);
    }
#if (defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)) && !defined(WOLFSSL_SP_NO_MALLOC)
    if (err == MP_OKAY) {
        tmp = (sp_digit*)XMALLOC(sizeof(sp_digit) * 2 * 6 * 5, NULL,
                                                              DYNAMIC_TYPE_ECC);
        if (tmp == NULL) {
            err = MEMORY_E;
        }
    }
#else
    tmp = tmpd;
#endif

    if (err == MP_OKAY) {
        sp_384_from_mp(p->x, 6, pX);
        sp_384_from_mp(p->y, 6, pY);
        sp_384_from_mp(p->z, 6, pZ);
        sp_384_from_mp(q->x, 6, qX);
        sp_384_from_mp(q->y, 6, qY);
        sp_384_from_mp(q->z, 6, qZ);

            sp_384_proj_point_add_6(p, p, q, tmp);
    }

    if (err == MP_OKAY) {
        err = sp_384_to_mp(p->x, rX);
    }
    if (err == MP_OKAY) {
        err = sp_384_to_mp(p->y, rY);
    }
    if (err == MP_OKAY) {
        err = sp_384_to_mp(p->z, rZ);
    }

#if (defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)) && !defined(WOLFSSL_SP_NO_MALLOC)
    if (tmp != NULL) {
        XFREE(tmp, NULL, DYNAMIC_TYPE_ECC);
    }
#endif
    sp_384_point_free_6(q, 0, NULL);
    sp_384_point_free_6(p, 0, NULL);

    return err;
}

/* Double a projective EC point.
 * (pX, pY, pZ) + (pX, pY, pZ) = (rX, rY, rZ)
 *
 * pX   EC point's X ordinate.
 * pY   EC point's Y ordinate.
 * pZ   EC point's Z ordinate.
 * rX   Resultant EC point's X ordinate.
 * rY   Resultant EC point's Y ordinate.
 * rZ   Resultant EC point's Z ordinate.
 * returns MEMORY_E if dynamic memory allocation fails and MP_OKAY otherwise.
 */
int sp_ecc_proj_dbl_point_384(mp_int* pX, mp_int* pY, mp_int* pZ,
                              mp_int* rX, mp_int* rY, mp_int* rZ)
{
#if (!defined(WOLFSSL_SP_SMALL) && !defined(WOLFSSL_SMALL_STACK)) || defined(WOLFSSL_SP_NO_MALLOC)
    sp_digit tmpd[2 * 6 * 2];
    sp_point_384 pd;
#endif
    sp_digit* tmp = NULL;
    sp_point_384* p;
    int err;

    err = sp_384_point_new_6(NULL, pd, p);
#if (defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)) && !defined(WOLFSSL_SP_NO_MALLOC)
    if (err == MP_OKAY) {
        tmp = (sp_digit*)XMALLOC(sizeof(sp_digit) * 2 * 6 * 2, NULL,
                                                              DYNAMIC_TYPE_ECC);
        if (tmp == NULL) {
            err = MEMORY_E;
        }
    }
#else
    tmp = tmpd;
#endif

    if (err == MP_OKAY) {
        sp_384_from_mp(p->x, 6, pX);
        sp_384_from_mp(p->y, 6, pY);
        sp_384_from_mp(p->z, 6, pZ);

            sp_384_proj_point_dbl_6(p, p, tmp);
    }

    if (err == MP_OKAY) {
        err = sp_384_to_mp(p->x, rX);
    }
    if (err == MP_OKAY) {
        err = sp_384_to_mp(p->y, rY);
    }
    if (err == MP_OKAY) {
        err = sp_384_to_mp(p->z, rZ);
    }

#if (defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)) && !defined(WOLFSSL_SP_NO_MALLOC)
    if (tmp != NULL) {
        XFREE(tmp, NULL, DYNAMIC_TYPE_ECC);
    }
#endif
    sp_384_point_free_6(p, 0, NULL);

    return err;
}

/* Map a projective EC point to affine in place.
 * pZ will be one.
 *
 * pX   EC point's X ordinate.
 * pY   EC point's Y ordinate.
 * pZ   EC point's Z ordinate.
 * returns MEMORY_E if dynamic memory allocation fails and MP_OKAY otherwise.
 */
int sp_ecc_map_384(mp_int* pX, mp_int* pY, mp_int* pZ)
{
#if (!defined(WOLFSSL_SP_SMALL) && !defined(WOLFSSL_SMALL_STACK)) || defined(WOLFSSL_SP_NO_MALLOC)
    sp_digit tmpd[2 * 6 * 6];
    sp_point_384 pd;
#endif
    sp_digit* tmp = NULL;
    sp_point_384* p;
    int err;

    err = sp_384_point_new_6(NULL, pd, p);
#if (defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)) && !defined(WOLFSSL_SP_NO_MALLOC)
    if (err == MP_OKAY) {
        tmp = (sp_digit*)XMALLOC(sizeof(sp_digit) * 2 * 6 * 6, NULL,
                                                              DYNAMIC_TYPE_ECC);
        if (tmp == NULL) {
            err = MEMORY_E;
        }
    }
#else
    tmp = tmpd;
#endif
    if (err == MP_OKAY) {
        sp_384_from_mp(p->x, 6, pX);
        sp_384_from_mp(p->y, 6, pY);
        sp_384_from_mp(p->z, 6, pZ);

        sp_384_map_6(p, p, tmp);
    }

    if (err == MP_OKAY) {
        err = sp_384_to_mp(p->x, pX);
    }
    if (err == MP_OKAY) {
        err = sp_384_to_mp(p->y, pY);
    }
    if (err == MP_OKAY) {
        err = sp_384_to_mp(p->z, pZ);
    }

#if (defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)) && !defined(WOLFSSL_SP_NO_MALLOC)
    if (tmp != NULL) {
        XFREE(tmp, NULL, DYNAMIC_TYPE_ECC);
    }
#endif
    sp_384_point_free_6(p, 0, NULL);

    return err;
}
#endif /* WOLFSSL_PUBLIC_ECC_ADD_DBL */
#ifdef HAVE_COMP_KEY
/* Find the square root of a number mod the prime of the curve.
 *
 * y  The number to operate on and the result.
 * returns MEMORY_E if dynamic memory allocation fails and MP_OKAY otherwise.
 */
static int sp_384_mont_sqrt_6(sp_digit* y)
{
#if (defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)) && !defined(WOLFSSL_SP_NO_MALLOC)
    sp_digit* d;
#else
    sp_digit t1d[2 * 6];
    sp_digit t2d[2 * 6];
    sp_digit t3d[2 * 6];
    sp_digit t4d[2 * 6];
    sp_digit t5d[2 * 6];
#endif
    sp_digit* t1;
    sp_digit* t2;
    sp_digit* t3;
    sp_digit* t4;
    sp_digit* t5;
    int err = MP_OKAY;

#if (defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)) && !defined(WOLFSSL_SP_NO_MALLOC)
    d = (sp_digit*)XMALLOC(sizeof(sp_digit) * 5 * 2 * 6, NULL, DYNAMIC_TYPE_ECC);
    if (d == NULL) {
        err = MEMORY_E;
    }
#endif

    if (err == MP_OKAY) {
#if (defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)) && !defined(WOLFSSL_SP_NO_MALLOC)
        t1 = d + 0 * 6;
        t2 = d + 2 * 6;
        t3 = d + 4 * 6;
        t4 = d + 6 * 6;
        t5 = d + 8 * 6;
#else
        t1 = t1d;
        t2 = t2d;
        t3 = t3d;
        t4 = t4d;
        t5 = t5d;
#endif

        {
            /* t2 = y ^ 0x2 */
            sp_384_mont_sqr_6(t2, y, p384_mod, p384_mp_mod);
            /* t1 = y ^ 0x3 */
            sp_384_mont_mul_6(t1, t2, y, p384_mod, p384_mp_mod);
            /* t5 = y ^ 0xc */
            sp_384_mont_sqr_n_6(t5, t1, 2, p384_mod, p384_mp_mod);
            /* t1 = y ^ 0xf */
            sp_384_mont_mul_6(t1, t1, t5, p384_mod, p384_mp_mod);
            /* t2 = y ^ 0x1e */
            sp_384_mont_sqr_6(t2, t1, p384_mod, p384_mp_mod);
            /* t3 = y ^ 0x1f */
            sp_384_mont_mul_6(t3, t2, y, p384_mod, p384_mp_mod);
            /* t2 = y ^ 0x3e0 */
            sp_384_mont_sqr_n_6(t2, t3, 5, p384_mod, p384_mp_mod);
            /* t1 = y ^ 0x3ff */
            sp_384_mont_mul_6(t1, t3, t2, p384_mod, p384_mp_mod);
            /* t2 = y ^ 0x7fe0 */
            sp_384_mont_sqr_n_6(t2, t1, 5, p384_mod, p384_mp_mod);
            /* t3 = y ^ 0x7fff */
            sp_384_mont_mul_6(t3, t3, t2, p384_mod, p384_mp_mod);
            /* t2 = y ^ 0x3fff800 */
            sp_384_mont_sqr_n_6(t2, t3, 15, p384_mod, p384_mp_mod);
            /* t4 = y ^ 0x3ffffff */
            sp_384_mont_mul_6(t4, t3, t2, p384_mod, p384_mp_mod);
            /* t2 = y ^ 0xffffffc000000 */
            sp_384_mont_sqr_n_6(t2, t4, 30, p384_mod, p384_mp_mod);
            /* t1 = y ^ 0xfffffffffffff */
            sp_384_mont_mul_6(t1, t4, t2, p384_mod, p384_mp_mod);
            /* t2 = y ^ 0xfffffffffffffff000000000000000 */
            sp_384_mont_sqr_n_6(t2, t1, 60, p384_mod, p384_mp_mod);
            /* t1 = y ^ 0xffffffffffffffffffffffffffffff */
            sp_384_mont_mul_6(t1, t1, t2, p384_mod, p384_mp_mod);
            /* t2 = y ^ 0xffffffffffffffffffffffffffffff000000000000000000000000000000 */
            sp_384_mont_sqr_n_6(t2, t1, 120, p384_mod, p384_mp_mod);
            /* t1 = y ^ 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff */
            sp_384_mont_mul_6(t1, t1, t2, p384_mod, p384_mp_mod);
            /* t2 = y ^ 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff8000 */
            sp_384_mont_sqr_n_6(t2, t1, 15, p384_mod, p384_mp_mod);
            /* t1 = y ^ 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff */
            sp_384_mont_mul_6(t1, t3, t2, p384_mod, p384_mp_mod);
            /* t2 = y ^ 0x3fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff80000000 */
            sp_384_mont_sqr_n_6(t2, t1, 31, p384_mod, p384_mp_mod);
            /* t1 = y ^ 0x3fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffbfffffff */
            sp_384_mont_mul_6(t1, t4, t2, p384_mod, p384_mp_mod);
            /* t2 = y ^ 0x3fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffbfffffff0 */
            sp_384_mont_sqr_n_6(t2, t1, 4, p384_mod, p384_mp_mod);
            /* t1 = y ^ 0x3fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffbfffffffc */
            sp_384_mont_mul_6(t1, t5, t2, p384_mod, p384_mp_mod);
            /* t2 = y ^ 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000 */
            sp_384_mont_sqr_n_6(t2, t1, 62, p384_mod, p384_mp_mod);
            /* t1 = y ^ 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000001 */
            sp_384_mont_mul_6(t1, y, t2, p384_mod, p384_mp_mod);
            /* t2 = y ^ 0x3fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffbfffffffc00000000000000040000000 */
            sp_384_mont_sqr_n_6(y, t1, 30, p384_mod, p384_mp_mod);
        }
    }

#if (defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)) && !defined(WOLFSSL_SP_NO_MALLOC)
    if (d != NULL) {
        XFREE(d, NULL, DYNAMIC_TYPE_ECC);
    }
#endif

    return err;
}


/* Uncompress the point given the X ordinate.
 *
 * xm    X ordinate.
 * odd   Whether the Y ordinate is odd.
 * ym    Calculated Y ordinate.
 * returns MEMORY_E if dynamic memory allocation fails and MP_OKAY otherwise.
 */
int sp_ecc_uncompress_384(mp_int* xm, int odd, mp_int* ym)
{
#if (defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)) && !defined(WOLFSSL_SP_NO_MALLOC)
    sp_digit* d;
#else
    sp_digit xd[2 * 6];
    sp_digit yd[2 * 6];
#endif
    sp_digit* x = NULL;
    sp_digit* y = NULL;
    int err = MP_OKAY;

#if (defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)) && !defined(WOLFSSL_SP_NO_MALLOC)
    d = (sp_digit*)XMALLOC(sizeof(sp_digit) * 4 * 6, NULL, DYNAMIC_TYPE_ECC);
    if (d == NULL) {
        err = MEMORY_E;
    }
#endif

    if (err == MP_OKAY) {
#if (defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)) && !defined(WOLFSSL_SP_NO_MALLOC)
        x = d + 0 * 6;
        y = d + 2 * 6;
#else
        x = xd;
        y = yd;
#endif

        sp_384_from_mp(x, 6, xm);
        err = sp_384_mod_mul_norm_6(x, x, p384_mod);
    }
    if (err == MP_OKAY) {
        /* y = x^3 */
        {
            sp_384_mont_sqr_6(y, x, p384_mod, p384_mp_mod);
            sp_384_mont_mul_6(y, y, x, p384_mod, p384_mp_mod);
        }
        /* y = x^3 - 3x */
        sp_384_mont_sub_6(y, y, x, p384_mod);
        sp_384_mont_sub_6(y, y, x, p384_mod);
        sp_384_mont_sub_6(y, y, x, p384_mod);
        /* y = x^3 - 3x + b */
        err = sp_384_mod_mul_norm_6(x, p384_b, p384_mod);
    }
    if (err == MP_OKAY) {
        sp_384_mont_add_6(y, y, x, p384_mod);
        /* y = sqrt(x^3 - 3x + b) */
        err = sp_384_mont_sqrt_6(y);
    }
    if (err == MP_OKAY) {
        XMEMSET(y + 6, 0, 6U * sizeof(sp_digit));
        sp_384_mont_reduce_6(y, p384_mod, p384_mp_mod);
        if ((((word32)y[0] ^ (word32)odd) & 1U) != 0U) {
            sp_384_mont_sub_6(y, p384_mod, y, p384_mod);
        }

        err = sp_384_to_mp(y, ym);
    }

#if (defined(WOLFSSL_SP_SMALL) || defined(WOLFSSL_SMALL_STACK)) && !defined(WOLFSSL_SP_NO_MALLOC)
    if (d != NULL) {
        XFREE(d, NULL, DYNAMIC_TYPE_ECC);
    }
#endif

    return err;
}
#endif
#endif /* WOLFSSL_SP_384 */
#endif /* WOLFSSL_HAVE_SP_ECC */
#endif /* WOLFSSL_SP_ARM64_ASM */
#endif /* WOLFSSL_HAVE_SP_RSA || WOLFSSL_HAVE_SP_DH || WOLFSSL_HAVE_SP_ECC */
