/* sp_int.c
 *
 * Copyright (C) 2006-2021 wolfSSL Inc.
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

/*
DESCRIPTION
This library provides single precision (SP) integer math functions.

*/
#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

/* SP Build Options:
 * WOLFSSL_HAVE_SP_ECC:         Enable SP ECC support
 * WOLFSSL_SP_MATH:             Use only single precision math and algorithms
 *      it supports (no fastmath tfm.c or normal integer.c)
 * WOLFSSL_SP_MATH_ALL          Implementation of all MP functions
 *      (replacement for tfm.c and integer.c)
 * WOLFSSL_SP_SMALL:            Use smaller version of code and avoid large
 *      stack variables
 * WOLFSSL_SP_NO_256            Disable ECC 256-bit SECP256R1 support
 * WOLFSSL_SP_384               Enable ECC 384-bit SECP384R1 support
 * WOLFSSL_SP_ARM64_ASM         Enable Aarch64 assembly implementation
 * SP_WORD_SIZE                 Force 32 or 64 bit mode
 */

#if defined(WOLFSSL_SP_MATH) || defined(WOLFSSL_SP_MATH_ALL)

#include <wolfssl/wolfcrypt/sp_int.h>


/* Initialize the multi-precision number to be zero.
 *
 * @param  [out]  a  SP integer.
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when a is NULL.
 */
int sp_init(sp_int* a)
{
    int err = MP_OKAY;

    if (a == NULL) {
        err = MP_VAL;
    }
    if (err == MP_OKAY) {
        a->used = 0;
        a->size = SP_INT_DIGITS;
    #ifdef WOLFSSL_SP_INT_NEGATIVE
        a->sign = MP_ZPOS;
    #endif
    }

    return err;
}

int sp_init_size(sp_int* a, int size)
{
    int err = sp_init(a);

    if (err == MP_OKAY) {
        a->size = size;
    }

    return err;
}

#if !defined(WOLFSSL_RSA_PUBLIC_ONLY) || !defined(NO_DH) || defined(HAVE_ECC)
/* Initialize up to six multi-precision numbers to be zero.
 *
 * @param  [out]  n1  SP integer.
 * @param  [out]  n2  SP integer.
 * @param  [out]  n3  SP integer.
 * @param  [out]  n4  SP integer.
 * @param  [out]  n5  SP integer.
 * @param  [out]  n6  SP integer.
 *
 * @return  MP_OKAY on success.
 */
int sp_init_multi(sp_int* n1, sp_int* n2, sp_int* n3, sp_int* n4, sp_int* n5,
                  sp_int* n6)
{
    if (n1 != NULL) {
        n1->used = 0;
        n1->size = SP_INT_DIGITS;
#ifdef WOLFSSL_SP_INT_NEGATIVE
        n1->sign = MP_ZPOS;
#endif
    }
    if (n2 != NULL) {
        n2->used = 0;
        n2->size = SP_INT_DIGITS;
#ifdef WOLFSSL_SP_INT_NEGATIVE
        n2->sign = MP_ZPOS;
#endif
    }
    if (n3 != NULL) {
        n3->used = 0;
        n3->size = SP_INT_DIGITS;
#ifdef WOLFSSL_SP_INT_NEGATIVE
        n3->sign = MP_ZPOS;
#endif
    }
    if (n4 != NULL) {
        n4->used = 0;
        n4->size = SP_INT_DIGITS;
#ifdef WOLFSSL_SP_INT_NEGATIVE
        n4->sign = MP_ZPOS;
#endif
    }
    if (n5 != NULL) {
        n5->used = 0;
        n5->size = SP_INT_DIGITS;
#ifdef WOLFSSL_SP_INT_NEGATIVE
        n5->sign = MP_ZPOS;
#endif
    }
    if (n6 != NULL) {
        n6->used = 0;
        n6->size = SP_INT_DIGITS;
#ifdef WOLFSSL_SP_INT_NEGATIVE
        n6->sign = MP_ZPOS;
#endif
    }

    return MP_OKAY;
}
#endif /* !WOLFSSL_RSA_PUBLIC_ONLY || !NO_DH || HAVE_ECC */

/* Free the memory allocated in the multi-precision number.
 *
 * @param  [in]  a  SP integer.
 */
void sp_free(sp_int* a)
{
	(void)a;
	return;
}

#if !defined(WOLFSSL_RSA_VERIFY_ONLY) || !defined(NO_DH) || defined(HAVE_ECC)
/* Grow multi-precision number to be able to hold l digits.
 * This function does nothing as the number of digits is fixed.
 *
 * @param  [in,out]  a  SP integer.
 * @param  [in]      l  Number of digits to grow to.
 *
 * @return  MP_OKAY on success
 * @return  MP_MEM if the number of digits requested is more than available.
 */
int sp_grow(sp_int* a, int l)
{
    int err = MP_OKAY;

    if (a == NULL) {
        err = MP_VAL;
    }
    if ((err == MP_OKAY) && (l > a->size)) {
        err = MP_MEM;
    }
    if (err == MP_OKAY) {
        int i;

        for (i = a->used; i < l; i++) {
            a->dp[i] = 0;
        }
    }

    return err;
}
#endif /* !WOLFSSL_RSA_VERIFY_ONLY || !NO_DH || HAVE_ECC */

/* Set the multi-precision number to zero.
 *
 * Assumes a is not NULL.
 *
 * @param  [out]  a  SP integer to set to zero.
 */
static void _sp_zero(sp_int* a)
{
    a->dp[0] = 0;
    a->used = 0;
#ifdef WOLFSSL_SP_INT_NEGATIVE
    a->sign = MP_ZPOS;
#endif
}

#if !defined(WOLFSSL_RSA_VERIFY_ONLY)
/* Set the multi-precision number to zero.
 *
 * @param  [out]  a  SP integer to set to zero.
 */
void sp_zero(sp_int* a)
{
    if (a != NULL) {
        _sp_zero(a);
    }
}
#endif /* !WOLFSSL_RSA_VERIFY_ONLY */

/* Clear the data from the multi-precision number and set to zero.
 *
 * @param  [out]  a  SP integer.
 */
void sp_clear(sp_int* a)
{
    if (a != NULL) {
        int i;

        for (i = 0; i < a->used; i++) {
            a->dp[i] = 0;
        }
        a->used = 0;
    #ifdef WOLFSSL_SP_INT_NEGATIVE
        a->sign = MP_ZPOS;
    #endif
    }
}

#if !defined(WOLFSSL_RSA_PUBLIC_ONLY) || !defined(NO_DH) || defined(HAVE_ECC)
/* Ensure the data in the multi-precision number is zeroed.
 *
 * Use when security sensitive data needs to be wiped.
 *
 * @param  [in]  a  SP integer.
 */
void sp_forcezero(sp_int* a)
{
    ForceZero(a->dp, a->used * sizeof(sp_int_digit));
    a->used = 0;
#ifdef WOLFSSL_SP_INT_NEGATIVE
    a->sign = MP_ZPOS;
#endif
}
#endif /* !WOLFSSL_RSA_VERIFY_ONLY || !NO_DH || HAVE_ECC */

#if defined(WOLSSL_SP_MATH_ALL) || !defined(NO_DH) || defined(HAVE_ECC) || \
    !defined(NO_RSA) || defined(WOLFSSL_KEY_GEN) || defined(HAVE_COMP_KEY)
/* Copy value of multi-precision number a into r.
 *
 * @param  [in]   a  SP integer - source.
 * @param  [out]  r  SP integer - destination.
 *
 * @return  MP_OKAY on success.
 */
int sp_copy(sp_int* a, sp_int* r)
{
    int err = MP_OKAY;

    if ((a == NULL) || (r == NULL)) {
        err = MP_VAL;
    }
    else if (a != r) {
        XMEMCPY(r->dp, a->dp, a->used * sizeof(sp_int_digit));
        if (a->used == 0)
            r->dp[0] = 0;
        r->used = a->used;
#ifdef WOLFSSL_SP_INT_NEGATIVE
        r->sign = a->sign;
#endif
    }

    return err;
}
#endif

#if defined(HAVE_ECC) && defined(ECC_TIMING_RESISTANT) && \
    !defined(WC_NO_CACHE_RESISTANT)
int sp_cond_swap_ct(sp_int * a, sp_int * b, int c, int m)
{
    int i;
    sp_digit mask = (sp_digit)0 - m;
#ifndef WOLFSSL_SMALL_STACK
    sp_int  t[1];
#else
    sp_int* t;
#endif

    t->used = (int)((a->used ^ b->used) & mask);
    for (i = 0; i < c; i++) {
        t->dp[i] = (a->dp[i] ^ b->dp[i]) & mask;
    }
    a->used ^= t->used;
    for (i = 0; i < c; i++) {
        a->dp[i] ^= t->dp[i];
    }
    b->used ^= t->used;
    for (i = 0; i < c; i++) {
        b->dp[i] ^= t->dp[i];
    }

    return MP_OKAY;
}
#endif /* HAVE_ECC && ECC_TIMING_RESISTANT && !WC_NO_CACHE_RESISTANT */

#ifdef WOLFSSL_SP_INT_NEGATIVE
/* Calculate the absolute value of the multi-precision number.
 *
 * @param  [in]   a  SP integer to calculate absolute value of.
 * @param  [out]  r  SP integer to hold result.
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when a or r is NULL.
 */
int sp_abs(sp_int* a, sp_int* r)
{
    int err;

    err = sp_copy(a, r);
    if (r != NULL) {
        r->sign = MP_ZPOS;
    }

    return err;
}
#endif /* WOLFSSL_SP_INT_NEGATIVE */

/* Compare absolute value of two multi-precision numbers.
 *
 * @param  [in]  a  SP integer.
 * @param  [in]  b  SP integer.
 *
 * @return  MP_GT when a is greater than b.
 * @return  MP_LT when a is less than b.
 * @return  MP_EQ when a is equals b.
 */
static int _sp_cmp_abs(sp_int* a, sp_int* b)
{
    int ret = MP_EQ;

    if (a->used > b->used) {
        ret = MP_GT;
    }
    else if (a->used < b->used) {
        ret = MP_LT;
    }
    else {
        int i;

        for (i = a->used - 1; i >= 0; i--) {
            if (a->dp[i] > b->dp[i]) {
                ret = MP_GT;
                break;
            }
            else if (a->dp[i] < b->dp[i]) {
                ret = MP_LT;
                break;
            }
        }
    }

    return ret;
}

/* Compare two multi-precision numbers.
 *
 * Assumes a and b are not NULL.
 *
 * @param  [in]  a  SP integer.
 * @param  [in]  a  SP integer.
 *
 * @return  MP_GT when a is greater than b.
 * @return  MP_LT when a is less than b.
 * @return  MP_EQ when a is equals b.
 */
static int _sp_cmp(sp_int* a, sp_int* b)
{
    int ret;

#ifdef WOLFSSL_SP_INT_NEGATIVE
    if (a->sign == b->sign) {
#endif
        ret = _sp_cmp_abs(a, b);
#ifdef WOLFSSL_SP_INT_NEGATIVE
    }
    else if (a->sign > b->sign) {
        ret = MP_LT;
    }
    else /* (a->sign < b->sign) */ {
        ret = MP_GT;
    }
#endif

    return ret;
}


/* Compare two multi-precision numbers.
 *
 * Pointers are compared such that NULL is less than not NULL.
 *
 * @param  [in]  a  SP integer.
 * @param  [in]  a  SP integer.
 *
 * @return  MP_GT when a is greater than b.
 * @return  MP_LT when a is less than b.
 * @return  MP_EQ when a is equals b.
 */
int sp_cmp(sp_int* a, sp_int* b)
{
    int ret;

    if (a == b) {
        ret = MP_EQ;
    }
    else if (a == NULL) {
        ret = MP_LT;
    }
    else if (b == NULL) {
        ret = MP_GT;
    }
    else
    {
        ret = _sp_cmp(a, b);
    }

    return ret;
}

/* Count the number of bits in the multi-precision number.
 *
 * When a is not NULL, result is 0.
 *
 * @param  [in]  a  SP integer.
 *
 * @return  The number of bits in the number.
 */
int sp_count_bits(sp_int* a)
{
    int r = 0;

    if (a != NULL) {
        r = a->used - 1;
        while ((r >= 0) && (a->dp[r] == 0)) {
            r--;
        }
        if (r < 0) {
            r = 0;
        }
        else {
            sp_int_digit d;

            d = a->dp[r];
            r *= SP_WORD_SIZE;
            if (d > SP_HALF_MAX) {
                r += SP_WORD_SIZE;
                while ((d & (1UL << (SP_WORD_SIZE - 1))) == 0) {
                    r--;
                    d <<= 1;
                }
            }
            else {
                while (d != 0) {
                    r++;
                    d >>= 1;
                }
            }
        }
    }

    return r;
}

#if !defined(WOLFSSL_RSA_VERIFY_ONLY)
/* Determine if the most significant byte of the encoded multi-precision number
 * has the top bit set.
 *
 * When A is NULL, result is 0.
 *
 * @param  [in]  a  SP integer.
 *
 * @return  1 when the top bit of top byte is set.
 * @return  0 when the top bit of top byte is not set.
 */
int sp_leading_bit(sp_int* a)
{
    int bit = 0;

    if ((a != NULL) && (a->used > 0)) {
        sp_int_digit d = a->dp[a->used - 1];
    #if SP_WORD_SIZE > 8
        while (d > (sp_int_digit)0xff) {
            d >>= 8;
        }
    #endif
        bit = (int)(d >> 7);
    }

    return bit;
}
#endif /* !WOLFSSL_RSA_VERIFY_ONLY */

#if defined(WOLFSSL_SP_MATH_ALL) || defined(WOLFSSL_HAVE_SP_DH) || \
    defined(HAVE_ECC) || defined(WOLFSSL_KEY_GEN) || defined(OPENSSL_EXTRA) || \
    !defined(NO_RSA)
/* Set a bit of a: a |= 1 << i
 * The field 'used' is updated in a.
 *
 * @param  [in,out]  a  SP integer to set bit into.
 * @param  [in]      i  Index of bit to set.
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when a is NULL or index is too large.
 */
int sp_set_bit(sp_int* a, int i)
{
    int err = MP_OKAY;
    int w = (int)(i >> SP_WORD_SHIFT);

    if ((a == NULL) || (w >= a->size)) {
        err = MP_VAL;
    }
    else {
        int s = (int)(i & (SP_WORD_SIZE - 1));
        int j;

        for (j = a->used; j <= w; j++) {
            a->dp[j] = 0;
        }
        a->dp[w] |= (sp_int_digit)1 << s;
        if (a->used <= w) {
            a->used = w + 1;
        }
    }
    return err;
}
#endif /* WOLFSSL_SP_MATH_ALL || WOLFSSL_HAVE_SP_DH || HAVE_ECC ||
        * WOLFSSL_KEY_GEN || OPENSSL_EXTRA || !NO_RSA */

/**********************
 * Digit/Long functions
 **********************/

#if !defined(WOLFSSL_RSA_VERIFY_ONLY)
/* Set the multi-precision number to be the value of the digit.
 *
 * @param  [out]  a  SP integer to become number.
 * @param  [in]   d  Digit to be set.
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when a is NULL.
 */
int sp_set(sp_int* a, sp_int_digit d)
{
    int err = MP_OKAY;

    if (a == NULL) {
        err = MP_VAL;
    }
    if (err == MP_OKAY) {
        a->dp[0] = d;
        a->used = d > 0;
    #ifdef WOLFSSL_SP_INT_NEGATIVE
        a->sign = MP_ZPOS;
    #endif
    }

    return err;
}
#endif /* WOLFSSL_RSA_VERIFY_ONLY */

/* Compare a one digit number with a multi-precision number.
 *
 * When a is NULL, MP_LT is returned.
 *
 * @param  [in]  a  SP integer to compare.
 * @param  [in]  d  Digit to compare with.
 *
 * @return  MP_GT when a is greater than d.
 * @return  MP_LT when a is less than d.
 * @return  MP_EQ when a is equals d.
 */
int sp_cmp_d(sp_int* a, sp_int_digit d)
{
    int ret = MP_EQ;

    if (a == NULL) {
        ret = MP_LT;
    }
    else
#ifdef WOLFSSL_SP_INT_NEGATIVE
    if (a->sign == MP_NEG) {
        ret = MP_LT;
    }
    else
#endif
    {
        /* special case for zero*/
        if (a->used == 0) {
            if (d == 0) {
                ret = MP_EQ;
            }
            else {
                ret = MP_LT;
            }
        }
        else if (a->used > 1) {
            ret = MP_GT;
        }
        else {
            if (a->dp[0] > d) {
                ret = MP_GT;
            }
            else if (a->dp[0] < d) {
                ret = MP_LT;
            }
        }
    }

    return ret;
}


#if defined(WOLFSSL_SP_MATH_ALL) || defined(WOLFSSL_SP_INT_NEGATIVE) || \
    !defined(NO_DH) || !defined(NO_DSA) || defined(HAVE_ECC) || \
    (!defined(NO_RSA) && !defined(WOLFSSL_RSA_VERIFY_ONLY))
/* Sub a one digit number from the multi-precision number.
 *
 * returns MP_OKAY always.
 * @param  [in]   a  SP integer be subtracted from.
 * @param  [in]   d  Digit to subtract.
 * @param  [out]  r  SP integer to store result in.
 */
static void _sp_sub_d(sp_int* a, sp_int_digit d, sp_int* r)
{
    int i = 0;
    sp_int_digit t;

    r->used = a->used;
    if (a->used == 0) {
        r->dp[0] = 0;
    }
    else {
        t = a->dp[0] - d;
        if (t > a->dp[0]) {
            for (++i; i < a->used; i++) {
                r->dp[i] = a->dp[i] - 1;
                if (r->dp[i] != SP_DIGIT_MAX) {
                   break;
                }
            }
        }
        r->dp[0] = t;
        if (r != a) {
            for (++i; i < a->used; i++) {
                r->dp[i] = a->dp[i];
            }
        }
        sp_clamp(r);
    }
}
#endif /* WOLFSSL_SP_MATH_ALL || WOLFSSL_SP_INT_NEGATIVE || !NO_DH || !NO_DSA ||
        * HAVE_ECC || (!NO_RSA && !WOLFSSL_RSA_VERIFY_ONLY) */

#if (!defined(NO_RSA) && !defined(WOLFSSL_RSA_VERIFY_ONLY)) || \
    !defined(NO_DH) || defined(HAVE_ECC) || !defined(NO_DSA)
/* Sub a one digit number from the multi-precision number.
 *
 * @param  [in]   a  SP integer be subtracted from.
 * @param  [in]   d  Digit to subtract.
 * @param  [out]  r  SP integer to store result in.
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when a or r is NULL.
 */
int sp_sub_d(sp_int* a, sp_int_digit d, sp_int* r)
{
    int err = MP_OKAY;

    if ((a == NULL) || (r == NULL)) {
        err = MP_VAL;
    }
    else {
    #ifndef WOLFSSL_SP_INT_NEGATIVE
        _sp_sub_d(a, d, r);
    #else
        if (a->sign == MP_NEG) {
            r->sign = MP_NEG;
            err = _sp_add_d(a, d, r);
        }
        else if ((a->used > 1) || (a->dp[0] >= d)) {
            r->sign = MP_ZPOS;
            _sp_sub_d(a, d, r);
        }
        else {
            r->sign = MP_NEG;
            r->dp[0] = d - a->dp[0];
            r->used = r->dp[0] > 0;
        }
    #endif
    }

    return err;
}
#endif /* (!NO_RSA && !WOLFSSL_RSA_VERIFY_ONLY) || !NO_DH || HAVE_ECC ||
        * !NO_DSA */
#if (defined(WOLFSSL_SP_MATH_ALL) && !defined(WOLFSSL_RSA_VERIFY_ONLY)) || \
    defined(WOLFSSL_SP_SMALL) && (defined(WOLFSSL_SP_MATH_ALL) || \
    !defined(NO_DH) || defined(HAVE_ECC) || \
    (!defined(NO_RSA) && !defined(WOLFSSL_RSA_VERIFY_ONLY) && \
     !defined(WOLFSSL_RSA_PUBLIC_ONLY))) || \
    (defined(WOLFSSL_KEY_GEN) && !defined(NO_RSA))
/* Multiply a by digit n and put result into r shifting up o digits.
 *   r = (a * n) << (o * SP_WORD_SIZE)
 *
 * @param  [in]   a  SP integer to be multiplied.
 * @param  [in]   n  Number (SP digit) to multiply by.
 * @param  [out]  r  SP integer result.
 * @param  [in]   o  Number of digits to move result up by.
 */
static void _sp_mul_d(sp_int* a, sp_int_digit n, sp_int* r, int o)
{
    int i;
    sp_int_word t = 0;

#ifdef WOLFSSL_SP_SMALL
    for (i = 0; i < o; i++) {
        r->dp[i] = 0;
    }
#else
    /* Don't use the offset. Only when doing small code size div. */
    (void)o;
#endif

    for (i = 0; i < a->used; i++, o++) {
        t += (sp_int_word)a->dp[i] * n;
        r->dp[o] = (sp_int_digit)t;
        t >>= SP_WORD_SIZE;
    }

    r->dp[o++] = (sp_int_digit)t;
    r->used = o;
    sp_clamp(r);
}
#endif /* (WOLFSSL_SP_MATH_ALL && !WOLFSSL_RSA_VERIFY_ONLY) ||
        *  WOLFSSL_SP_SMALL || (WOLFSSL_KEY_GEN && !NO_RSA) */

#if defined(WOLFSSL_SP_MATH_ALL) || !defined(NO_DH) || defined(HAVE_ECC) || \
    (!defined(NO_RSA) && !defined(WOLFSSL_RSA_VERIFY_ONLY))
#ifndef SP_ASM_DIV_WORD
/* Divide a two digit number by a digit number and return. (hi | lo) / d
 *
 * @param  [in]  hi  SP integer digit. High digit of the dividend.
 * @param  [in]  lo  SP integer digit. Lower digit of the dividend.
 * @param  [in]  d   SP integer digit. Number to divide by.
 * @reutrn  The division result.
 */
static WC_INLINE sp_int_digit sp_div_word(sp_int_digit hi, sp_int_digit lo,
                                          sp_int_digit d)
{
#ifdef WOLFSSL_SP_DIV_WORD_HALF
    sp_int_digit r;

    if (hi != 0) {
        sp_int_digit div = d >> SP_HALF_SIZE;
        sp_int_digit r2;
        sp_int_word w = ((sp_int_word)hi << SP_WORD_SIZE) | lo;
        sp_int_word trial;

        r = hi / div;
        if (r > SP_HALF_MAX) {
            r = SP_HALF_MAX;
        }
        r <<= SP_HALF_SIZE;
        trial = r * (sp_int_word)d;
        while (trial > w) {
            r -= (sp_int_digit)1 << SP_HALF_SIZE;
            trial -= (sp_int_word)d << SP_HALF_SIZE;
        }
        w -= trial;
        r2 = ((sp_int_digit)(w >> SP_HALF_SIZE)) / div;
        trial = r2 * (sp_int_word)d;
        while (trial > w) {
            r2--;
            trial -= d;
        }
        w -= trial;
        r += r2;
        r2 = ((sp_int_digit)w) / d;
        r += r2;
    }
    else {
        r = lo / d;
    }

    return r;
#else
    sp_int_word w;
    sp_int_digit r;

    w = ((sp_int_word)hi << SP_WORD_SIZE) | lo;
    w /= d;
    r = (sp_int_digit)w;

    return r;
#endif /* WOLFSSL_SP_DIV_WORD_HALF */
}
#endif /* !SP_ASM_DIV_WORD */
#endif /* WOLFSSL_SP_MATH_ALL || !NO_DH || HAVE_ECC ||
        * (!NO_RSA && !WOLFSSL_RSA_VERIFY_ONLY) */

#if defined(HAVE_ECC) || !defined(NO_DSA) || defined(OPENSSL_EXTRA) || \
    (!defined(NO_RSA) && !defined(WOLFSSL_RSA_VERIFY_ONLY))
/* Divides a by 2 and stores in r: r = a >> 1
 *
 * @param  [in]   a  SP integer to divide.
 * @param  [out]  r  SP integer to hold result.
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when a or r is NULL.
 */
#if !(defined(WOLFSSL_SP_MATH_ALL) && defined(HAVE_ECC))
static
#endif
int sp_div_2(sp_int* a, sp_int* r)
{
    int err = MP_OKAY;

    if (err == MP_OKAY) {
        int i;

        r->used = a->used;
        for (i = 0; i < a->used - 1; i++) {
            r->dp[i] = (a->dp[i] >> 1) | (a->dp[i+1] << (SP_WORD_SIZE - 1));
        }
        r->dp[i] = a->dp[i] >> 1;
        r->used = i + 1;
        sp_clamp(r);
    #ifdef WOLFSSL_SP_INT_NEGATIVE
        r->sign = a->sign;
    #endif
    }

    return err;
}
#endif /* HAVE_ECC || !NO_DSA || OPENSSL_EXTRA ||
        * (!NO_RSA && !WOLFSSL_RSA_VERIFY_ONLY) */

/************************
 * Add/Subtract Functions
 ************************/

#if !defined(WOLFSSL_RSA_VERIFY_ONLY)
/* Add offset b to a into r: r = a + (b << (o * SP_WORD_SIZEOF))
 *
 * @param  [in]   a  SP integer to add to.
 * @param  [in]   b  SP integer to add.
 * @param  [out]  r  SP integer to store result in.
 * @param  [in]   o  Number of digits to offset b.
 *
 * @return  MP_OKAY on success.
 */
static int _sp_add_off(sp_int* a, sp_int* b, sp_int* r, int o)
{
    int i;
    int j;
    sp_int_word t = 0;

    if (0) {
        sp_print(a, "a");
        sp_print(b, "b");
    }

#ifdef SP_MATH_NEED_ADD_OFF
    for (i = 0; (i < o) && (i < a->used); i++) {
        r->dp[i] = a->dp[i];
    }
    for (; i < o; i++) {
        r->dp[i] = 0;
    }
#else
    i = 0;
    (void)o;
#endif

    for (j = 0; (i < a->used) && (j < b->used); i++, j++) {
        t += a->dp[i];
        t += b->dp[j];
        r->dp[i] = (sp_int_digit)t;
        t >>= SP_WORD_SIZE;
    }
    for (; i < a->used; i++) {
        t += a->dp[i];
        r->dp[i] = (sp_int_digit)t;
        t >>= SP_WORD_SIZE;
    }
    for (; j < b->used; i++, j++) {
        t += b->dp[j];
        r->dp[i] = (sp_int_digit)t;
        t >>= SP_WORD_SIZE;
    }
    r->used = i;
    if (t != 0) {
       r->dp[i] = (sp_int_digit)t;
       r->used++;
    }

    sp_clamp(r);

    if (0) {
        sp_print(r, "radd");
    }

    return MP_OKAY;
}
#endif /* !WOLFSSL_RSA_VERIFY_ONLY */

#if defined(WOLFSSL_SP_MATH_ALL) || defined(WOLFSSL_SP_INT_NEGATIVE) || \
    !defined(NO_DH) || defined(HAVE_ECC) || (!defined(NO_RSA) && \
    !defined(WOLFSSL_RSA_VERIFY_ONLY))
/* Sub offset b from a into r: r = a - (b << (o * SP_WORD_SIZEOF))
 * a must be greater than b.
 *
 * @param  [in]   a  SP integer to subtract from.
 * @param  [in]   b  SP integer to subtract.
 * @param  [out]  r  SP integer to store result in.
 * @param  [in]   o  Number of digits to offset b.
 *
 * @return  MP_OKAY on success.
 */
static int _sp_sub_off(sp_int* a, sp_int* b, sp_int* r, int o)
{
    int i;
    int j;
    sp_int_sword t = 0;

    for (i = 0; (i < o) && (i < a->used); i++) {
        r->dp[i] = a->dp[i];
    }
    for (j = 0; (i < a->used) && (j < b->used); i++, j++) {
        t += a->dp[i];
        t -= b->dp[j];
        r->dp[i] = (sp_int_digit)t;
        t >>= SP_WORD_SIZE;
    }
    for (; i < a->used; i++) {
        t += a->dp[i];
        r->dp[i] = (sp_int_digit)t;
        t >>= SP_WORD_SIZE;
    }
    r->used = i;
    sp_clamp(r);

    return MP_OKAY;
}
#endif /* WOLFSSL_SP_MATH_ALL || WOLFSSL_SP_INT_NEGATIVE || !NO_DH ||
        * HAVE_ECC || (!NO_RSA && !WOLFSSL_RSA_VERIFY_ONLY) */

#if !defined(WOLFSSL_RSA_VERIFY_ONLY)
/* Add b to a into r: r = a + b
 *
 * @param  [in]   a  SP integer to add to.
 * @param  [in]   b  SP integer to add.
 * @param  [out]  r  SP integer to store result in.
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when a, b, or r is NULL.
 */
int sp_add(sp_int* a, sp_int* b, sp_int* r)
{
    int err = MP_OKAY;

    if ((a == NULL) || (b == NULL) || (r == NULL)) {
        err = MP_VAL;
    }
    else {
    #ifndef WOLFSSL_SP_INT_NEGATIVE
        err = _sp_add_off(a, b, r, 0);
    #else
        if (a->sign == b->sign) {
            r->sign = a->sign;
            err = _sp_add_off(a, b, r, 0);
        }
        else if (_sp_cmp_abs(a, b) != MP_LT) {
            r->sign = a->sign;
            err = _sp_sub_off(a, b, r, 0);
        }
        else {
            r->sign = b->sign;
            err = _sp_sub_off(b, a, r, 0);
        }
    #endif
    }

    return err;
}
#endif /* !WOLFSSL_RSA_VERIFY_ONLY */

#if defined(WOLFSSL_SP_MATH_ALL) || !defined(NO_DH) || defined(HAVE_ECC) || \
    (!defined(NO_RSA) && !defined(WOLFSSL_RSA_VERIFY_ONLY))
/* Subtract b from a into r: r = a - b
 *
 * a must be greater than b unless WOLFSSL_SP_INT_NEGATIVE is defined.
 *
 * @param  [in]   a  SP integer to subtract from.
 * @param  [in]   b  SP integer to subtract.
 * @param  [out]  r  SP integer to store result in.
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when a, b, or r is NULL.
 */
int sp_sub(sp_int* a, sp_int* b, sp_int* r)
{
    int err = MP_OKAY;

    if ((a == NULL) || (b == NULL) || (r == NULL)) {
        err = MP_VAL;
    }
    else {
    #ifndef WOLFSSL_SP_INT_NEGATIVE
        err = _sp_sub_off(a, b, r, 0);
    #else
        if (a->sign != b->sign) {
            r->sign = a->sign;
            err = _sp_add_off(a, b, r, 0);
        }
        else if (_sp_cmp_abs(a, b) != MP_LT) {
            r->sign = a->sign;
            err = _sp_sub_off(a, b, r, 0);
        }
        else {
            r->sign = 1 - a->sign;
            err = _sp_sub_off(b, a, r, 0);
        }
    #endif
    }

    return err;
}
#endif /* WOLFSSL_SP_MATH_ALL || !NO_DH || HAVE_ECC ||
        * (!NO_RSA && !WOLFSSL_RSA_VERIFY_ONLY)*/

/********************
 * Shifting functoins
 ********************/

#if !defined(NO_DH) || defined(HAVE_ECC) || defined(WC_RSA_BLINDING) || \
    !defined(WOLFSSL_RSA_VERIFY_ONLY)
/* Left shift the multi-precision number by a number of digits.
 *
 * @param  [in,out]  a  SP integer to shift.
 * @param  [in]      s  Number of digits to shift.
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when a is NULL or the result is too big to fit in an SP.
 */
int sp_lshd(sp_int* a, int s)
{
    int err = MP_OKAY;

    if (a == NULL) {
        err = MP_VAL;
    }
    if ((err == MP_OKAY) && (a->used + s > a->size)) {
        err = MP_VAL;
    }
    if (err == MP_OKAY) {
        XMEMMOVE(a->dp + s, a->dp, a->used * sizeof(sp_int_digit));
        a->used += s;
        XMEMSET(a->dp, 0, s * sizeof(sp_int_digit));
        sp_clamp(a);
    }

    return err;
}
#endif

#if defined(WOLFSSL_SP_MATH_ALL) || !defined(NO_DH) || defined(HAVE_ECC) || \
    (!defined(NO_RSA) && !defined(WOLFSSL_RSA_VERIFY_ONLY))
/* Left shift the multi-precision number by n bits.
 * Bits may be larger than the word size.
 *
 * @param  [in,out]  a  SP integer to shift.
 * @param  [in]      n  Number of bits to shift left.
 *
 * @return  MP_OKAY on success.
 */
static int sp_lshb(sp_int* a, int n)
{
    if (a->used != 0) {
        int s = n >> SP_WORD_SHIFT;
        int i;

        n &= SP_WORD_MASK;
        if (n != 0) {
            sp_int_digit v;

            v = a->dp[a->used - 1] >> (SP_WORD_SIZE - n);
            a->dp[a->used - 1 + s] = a->dp[a->used - 1] << n;
            for (i = a->used - 2; i >= 0; i--) {
                a->dp[i + 1 + s] |= a->dp[i] >> (SP_WORD_SIZE - n);
                a->dp[i     + s] = a->dp[i] << n;
            }
            if (v != 0) {
                a->dp[a->used + s] = v;
                a->used++;
            }
        }
        else if (s > 0) {
            for (i = a->used - 1; i >= 0; i--) {
                a->dp[i + s] = a->dp[i];
            }
        }
        a->used += s;
        XMEMSET(a->dp, 0, SP_WORD_SIZEOF * s);
    }

    return MP_OKAY;
}
#endif /* WOLFSSL_SP_MATH_ALL || !NO_DH || HAVE_ECC ||
        * (!NO_RSA && !WOLFSSL_RSA_VERIFY_ONLY) */

#if defined(WOLFSSL_SP_MATH_ALL) || !defined(NO_DH) || defined(HAVE_ECC) || \
    (!defined(NO_RSA) && !defined(WOLFSSL_RSA_VERIFY_ONLY))
/* Shift a right by n digits into r: r = a >> (n * SP_WORD_SIZE)
 *
 * @param  [in]   a  SP integer to shift.
 * @param  [in]   n  Number of digits to shift.
 * @param  [out]  r  SP integer to store result in.
 */
void sp_rshd(sp_int* a, int c)
{
    if (a != NULL) {
        int i;
        int j;

        if (c >= a->used) {
            a->dp[0] = 0;
            a->used = 0;
        }
        else {
            for (i = c, j = 0; i < a->used; i++, j++) {
                a->dp[j] = a->dp[i];
            }
            a->used -= c;
        }
    }
}
#endif /* WOLFSSL_SP_MATH_ALL || !NO_DH || HAVE_ECC ||
        * (!NO_RSA && !WOLFSSL_RSA_VERIFY_ONLY) */

#if defined(WOLFSSL_SP_MATH_ALL) || !defined(NO_DH) || defined(HAVE_ECC) || \
    (!defined(NO_RSA) && !defined(WOLFSSL_RSA_VERIFY_ONLY)) || \
    defined(WOLFSSL_HAVE_SP_DH)
/* Shift a right by n bits into r: r = a >> n
 *
 * @param  [in]   a  SP integer to shift.
 * @param  [in]   n  Number of bits to shift.
 * @param  [out]  r  SP integer to store result in.
 */
void sp_rshb(sp_int* a, int n, sp_int* r)
{
    int i = n >> SP_WORD_SHIFT;

    if (i >= a->used) {
        r->dp[0] = 0;
        r->used = 0;
#ifdef WOLFSSL_SP_INT_NEGATIVE
        r->sign = MP_ZPOS;
#endif
    }
    else {
        int j;

        n &= SP_WORD_SIZE - 1;
        if (n == 0) {
            for (j = 0; i < a->used; i++, j++)
                r->dp[j] = a->dp[i];
            r->used = j;
        }
        else if (n > 0) {
            for (j = 0; i < a->used-1; i++, j++)
                r->dp[j] = (a->dp[i] >> n) | (a->dp[i+1] << (SP_WORD_SIZE - n));
            r->dp[j] = a->dp[i] >> n;
            r->used = j + 1;
            sp_clamp(r);
        }
#ifdef WOLFSSL_SP_INT_NEGATIVE
        r->sign = a->sign;
#endif
    }
}
#endif /* WOLFSSL_SP_MATH_ALL || !NO_DH || HAVE_ECC ||
        * (!NO_RSA && !WOLFSSL_RSA_VERIFY_ONLY) || WOLFSSL_HAVE_SP_DH */

#if defined(WOLFSSL_SP_MATH_ALL) || !defined(NO_DH) || defined(HAVE_ECC) || \
    (!defined(NO_RSA) && !defined(WOLFSSL_RSA_VERIFY_ONLY))
/* Divide a by d and return the quotient in r and the remainder in rem.
 *   r = a / d; rem = a % d
 *
 * @param  [in]   a    SP integer to be divided.
 * @param  [in]   d    SP integer to divide by.
 * @param  [out]  r    SP integer that is the quotient.
 * @param  [out]  rem  SP integer that is the remainder.
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when a or d is NULL, r and rem are NULL, or d is 0.
 * @return  MP_MEM when dynamic memory allocation fails.
 */
#ifndef WOLFSSL_SP_MATH_ALL
static
#endif
int sp_div(sp_int* a, sp_int* d, sp_int* r, sp_int* rem)
{
    int err = MP_OKAY;
    int ret;
    int done = 0;
    int i;
    int s;
    sp_int_digit dt;
    sp_int_digit t;
    sp_int sa[1];
    sp_int sd[1];
    sp_int tr[1];
    sp_int trial[1];
#ifdef WOLFSSL_SP_SMALL
    int c;
#else
    int j, o;
    sp_int_word tw;
    sp_int_sword sw;
#endif /* WOLFSSL_SP_SMALL */
#ifdef WOLFSSL_SP_INT_NEGATIVE
    int aSign = MP_ZPOS;
    int dSign = MP_ZPOS;
#endif /* WOLFSSL_SP_INT_NEGATIVE */

    if ((a == NULL) || (d == NULL) || ((r == NULL) && (rem == NULL))) {
        err = MP_VAL;
    }
    if ((err == MP_OKAY) && sp_iszero(d)) {
        err = MP_VAL;
    }

    if (0 && (err == MP_OKAY)) {
        sp_print(a, "a");
        sp_print(d, "b");
    }

    if (err == MP_OKAY) {
    #ifdef WOLFSSL_SP_INT_NEGATIVE
        aSign = a->sign;
        dSign = d->sign;
    #endif /* WOLFSSL_SP_INT_NEGATIVE */

        ret = _sp_cmp_abs(a, d);
        if (ret == MP_LT) {
            if (rem != NULL) {
                sp_copy(a, rem);
            }
            if (r != NULL) {
                sp_set(r, 0);
            }
            done = 1;
        }
        else if (ret == MP_EQ) {
            if (rem != NULL) {
                sp_set(rem, 0);
            }
            if (r != NULL) {
                sp_set(r, 1);
            #ifdef WOLFSSL_SP_INT_NEGATIVE
                r->sign = aSign;
            #endif /* WOLFSSL_SP_INT_NEGATIVE */
            }
            done = 1;
        }
        else if (sp_count_bits(a) == sp_count_bits(d)) {
            /* a is greater than d but same bit length */
            if (rem != NULL) {
                _sp_sub_off(a, d, rem, 0);
            }
            if (r != NULL) {
                sp_set(r, 1);
            #ifdef WOLFSSL_SP_INT_NEGATIVE
                r->sign = aSign;
            #endif /* WOLFSSL_SP_INT_NEGATIVE */
            }
            done = 1;
        }
    }

    if ((!done) && (err == MP_OKAY)) {
        sp_init(sa);
        sp_init(sd);
        sp_init(tr);
        sp_init(trial);

        s = sp_count_bits(d);
        s = SP_WORD_SIZE - (s & SP_WORD_MASK);
        sp_copy(a, sa);
        if (s != SP_WORD_SIZE) {
            sp_lshb(sa, s);
            sp_copy(d, sd);
            sp_lshb(sd, s);
            d = sd;
        }
    }
    if ((!done) && (err == MP_OKAY) && (d->used > 0)) {
#ifdef WOLFSSL_SP_INT_NEGATIVE
        sa->sign = MP_ZPOS;
        sd->sign = MP_ZPOS;
#endif /* WOLFSSL_SP_INT_NEGATIVE */

        tr->used = sa->used - d->used + 1;
        sp_clear(tr);
        tr->used = sa->used - d->used + 1;
        dt = d->dp[d->used-1];

        for (i = d->used - 1; i > 0; i--) {
            if (sa->dp[sa->used - d->used + i] != d->dp[i]) {
                break;
            }
        }
        if (sa->dp[sa->used - d->used + i] >= d->dp[i]) {
            i = sa->used;
            _sp_sub_off(sa, d, sa, sa->used - d->used);
            /* Keep the same used so that 0 zeros will be put in. */
            sa->used = i;
            if (r != NULL) {
                tr->dp[sa->used - d->used] = 1;
            }
        }
        for (i = sa->used - 1; i >= d->used; i--) {
            if (sa->dp[i] == dt) {
                t = SP_DIGIT_MAX;
            }
            else {
                t = sp_div_word(sa->dp[i], sa->dp[i-1], dt);
            }

            do {
                _sp_mul_d(d, t, trial, i - d->used);
                c = _sp_cmp_abs(trial, sa);
                if (c == MP_GT) {
                    t--;
                }
            }
            while (c == MP_GT);

            _sp_sub_off(sa, trial, sa, 0);
            tr->dp[i - d->used] += t;
            if (tr->dp[i - d->used] < t) {
                tr->dp[i + 1 - d->used]++;
            }
        }
        sa->used = i + 1;

        if (rem != NULL) {
#ifdef WOLFSSL_SP_INT_NEGATIVE
            sa->sign = (sa->used == 0) ? MP_ZPOS : aSign;
#endif /* WOLFSSL_SP_INT_NEGATIVE */
            if (s != SP_WORD_SIZE) {
                sp_rshb(sa, s, sa);
            }
            sp_copy(sa, rem);
            sp_clamp(rem);
        }
        if (r != NULL) {
            sp_copy(tr, r);
            sp_clamp(r);
#ifdef WOLFSSL_SP_INT_NEGATIVE
            r->sign = (aSign == dSign) ? MP_ZPOS : MP_NEG;
#endif /* WOLFSSL_SP_INT_NEGATIVE */
        }
    }

    if (0 && (err == MP_OKAY)) {
        if (rem != NULL) {
            sp_print(rem, "rdr");
        }
        if (r != NULL) {
            sp_print(r, "rdw");
        }
    }

    return err;
}
#endif /* WOLFSSL_SP_MATH_ALL || !NO_DH || HAVE_ECC || \
        * (!NO_RSA && !WOLFSSL_RSA_VERIFY_ONLY) */

#if defined(WOLFSSL_SP_MATH_ALL) || !defined(NO_DH) || defined(HAVE_ECC) || \
    (!defined(NO_RSA) && !defined(WOLFSSL_RSA_VERIFY_ONLY))
#ifndef FREESCALE_LTC_TFM
/* Calculate the remainder of dividing a by m: r = a mod m.
 *
 * @param  [in]   a  SP integer to reduce.
 * @param  [in]   m  SP integer that is the modulus.
 * @param  [out]  r  SP integer to store result in.
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when a, m or r is NULL or m is 0.
 */
int sp_mod(sp_int* a, sp_int* m, sp_int* r)
{
    int err = MP_OKAY;
#ifdef WOLFSSL_SP_INT_NEGATIVE
        sp_int t[1];
#endif /* WOLFSSL_SP_INT_NEGATIVE */

    if ((a == NULL) || (m == NULL) || (r == NULL)) {
        err = MP_VAL;
    }

#ifndef WOLFSSL_SP_INT_NEGATIVE
    if (err == MP_OKAY) {
        err = sp_div(a, m, NULL, r);
    }
#else
    if (err == MP_OKAY) {
    }
    if (err == MP_OKAY) {
        sp_init(t);
        err = sp_div(a, m, NULL, t);
    }
    if (err == MP_OKAY) {
        if (t->sign != m->sign) {
            err = sp_add(t, m, r);
        }
        else {
            err = sp_copy(t, r);
        }
    }
#endif /* WOLFSSL_SP_INT_NEGATIVE */

    return err;
}
#endif /* !FREESCALE_LTC_TFM */
#endif /* WOLFSSL_SP_MATH_ALL || !NO_DH || HAVE_ECC || \
        * (!NO_RSA && !WOLFSSL_RSA_VERIFY_ONLY) */

/* START SP_MUL implementations. */
/* This code is generated.
 * To generate:
 *   cd scripts/sp/sp_int
 *   ./gen.sh
 * File sp_mul.c contains code.
 */

#ifdef SQR_MUL_ASM
#else
    /* Multiply a by b into r. r = a * b
     *
     * @param  [in]   a    SP integer to mulitply.
     * @param  [in]   b    SP integer to mulitply by.
     * @param  [out]  r    SP integer to hod reult.
     *
     * @return  MP_OKAY otherwise.
     * @return  MP_MEM when dynamic memory allocation fails.
     */
    static int _sp_mul(sp_int* a, sp_int* b, sp_int* r)
    {
        int err = MP_OKAY;
        int i;
        int j;
        int k;
        sp_int t[1];

        if (err == MP_OKAY) {
            sp_int_word w;
            sp_int_word l;
            sp_int_word h;

            w = (sp_int_word)a->dp[0] * b->dp[0];
            t->dp[0] = (sp_int_digit)w;
            l = (sp_int_digit)(w >> SP_WORD_SIZE);
            h = 0;
            for (k = 1; k <= (a->used - 1) + (b->used - 1); k++) {
                i = k - (b->used - 1);
                i &= ~(i >> (sizeof(i) * 8 - 1));
                j = k - i;
                for (; (i < a->used) && (j >= 0); i++, j--) {
                    w = (sp_int_word)a->dp[i] * b->dp[j];
                    l += (sp_int_digit)w;
                    h += (sp_int_digit)(w >> SP_WORD_SIZE);
                }
                t->dp[k] = (sp_int_digit)l;
                l >>= SP_WORD_SIZE;
                l += (sp_int_digit)h;
                h >>= SP_WORD_SIZE;
            }
            t->dp[k] = (sp_int_digit)l;
            t->dp[k+1] = (sp_int_digit)h;
            t->used = k + 2;

            err = sp_copy(t, r);
        }
        if (err == MP_OKAY) {
            sp_clamp(r);
        }

        return err;
    }
#endif

/* Multiply a by b and store in r: r = a * b
 *
 * @param  [in]   a  SP integer to multiply.
 * @param  [in]   b  SP integer to multiply.
 * @param  [out]  r  SP integer result.
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when a, b or is NULL; or the result will be too big for fixed
 *          data length.
 * @return  MP_MEM when dynamic memory allocation fails.
 */
int sp_mul(sp_int* a, sp_int* b, sp_int* r)
{
    int err = MP_OKAY;
#ifdef WOLFSSL_SP_INT_NEGATIVE
    int sign;
#endif

    if ((a == NULL) || (b == NULL) || (r == NULL)) {
        err = MP_VAL;
    }

    /* Need extra digit during calculation. */
    if ((err == MP_OKAY) && (a->used + b->used >= r->size)) {
        err = MP_VAL;
    }

    if (0 && (err == MP_OKAY)) {
        sp_print(a, "a");
        sp_print(b, "b");
    }

    if (err == MP_OKAY) {
    #ifdef WOLFSSL_SP_INT_NEGATIVE
        sign = a->sign ^ b->sign;
    #endif

        if ((a->used == 0) || (b->used == 0)) {
            _sp_zero(r);
        }
        else
#ifdef SQR_MUL_ASM
        if (a->used == b->used) {
            err = _sp_mul_nxn(a, b, r);
        }
        else
#endif
        {
            err = _sp_mul(a, b, r);
        }
    }

#ifdef WOLFSSL_SP_INT_NEGATIVE
    if (err == MP_OKAY) {
        r->sign = (r->used == 0) ? MP_ZPOS : sign;
    }
#endif

    if (0 && (err == MP_OKAY)) {
        sp_print(r, "rmul");
    }

    return err;
}
/* END SP_MUL implementations. */

#if !defined(WOLFSSL_RSA_VERIFY_ONLY)
/* Multiply a by b mod m and store in r: r = (a * b) mod m
 *
 * @param  [in]   a  SP integer to multiply.
 * @param  [in]   b  SP integer to multiply.
 * @param  [in]   m  SP integer that is the modulus.
 * @param  [out]  r  SP integer result.
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when a, b, m or r is NULL; m is 0; or a * b is too big for
 *          fixed data length.
 * @return  MP_MEM when dynamic memory allocation fails.
 */
int sp_mulmod(sp_int* a, sp_int* b, sp_int* m, sp_int* r)
{
    int err = MP_OKAY;
    sp_int t[1];

    if ((a == NULL) || (b == NULL) || (m == NULL) || (r == NULL)) {
        err = MP_VAL;
    }
    /* Need extra digit during calculation. */
    if ((err == MP_OKAY) && (a->used + b->used >= r->size)) {
        err = MP_VAL;
    }

    if (err == MP_OKAY) {
        err = sp_init(t);
    }
    if (err == MP_OKAY) {
        err = sp_mul(a, b, t);
    }
    if (err == MP_OKAY) {
        err = sp_mod(t, m, r);
    }

    return err;
}
#endif /* !WOLFSSL_RSA_VERIFY_ONLY */

#if defined(HAVE_ECC) || !defined(NO_DSA) || defined(OPENSSL_EXTRA) || \
    (!defined(NO_RSA) && !defined(WOLFSSL_RSA_VERIFY_ONLY))
/* Calculates the multiplicative inverse in the field.
 *
 * @param  [in]   a  SP integer to find inverse of.
 * @param  [in]   m  SP integer this is the modulus.
 * @param  [out]  r  SP integer to hold result.
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when a, m or r is NULL; a or m is zero; a and m are even or
 *          m is negative.
 * @return  MP_MEM when dynamic memory allocation fails.
 */
int sp_invmod(sp_int* a, sp_int* m, sp_int* r)
{
    int err = MP_OKAY;
    sp_int u[1];
    sp_int v[1];
    sp_int b[1];
    sp_int c[1];

    if ((a == NULL) || (m == NULL) || (r == NULL)) {
        err = MP_VAL;
    }

#ifdef WOLFSSL_SP_INT_NEGATIVE
    if ((err == MP_OKAY) && (m->sign == MP_NEG)) {
        err = MP_VAL;
    }
#endif

    if (err == MP_OKAY) {
        sp_init(v);

        if (_sp_cmp_abs(a, m) != MP_LT) {
            err = sp_mod(a, m, v);
            a = v;
        }
    }

#ifdef WOLFSSL_SP_INT_NEGATIVE
    if ((err == MP_OKAY) && (a->sign == MP_NEG)) {
        /* Make 'a' positive */
        err = sp_add(m, a, v);
        a = v;
    }
#endif

    /* 0 != n*m + 1 (+ve m), r*a mod 0 is always 0 (never 1)  */
    if ((err == MP_OKAY) && (sp_iszero(a) || sp_iszero(m))) {
        err = MP_VAL;
    }
    /* r*2*x != n*2*y + 1 for integer x,y */
    if ((err == MP_OKAY) && sp_iseven(a) && sp_iseven(m)) {
        err = MP_VAL;
    }

    /* 1*1 = 0*m + 1  */
    if ((err == MP_OKAY) && sp_isone(a)) {
        sp_set(r, 1);
    }
    else if (err != MP_OKAY) {
    }
    else if (sp_iseven(m)) {
        /* a^-1 mod m = m + (1 - m*(m^-1 % a)) / a
         *            = m - (m*(m^-1 % a) - 1) / a
         */
        err = sp_invmod(m, a, r);
        if (err == MP_OKAY) {
            err = sp_mul(r, m, r);
        }
        if (err == MP_OKAY) {
            _sp_sub_d(r, 1, r);
            sp_div(r, a, r, NULL);
            sp_sub(m, r, r);
        }
    }
    else {
        sp_init(u);
        sp_init(b);
        sp_init(c);

        sp_copy(m, u);
        sp_copy(a, v);
        _sp_zero(b);
        sp_set(c, 1);

        while (!sp_isone(v) && !sp_iszero(u)) {
            if (sp_iseven(u)) {
                sp_div_2(u, u);
                if (sp_isodd(b)) {
                    sp_add(b, m, b);
                }
                sp_div_2(b, b);
            }
            else if (sp_iseven(v)) {
                sp_div_2(v, v);
                if (sp_isodd(c)) {
                    sp_add(c, m, c);
                }
                sp_div_2(c, c);
            }
            else if (_sp_cmp(u, v) != MP_LT) {
                sp_sub(u, v, u);
                if (_sp_cmp(b, c) == MP_LT) {
                    sp_add(b, m, b);
                }
                sp_sub(b, c, b);
            }
            else {
                sp_sub(v, u, v);
                if (_sp_cmp(c, b) == MP_LT) {
                    sp_add(c, m, c);
                }
                sp_sub(c, b, c);
            }
        }
        if (sp_iszero(u)) {
            err = MP_VAL;
        }
        else {
            err = sp_copy(c, r);
        }
    }
    return err;
}
#endif /* HAVE_ECC || !NO_DSA || OPENSSL_EXTRA || \
        * (!NO_RSA && !WOLFSSL_RSA_VERIFY_ONLY) */

#if defined(WOLFSSL_SP_MATH_ALL) || defined(WOLFSSL_HAVE_SP_DH) || \
    defined(HAVE_ECC) || (!defined(NO_RSA) && !defined(WOLFSSL_RSA_VERIFY_ONLY))

/* Square a and store in r. r = a * a
 *
 * @param  [in]   a  SP integer to square.
 * @param  [out]  r  SP integer result.
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when a or r is NULL, or the result will be too big for fixed
 *          data length.
 * @return  MP_MEM when dynamic memory allocation fails.
 */
int sp_sqr(sp_int* a, sp_int* r)
{
    return sp_mul(a, a, r);
}
/* END SP_SQR implementations */

#endif /* WOLFSSL_SP_MATH_ALL || WOLFSSL_HAVE_SP_DH || HAVE_ECC ||
        * (!NO_RSA && !WOLFSSL_RSA_VERIFY_ONLY) */

#if !defined(WOLFSSL_RSA_VERIFY_ONLY)
/* Square a mod m and store in r: r = (a * a) mod m
 *
 * @param  [in]   a  SP integer to square.
 * @param  [in]   m  SP integer that is the modulus.
 * @param  [out]  r  SP integer result.
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when a, m or r is NULL; or m is 0; or a squared is too big
 *          for fixed data length.
 * @return  MP_MEM when dynamic memory allocation fails.
 */
int sp_sqrmod(sp_int* a, sp_int* m, sp_int* r)
{
    int err = MP_OKAY;

    if ((a == NULL) || (m == NULL) || (r == NULL)) {
        err = MP_VAL;
    }
    /* Need extra digit during calculation. */
    if ((err == MP_OKAY) && (a->used * 2 >= r->size)) {
        err = MP_VAL;
    }

    if (err == MP_OKAY) {
        err = sp_sqr(a, r);
    }
    if (err == MP_OKAY) {
        err = sp_mod(r, m, r);
    }

    return err;
}
#endif /* !WOLFSSL_RSA_VERIFY_ONLY */

/*********************************
 * To and from binary and strings.
 *********************************/

/* Calculate the number of 8-bit values required to represent the
 * multi-precision number.
 *
 * When a is NULL, return s 0.
 *
 * @param  [in]  a  SP integer.
 *
 * @return  The count of 8-bit values.
 */
int sp_unsigned_bin_size(sp_int* a)
{
    int cnt = 0;

    if (a != NULL) {
        cnt = (sp_count_bits(a) + 7) / 8;
    }

    return cnt;
}

/* Convert a number as an array of bytes in big-endian format to a
 * multi-precision number.
 *
 * @param  [out]  a     SP integer.
 * @param  [in]   in    Array of bytes.
 * @param  [in]   inSz  Number of data bytes in array.
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when the number is too big to fit in an SP.
 */
int sp_read_unsigned_bin(sp_int* a, const byte* in, word32 inSz)
{
    int err = MP_OKAY;

    if ((a == NULL) || ((in == NULL) && (inSz > 0))) {
        err = MP_VAL;
    }

    /* Extra digit added to SP_INT_DIGITS to be used in calculations. */
    if ((err == MP_OKAY) && (inSz > ((word32)a->size - 1) * SP_WORD_SIZEOF)) {
        err = MP_VAL;
    }

    if (err == MP_OKAY) {
        int i;
        int j;

        a->used = (inSz + SP_WORD_SIZEOF - 1) / SP_WORD_SIZEOF;

        for (i = inSz-1, j = 0; i >= SP_WORD_SIZEOF - 1; i -= SP_WORD_SIZEOF) {
            a->dp[j]  = ((sp_int_digit)in[i - 0] <<  0);
        #if SP_WORD_SIZE >= 16
            a->dp[j] |= ((sp_int_digit)in[i - 1] <<  8);
        #endif
        #if SP_WORD_SIZE >= 32
            a->dp[j] |= ((sp_int_digit)in[i - 2] << 16) |
                        ((sp_int_digit)in[i - 3] << 24);
        #endif
        #if SP_WORD_SIZE >= 64
            a->dp[j] |= ((sp_int_digit)in[i - 4] << 32) |
                        ((sp_int_digit)in[i - 5] << 40) |
                        ((sp_int_digit)in[i - 6] << 48) |
                        ((sp_int_digit)in[i - 7] << 56);
        #endif
            j++;
        }
        a->dp[j] = 0;

    #if SP_WORD_SIZE >= 16
        if (i >= 0) {
            byte *d = (byte*)a->dp;

            a->dp[a->used - 1] = 0;
            switch (i) {
                case 6: d[inSz - 1 - 6] = in[6]; FALL_THROUGH;
                case 5: d[inSz - 1 - 5] = in[5]; FALL_THROUGH;
                case 4: d[inSz - 1 - 4] = in[4]; FALL_THROUGH;
                case 3: d[inSz - 1 - 3] = in[3]; FALL_THROUGH;
                case 2: d[inSz - 1 - 2] = in[2]; FALL_THROUGH;
                case 1: d[inSz - 1 - 1] = in[1]; FALL_THROUGH;
                case 0: d[inSz - 1 - 0] = in[0];
            }
        }
    #endif

        sp_clamp(a);
    }

    return err;
}

#if (!defined(NO_DH) || defined(HAVE_ECC) || defined(WC_RSA_BLINDING)) && \
    !defined(WOLFSSL_RSA_VERIFY_ONLY)
/* Convert the multi-precision number to an array of bytes in big-endian format.
 *
 * The array must be large enough for encoded number - use mp_unsigned_bin_size
 * to calculate the number of bytes required.
 *
 * @param  [in]   a    SP integer.
 * @param  [out]  out  Array to put encoding into.
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when a or out is NULL.
 */
int sp_to_unsigned_bin(sp_int* a, byte* out)
{
    return sp_to_unsigned_bin_len(a, out, sp_unsigned_bin_size(a));
}
#endif /* (!NO_DH || HAVE_ECC || WC_RSA_BLINDING) && !WOLFSSL_RSA_VERIFY_ONLY */

#if !defined(WOLFSSL_RSA_VERIFY_ONLY)
/* Convert the multi-precision number to an array of bytes in big-endian format.
 *
 * The array must be large enough for encoded number - use mp_unsigned_bin_size
 * to calculate the number of bytes required.
 * Front-pads the output array with zeros make number the size of the array.
 *
 * @param  [in]   a      SP integer.
 * @param  [out]  out    Array to put encoding into.
 * @param  [in]   outSz  Size of the array in bytes.
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when a or out is NULL.
 */
int sp_to_unsigned_bin_len(sp_int* a, byte* out, int outSz)
{
    int err = MP_OKAY;

    if ((a == NULL) || (out == NULL)) {
        err = MP_VAL;
    }
    if (err == MP_OKAY) {
        int j = outSz - 1;

        if (!sp_iszero(a)) {
            int i;
            for (i = 0; (j >= 0) && (i < a->used); i++) {
                int b;
                for (b = 0; b < SP_WORD_SIZE; b += 8) {
                    out[j--] = a->dp[i] >> b;
                    if (j < 0) {
                        break;
                    }
                }
            }
        }
        for (; j >= 0; j--) {
            out[j] = 0;
        }
    }

    return err;
}
#endif /* !WOLFSSL_RSA_VERIFY_ONLY */

#if defined(WOLFSSL_SP_MATH_ALL) || defined(HAVE_ECC)
/* Convert hexadecimal number as string in big-endian format to a
 * multi-precision number.
 *
 * Negative values supported when compiled with WOLFSSL_SP_INT_NEGATIVE.
 *
 * @param  [out]  a   SP integer.
 * @param  [in]   in  NUL terminated string.
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when radix not supported, value is negative, or a character
 *          is not valid.
 */
static int _sp_read_radix_16(sp_int* a, const char* in)
{
    int  err = MP_OKAY;
    int  i;
    int  s = 0;
    int  j = 0;

#ifdef WOLFSSL_SP_INT_NEGATIVE
    if (*in == '-') {
        a->sign = MP_NEG;
        in++;
    }
#endif

    while (*in == '0') {
        in++;
    }

    a->dp[0] = 0;
    for (i = (int)(XSTRLEN(in) - 1); i >= 0; i--) {
        char ch = in[i];
        if ((ch >= '0') && (ch <= '9')) {
            ch -= '0';
        }
        else if ((ch >= 'A') && (ch <= 'F')) {
            ch -= 'A' - 10;
        }
        else if ((ch >= 'a') && (ch <= 'f')) {
            ch -= 'a' - 10;
        }
        else {
            err = MP_VAL;
            break;
        }

        if (s == SP_WORD_SIZE) {
            j++;
            if (j >= a->size) {
                err = MP_VAL;
                break;
            }
            s = 0;
            a->dp[j] = 0;
        }

        a->dp[j] |= ((sp_int_digit)ch) << s;
        s += 4;
    }

    if (err == MP_OKAY) {
        a->used = j + 1;
        sp_clamp(a);
    }

    return err;
}
#endif /* WOLFSSL_SP_MATH_ALL || HAVE_ECC */

#if defined(WOLFSSL_SP_MATH_ALL) || defined(HAVE_ECC)
/* Convert a number as string in big-endian format to a big number.
 * Only supports base-16 (hexadecimal) and base-10 (decimal).
 *
 * Negative values supported when WOLFSSL_SP_INT_NEGATIVE is defined.
 *
 * @param  [out]  a      SP integer.
 * @param  [in]   in     NUL terminated string.
 * @param  [in]   radix  Number of values in a digit.
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when a or in is NULL, radix not supported, value is negative,
 *          or a character is not valid.
 */
int sp_read_radix(sp_int* a, const char* in, int radix)
{
    int err = MP_OKAY;

    if ((a == NULL) || (in == NULL)) {
        err = MP_VAL;
    }

    if (err == MP_OKAY) {
    #ifndef WOLFSSL_SP_INT_NEGATIVE
        if (*in == '-') {
            err = MP_VAL;
        }
        else
    #endif
        if (radix == 16) {
            err = _sp_read_radix_16(a, in);
        }
        else {
            err = MP_VAL;
        }
    }

    return err;
}
#endif /* WOLFSSL_SP_MATH_ALL || HAVE_ECC */

#if defined(WOLFSSL_SP_MATH_ALL) || defined(WC_MP_TO_RADIX)
/* Hex string characters. */
static const char sp_hex_char[16] = {
    '0', '1', '2', '3', '4', '5', '6', '7',
    '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
};

/* Put the big-endian, hex string encoding of a into str.
 *
 * Assumes str is large enough for result.
 * Use sp_radix_size() to calculate required length.
 *
 * @param  [in]   a    SP integer to convert.
 * @param  [out]  str  String to hold hex string result.
 *
 * @return  MP_OKAY on success.
 * @return  MP_VAL when a or str is NULL.
 */
int sp_tohex(sp_int* a, char* str)
{
    int err = MP_OKAY;
    int i;
    int j;

    if ((a == NULL) || (str == NULL)) {
        err = MP_VAL;
    }
    if (err == MP_OKAY) {
        /* quick out if its zero */
        if (sp_iszero(a) == MP_YES) {
    #ifndef WC_DISABLE_RADIX_ZERO_PAD
            *str++ = '0';
    #endif /* WC_DISABLE_RADIX_ZERO_PAD */
            *str++ = '0';
            *str = '\0';
        }
        else {
    #ifdef WOLFSSL_SP_INT_NEGATIVE
            if (a->sign == MP_NEG) {
                *str = '-';
                str++;
            }
    #endif /* WOLFSSL_SP_INT_NEGATIVE */

            i = a->used - 1;
    #ifndef WC_DISABLE_RADIX_ZERO_PAD
            for (j = SP_WORD_SIZE - 8; j >= 0; j -= 8) {
                if (((a->dp[i] >> j) & 0xff) != 0) {
                    break;
                }
                else if (j == 0) {
                    j = SP_WORD_SIZE - 8;
                    --i;
                }
            }
            j += 4;
    #else
            for (j = SP_WORD_SIZE - 4; j >= 0; j -= 4) {
                if (((a->dp[i] >> j) & 0xf) != 0) {
                    break;
                }
                else if (j == 0) {
                    j = SP_WORD_SIZE - 4;
                    --i;
                }
            }
    #endif /* WC_DISABLE_RADIX_ZERO_PAD */
            for (; j >= 0; j -= 4) {
                *(str++) = sp_hex_char[(a->dp[i] >> j) & 0xf];
            }
            for (--i; i >= 0; i--) {
                for (j = SP_WORD_SIZE - 4; j >= 0; j -= 4) {
                    *(str++) = sp_hex_char[(a->dp[i] >> j) & 0xf];
                }
            }
            *str = '\0';
        }
    }

    return err;
}
#endif /* WOLFSSL_SP_MATH_ALL || WC_MP_TO_RADIX */

/* Returns the run time settings.
 *
 * @return  Settings value.
 */
word32 CheckRunTimeSettings(void)
{
    return CTC_SETTINGS;
}

/* Returns the fast math settings.
 *
 * @return  Setting - number of bits in a digit.
 */
word32 CheckRunTimeFastMath(void)
{
    return SP_WORD_SIZE;
}

#endif /* WOLFSSL_SP_MATH || WOLFSSL_SP_MATH_ALL */
