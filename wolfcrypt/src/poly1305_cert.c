/* poly1305_cert.c
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

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>
#ifdef HAVE_DO178
#ifdef HAVE_POLY1305
#include <wolfssl/wolfcrypt/poly1305.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/cpuid.h>
#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif
static word32 U8TO32(const byte *p)
{
    return
        (((word32)(p[0] & 0xff)      ) |
         ((word32)(p[1] & 0xff) <<  8) |
         ((word32)(p[2] & 0xff) << 16) |
         ((word32)(p[3] & 0xff) << 24));
}

static void U32TO8(byte *p, word32 v) {
    p[0] = (v      ) & 0xff;
    p[1] = (v >>  8) & 0xff;
    p[2] = (v >> 16) & 0xff;
    p[3] = (v >> 24) & 0xff;
}

static void U32TO64(word32 v, byte* p)
{
    XMEMSET(p, 0, 8);
    p[0] = (v & 0xFF);
    p[1] = (v >>  8) & 0xFF;
    p[2] = (v >> 16) & 0xFF;
    p[3] = (v >> 24) & 0xFF;
}

void poly1305_blocks(Poly1305* ctx, const unsigned char *m,
                            size_t bytes)
{
 /* if not 64 bit then use 32 bit */
    const word32 hibit = (ctx->finished) ? 0 : ((word32)1 << 24); /* 1 << 128 */
    word32 r0,r1,r2,r3,r4;
    word32 s1,s2,s3,s4;
    word32 h0,h1,h2,h3,h4;
    word64 d0,d1,d2,d3,d4;
    word32 c;


    r0 = ctx->r[0];
    r1 = ctx->r[1];
    r2 = ctx->r[2];
    r3 = ctx->r[3];
    r4 = ctx->r[4];

    s1 = r1 * 5;
    s2 = r2 * 5;
    s3 = r3 * 5;
    s4 = r4 * 5;

    h0 = ctx->h[0];
    h1 = ctx->h[1];
    h2 = ctx->h[2];
    h3 = ctx->h[3];
    h4 = ctx->h[4];

    while (bytes >= POLY1305_BLOCK_SIZE) {
        /* h += m[i] */
        h0 += (U8TO32(m+ 0)     ) & 0x3ffffff;
        h1 += (U8TO32(m+ 3) >> 2) & 0x3ffffff;
        h2 += (U8TO32(m+ 6) >> 4) & 0x3ffffff;
        h3 += (U8TO32(m+ 9) >> 6) & 0x3ffffff;
        h4 += (U8TO32(m+12) >> 8) | hibit;

        /* h *= r */
        d0 = ((word64)h0 * r0) + ((word64)h1 * s4) + ((word64)h2 * s3) +
             ((word64)h3 * s2) + ((word64)h4 * s1);
        d1 = ((word64)h0 * r1) + ((word64)h1 * r0) + ((word64)h2 * s4) +
             ((word64)h3 * s3) + ((word64)h4 * s2);
        d2 = ((word64)h0 * r2) + ((word64)h1 * r1) + ((word64)h2 * r0) +
             ((word64)h3 * s4) + ((word64)h4 * s3);
        d3 = ((word64)h0 * r3) + ((word64)h1 * r2) + ((word64)h2 * r1) +
             ((word64)h3 * r0) + ((word64)h4 * s4);
        d4 = ((word64)h0 * r4) + ((word64)h1 * r3) + ((word64)h2 * r2) +
             ((word64)h3 * r1) + ((word64)h4 * r0);

        /* (partial) h %= p */
                      c = (word32)(d0 >> 26); h0 = (word32)d0 & 0x3ffffff;
        d1 += c;      c = (word32)(d1 >> 26); h1 = (word32)d1 & 0x3ffffff;
        d2 += c;      c = (word32)(d2 >> 26); h2 = (word32)d2 & 0x3ffffff;
        d3 += c;      c = (word32)(d3 >> 26); h3 = (word32)d3 & 0x3ffffff;
        d4 += c;      c = (word32)(d4 >> 26); h4 = (word32)d4 & 0x3ffffff;
        h0 += c * 5;  c =  (h0 >> 26); h0 =                h0 & 0x3ffffff;
        h1 += c;

        m += POLY1305_BLOCK_SIZE;
        bytes -= POLY1305_BLOCK_SIZE;
    }

    ctx->h[0] = h0;
    ctx->h[1] = h1;
    ctx->h[2] = h2;
    ctx->h[3] = h3;
    ctx->h[4] = h4;
}

void poly1305_block(Poly1305* ctx, const unsigned char *m)
{
    poly1305_blocks(ctx, m, POLY1305_BLOCK_SIZE);
}


int wc_Poly1305SetKey(Poly1305* ctx, const byte* key, word32 keySz)
{
    if (key == NULL)
        return BAD_FUNC_ARG;

    if (keySz != 32 || ctx == NULL)
        return BAD_FUNC_ARG;

    /* r &= 0xffffffc0ffffffc0ffffffc0fffffff */
    ctx->r[0] = (U8TO32(key +  0)     ) & 0x3ffffff;
    ctx->r[1] = (U8TO32(key +  3) >> 2) & 0x3ffff03;
    ctx->r[2] = (U8TO32(key +  6) >> 4) & 0x3ffc0ff;
    ctx->r[3] = (U8TO32(key +  9) >> 6) & 0x3f03fff;
    ctx->r[4] = (U8TO32(key + 12) >> 8) & 0x00fffff;

    /* h = 0 */
    ctx->h[0] = 0;
    ctx->h[1] = 0;
    ctx->h[2] = 0;
    ctx->h[3] = 0;
    ctx->h[4] = 0;

    /* save pad for later */
    ctx->pad[0] = U8TO32(key + 16);
    ctx->pad[1] = U8TO32(key + 20);
    ctx->pad[2] = U8TO32(key + 24);
    ctx->pad[3] = U8TO32(key + 28);

    ctx->leftover = 0;
    ctx->finished = 0;

    return 0;
}


int wc_Poly1305Final(Poly1305* ctx, byte* mac)
{

    word32 h0,h1,h2,h3,h4,c;
    word32 g0,g1,g2,g3,g4;
    word64 f;
    word32 mask;

    if (ctx == NULL)
        return BAD_FUNC_ARG;
    /* process the remaining block */
    if (ctx->leftover) {
        size_t i = ctx->leftover;
        ctx->buffer[i++] = 1;
        for (; i < POLY1305_BLOCK_SIZE; i++)
            ctx->buffer[i] = 0;
        ctx->finished = 1;
        poly1305_block(ctx, ctx->buffer);
    }

    /* fully carry h */
    h0 = ctx->h[0];
    h1 = ctx->h[1];
    h2 = ctx->h[2];
    h3 = ctx->h[3];
    h4 = ctx->h[4];

                 c = h1 >> 26; h1 = h1 & 0x3ffffff;
    h2 +=     c; c = h2 >> 26; h2 = h2 & 0x3ffffff;
    h3 +=     c; c = h3 >> 26; h3 = h3 & 0x3ffffff;
    h4 +=     c; c = h4 >> 26; h4 = h4 & 0x3ffffff;
    h0 += c * 5; c = h0 >> 26; h0 = h0 & 0x3ffffff;
    h1 +=     c;

    /* compute h + -p */
    g0 = h0 + 5; c = g0 >> 26; g0 &= 0x3ffffff;
    g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ffffff;
    g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ffffff;
    g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ffffff;
    g4 = h4 + c - ((word32)1 << 26);

    /* select h if h < p, or h + -p if h >= p */
    mask = ((word32)g4 >> ((sizeof(word32) * 8) - 1)) - 1;
    g0 &= mask;
    g1 &= mask;
    g2 &= mask;
    g3 &= mask;
    g4 &= mask;
    mask = ~mask;
    h0 = (h0 & mask) | g0;
    h1 = (h1 & mask) | g1;
    h2 = (h2 & mask) | g2;
    h3 = (h3 & mask) | g3;
    h4 = (h4 & mask) | g4;

    /* h = h % (2^128) */
    h0 = ((h0      ) | (h1 << 26)) & 0xffffffff;
    h1 = ((h1 >>  6) | (h2 << 20)) & 0xffffffff;
    h2 = ((h2 >> 12) | (h3 << 14)) & 0xffffffff;
    h3 = ((h3 >> 18) | (h4 <<  8)) & 0xffffffff;

    /* mac = (h + pad) % (2^128) */
    f = (word64)h0 + ctx->pad[0]            ; h0 = (word32)f;
    f = (word64)h1 + ctx->pad[1] + (f >> 32); h1 = (word32)f;
    f = (word64)h2 + ctx->pad[2] + (f >> 32); h2 = (word32)f;
    f = (word64)h3 + ctx->pad[3] + (f >> 32); h3 = (word32)f;

    U32TO8(mac + 0, h0);
    U32TO8(mac + 4, h1);
    U32TO8(mac + 8, h2);
    U32TO8(mac + 12, h3);

    /* zero out the state */
    ctx->h[0] = 0;
    ctx->h[1] = 0;
    ctx->h[2] = 0;
    ctx->h[3] = 0;
    ctx->h[4] = 0;
    ctx->r[0] = 0;
    ctx->r[1] = 0;
    ctx->r[2] = 0;
    ctx->r[3] = 0;
    ctx->r[4] = 0;
    ctx->pad[0] = 0;
    ctx->pad[1] = 0;
    ctx->pad[2] = 0;
    ctx->pad[3] = 0;

    return 0;
}

int wc_Poly1305Update(Poly1305* ctx, const byte* m, word32 bytes)
{
    size_t i;

    if (ctx == NULL)
        return BAD_FUNC_ARG;
    {
        /* handle leftover */
        if (ctx->leftover) {
            size_t want = (POLY1305_BLOCK_SIZE - ctx->leftover);
            if (want > bytes)
                want = bytes;
            for (i = 0; i < want; i++)
                ctx->buffer[ctx->leftover + i] = m[i];
            bytes -= (word32)want;
            m += want;
            ctx->leftover += want;
            if (ctx->leftover < POLY1305_BLOCK_SIZE)
                return 0;
            poly1305_block(ctx, ctx->buffer);
            ctx->leftover = 0;
        }

        /* process full blocks */
        if (bytes >= POLY1305_BLOCK_SIZE) {
            size_t want = (bytes & ~(POLY1305_BLOCK_SIZE - 1));
            poly1305_blocks(ctx, m, want);
            m += want;
            bytes -= (word32)want;
        }

        /* store leftover */
        if (bytes) {
            for (i = 0; i < bytes; i++)
                ctx->buffer[ctx->leftover + i] = m[i];
            ctx->leftover += bytes;
        }
    }

    return 0;
}

/*  Takes in an initialized Poly1305 struct that has a key loaded and creates
    a MAC (tag) using recent TLS AEAD padding scheme.
    ctx        : Initialized Poly1305 struct to use
    additional : Additional data to use
    addSz      : Size of additional buffer
    input      : Input buffer to create tag from
    sz         : Size of input buffer
    tag        : Buffer to hold created tag
    tagSz      : Size of input tag buffer (must be at least
                 WC_POLY1305_MAC_SZ(16))
 */
int wc_Poly1305_MAC(Poly1305* ctx, byte* additional, word32 addSz,
                    byte* input, word32 sz, byte* tag, word32 tagSz)
{
    int ret;
    byte padding[WC_POLY1305_PAD_SZ - 1];
    word32 paddingLen;
    byte little64[16];

    XMEMSET(padding, 0, sizeof(padding));

    /* sanity check on arguments */
    if (ctx == NULL || input == NULL || tag == NULL ||
                                                   tagSz < WC_POLY1305_MAC_SZ) {
        return BAD_FUNC_ARG;
    }

    /* additional allowed to be 0 */
    if (addSz > 0) {
        if (additional == NULL)
            return BAD_FUNC_ARG;

        /* additional data plus padding */
        if ((ret = wc_Poly1305Update(ctx, additional, addSz)) != 0) {
            return ret;
        }
        paddingLen = -((int)addSz) & (WC_POLY1305_PAD_SZ - 1);
        if (paddingLen) {
            if ((ret = wc_Poly1305Update(ctx, padding, paddingLen)) != 0) {
                return ret;
            }
        }
    }

    /* input plus padding */
    if ((ret = wc_Poly1305Update(ctx, input, sz)) != 0) {
        return ret;
    }
    paddingLen = -((int)sz) & (WC_POLY1305_PAD_SZ - 1);
    if (paddingLen) {
        if ((ret = wc_Poly1305Update(ctx, padding, paddingLen)) != 0) {
            return ret;
        }
    }

    /* size of additional data and input as little endian 64 bit types */
    U32TO64(addSz, little64);
    U32TO64(sz, little64 + 8);
    ret = wc_Poly1305Update(ctx, little64, sizeof(little64));
    if (ret)
    {
        return ret;
    }

    /* Finalize the auth tag */
    ret = wc_Poly1305Final(ctx, tag);

    return ret;

}
#endif /* HAVE_POLY1305 */
#endif /* HAVE_DO178 */
