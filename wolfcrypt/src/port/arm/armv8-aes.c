/* armv8-aes.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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
#include <wolfssl/wolfcrypt/libwolfssl_sources.h>
/*
 * There are two versions one for 64 (Aarch64) and one for 32 bit (Aarch32).
 * If changing one check the other.
 */

#if !defined(NO_AES) && defined(WOLFSSL_ARMASM)

#include <wolfssl/wolfcrypt/aes.h>

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

extern void AES_set_encrypt_key(const unsigned char* key, word32 len,
    unsigned char* ks);
extern void AES_ECB_encrypt(const unsigned char* in, unsigned char* out,
    unsigned long len, const unsigned char* ks, int nr);

#if defined(GCM_TABLE) || defined(GCM_TABLE_4BIT)
/* in pre-C2x C, constness conflicts for dimensioned arrays can't be resolved.
 */
extern void GCM_gmult_len(byte* x, /* const */ byte m[32][WC_AES_BLOCK_SIZE],
    const unsigned char* data, unsigned long len);
#endif
extern void AES_GCM_encrypt(const unsigned char* in, unsigned char* out,
    unsigned long len, const unsigned char* ks, int nr, unsigned char* ctr);

static int wc_AesSetKey(Aes* aes, const byte* userKey, word32 keylen,
            const byte* iv, int dir)
{
    if ((keylen != 32)  ||
           (aes == NULL) || (userKey == NULL)) {
        return BAD_FUNC_ARG;
    }
    /* Check alignment */
    if ((unsigned long)userKey & (sizeof(aes->key[0]) - 1U)) {
        return BAD_FUNC_ARG;
    }
    aes->keylen = 32;
    aes->rounds = 14;

    AES_set_encrypt_key(userKey, keylen * 8, (byte*)aes->key);
    return 0;
}
static WC_INLINE void RIGHTSHIFTX(byte* x)
{
    int i;
    int carryIn = 0;
    byte borrow = (0x00 - (x[15] & 0x01)) & 0xE1;

    for (i = 0; i < WC_AES_BLOCK_SIZE; i++) {
        int carryOut = (x[i] & 0x01) << 7;
        x[i] = (byte) ((x[i] >> 1) | carryIn);
        carryIn = carryOut;
    }
    x[0] ^= borrow;
}

void GenerateM0(Gcm* gcm)
{
    int i;
    byte (*m)[WC_AES_BLOCK_SIZE] = gcm->M0;

    /* 0 times -> 0x0 */
    XMEMSET(m[0x0], 0, WC_AES_BLOCK_SIZE);
    /* 1 times -> 0x8 */
    XMEMCPY(m[0x8], gcm->H, WC_AES_BLOCK_SIZE);
    /* 2 times -> 0x4 */
    XMEMCPY(m[0x4], m[0x8], WC_AES_BLOCK_SIZE);
    RIGHTSHIFTX(m[0x4]);
    /* 4 times -> 0x2 */
    XMEMCPY(m[0x2], m[0x4], WC_AES_BLOCK_SIZE);
    RIGHTSHIFTX(m[0x2]);
    /* 8 times -> 0x1 */
    XMEMCPY(m[0x1], m[0x2], WC_AES_BLOCK_SIZE);
    RIGHTSHIFTX(m[0x1]);

    /* 0x3 */
    XMEMCPY(m[0x3], m[0x2], WC_AES_BLOCK_SIZE);
    xorbuf (m[0x3], m[0x1], WC_AES_BLOCK_SIZE);

    /* 0x5 -> 0x7 */
    XMEMCPY(m[0x5], m[0x4], WC_AES_BLOCK_SIZE);
    xorbuf (m[0x5], m[0x1], WC_AES_BLOCK_SIZE);
    XMEMCPY(m[0x6], m[0x4], WC_AES_BLOCK_SIZE);
    xorbuf (m[0x6], m[0x2], WC_AES_BLOCK_SIZE);
    XMEMCPY(m[0x7], m[0x4], WC_AES_BLOCK_SIZE);
    xorbuf (m[0x7], m[0x3], WC_AES_BLOCK_SIZE);

    /* 0x9 -> 0xf */
    XMEMCPY(m[0x9], m[0x8], WC_AES_BLOCK_SIZE);
    xorbuf (m[0x9], m[0x1], WC_AES_BLOCK_SIZE);
    XMEMCPY(m[0xa], m[0x8], WC_AES_BLOCK_SIZE);
    xorbuf (m[0xa], m[0x2], WC_AES_BLOCK_SIZE);
    XMEMCPY(m[0xb], m[0x8], WC_AES_BLOCK_SIZE);
    xorbuf (m[0xb], m[0x3], WC_AES_BLOCK_SIZE);
    XMEMCPY(m[0xc], m[0x8], WC_AES_BLOCK_SIZE);
    xorbuf (m[0xc], m[0x4], WC_AES_BLOCK_SIZE);
    XMEMCPY(m[0xd], m[0x8], WC_AES_BLOCK_SIZE);
    xorbuf (m[0xd], m[0x5], WC_AES_BLOCK_SIZE);
    XMEMCPY(m[0xe], m[0x8], WC_AES_BLOCK_SIZE);
    xorbuf (m[0xe], m[0x6], WC_AES_BLOCK_SIZE);
    XMEMCPY(m[0xf], m[0x8], WC_AES_BLOCK_SIZE);
    xorbuf (m[0xf], m[0x7], WC_AES_BLOCK_SIZE);

#ifndef __aarch64__
    for (i = 0; i < 16; i++) {
        word32* m32 = (word32*)gcm->M0[i];
        m32[0] = ByteReverseWord32(m32[0]);
        m32[1] = ByteReverseWord32(m32[1]);
        m32[2] = ByteReverseWord32(m32[2]);
        m32[3] = ByteReverseWord32(m32[3]);
    }
#elif !defined(BIG_ENDIAN_ORDER)
    for (i = 0; i < 16; i++) {
        Shift4_M0(m[16+i], m[i]);
    }
#endif
}

int wc_AesGcmSetKey(Aes* aes, const byte* key, word32 len)
{
    int  ret;
    byte iv[WC_AES_BLOCK_SIZE];

    if (aes == NULL) {
        return BAD_FUNC_ARG;
    }

    if (len != 32) {
        return BAD_FUNC_ARG;
    }

    XMEMSET(iv, 0, WC_AES_BLOCK_SIZE);
    ret = wc_AesSetKey(aes, key, len, iv, AES_ENCRYPTION);

    if (ret == 0) {
        AES_ECB_encrypt(iv, aes->gcm.H, WC_AES_BLOCK_SIZE,
            (const unsigned char*)aes->key, aes->rounds);
        #if defined(GCM_TABLE) || defined(GCM_TABLE_4BIT)
            GenerateM0(&aes->gcm);
        #endif /* GCM_TABLE */
    }

    return ret;
}

static WC_INLINE void FlattenSzInBits(byte* buf, word32 sz)
{
    /* Multiply the sz by 8 */
    word32 szHi = (sz >> (8*sizeof(sz) - 3));
    sz <<= 3;

    /* copy over the words of the sz into the destination buffer */
    buf[0] = (szHi >> 24) & 0xff;
    buf[1] = (szHi >> 16) & 0xff;
    buf[2] = (szHi >>  8) & 0xff;
    buf[3] = szHi & 0xff;
    buf[4] = (sz >> 24) & 0xff;
    buf[5] = (sz >> 16) & 0xff;
    buf[6] = (sz >>  8) & 0xff;
    buf[7] = sz & 0xff;
}

/* GCM_gmult_len implementation in armv8-32-aes-asm_c.c */
#define GCM_GMULT_LEN(aes, x, a, len) GCM_gmult_len(x, aes->gcm.M0, a, len)

static void gcm_ghash_arm32(Aes* aes, const byte* a, word32 aSz, const byte* c,
    word32 cSz, byte* s, word32 sSz)
{
    byte x[WC_AES_BLOCK_SIZE];
    byte scratch[WC_AES_BLOCK_SIZE];
    word32 blocks, partial;

    if (aes == NULL) {
        return;
    }

    XMEMSET(x, 0, WC_AES_BLOCK_SIZE);

    /* Hash in A, the Additional Authentication Data */
    if (aSz != 0 && a != NULL) {
        blocks = aSz / WC_AES_BLOCK_SIZE;
        partial = aSz % WC_AES_BLOCK_SIZE;
        if (blocks > 0) {
            GCM_GMULT_LEN(aes, x, a, blocks * WC_AES_BLOCK_SIZE);
            a += blocks * WC_AES_BLOCK_SIZE;
        }
        if (partial != 0) {
            XMEMSET(scratch, 0, WC_AES_BLOCK_SIZE);
            XMEMCPY(scratch, a, partial);
            GCM_GMULT_LEN(aes, x, scratch, WC_AES_BLOCK_SIZE);
        }
    }

    /* Hash in C, the Ciphertext */
    if (cSz != 0 && c != NULL) {
        blocks = cSz / WC_AES_BLOCK_SIZE;
        partial = cSz % WC_AES_BLOCK_SIZE;
        if (blocks > 0) {
            GCM_GMULT_LEN(aes, x, c, blocks * WC_AES_BLOCK_SIZE);
            c += blocks * WC_AES_BLOCK_SIZE;
        }
        if (partial != 0) {
            XMEMSET(scratch, 0, WC_AES_BLOCK_SIZE);
            XMEMCPY(scratch, c, partial);
            GCM_GMULT_LEN(aes, x, scratch, WC_AES_BLOCK_SIZE);
        }
    }

    /* Hash in the lengths of A and C in bits */
    FlattenSzInBits(&scratch[0], aSz);
    FlattenSzInBits(&scratch[8], cSz);
    GCM_GMULT_LEN(aes, x, scratch, WC_AES_BLOCK_SIZE);

    /* Copy the result into s. */
    XMEMCPY(s, x, sSz);
}

int wc_AesGcmEncrypt(Aes* aes, byte* out, const byte* in, word32 sz,
                   const byte* iv, word32 ivSz,
                   byte* authTag, word32 authTagSz,
                   const byte* authIn, word32 authInSz)
{
    word32 blocks;
    word32 partial;
    byte counter[WC_AES_BLOCK_SIZE];
    byte initialCounter[WC_AES_BLOCK_SIZE];
    byte x[WC_AES_BLOCK_SIZE];
    byte scratch[WC_AES_BLOCK_SIZE];

    /* argument checks */
    /* If the sz is non-zero, both in and out must be set. If sz is 0,
     * in and out are don't cares, as this is is the GMAC case. */
    if (aes == NULL || (iv == NULL && ivSz > 0) || (authTag == NULL) ||
        (sz != 0 && (in == NULL || out == NULL)) ||
        (authIn == NULL && authInSz > 0) || (ivSz == 0) ||
         authTagSz > AES_BLOCK_SIZE) {
        return BAD_FUNC_ARG;
    }

    if (authTagSz < WOLFSSL_MIN_AUTH_TAG_SZ || authTagSz > WC_AES_BLOCK_SIZE) {
        return BAD_FUNC_ARG;
    }

    if (aes->rounds != 10 && aes->rounds != 12 && aes->rounds != 14) {
        return KEYUSAGE_E;
    }
    XMEMSET(initialCounter, 0, WC_AES_BLOCK_SIZE);
    if (ivSz == GCM_NONCE_MID_SZ) {
        XMEMCPY(initialCounter, iv, ivSz);
        initialCounter[WC_AES_BLOCK_SIZE - 1] = 1;
    }
    else {
        gcm_ghash_arm32(aes, NULL, 0, iv, ivSz, initialCounter,
                        WC_AES_BLOCK_SIZE);
    }
    XMEMCPY(counter, initialCounter, WC_AES_BLOCK_SIZE);

    /* Hash in the Additional Authentication Data */
    XMEMSET(x, 0, WC_AES_BLOCK_SIZE);
    if (authInSz != 0 && authIn != NULL) {
        blocks = authInSz / WC_AES_BLOCK_SIZE;
        partial = authInSz % WC_AES_BLOCK_SIZE;
        if (blocks > 0) {
            GCM_GMULT_LEN(aes, x, authIn, blocks * WC_AES_BLOCK_SIZE);
            authIn += blocks * WC_AES_BLOCK_SIZE;
        }
        if (partial != 0) {
            XMEMSET(scratch, 0, WC_AES_BLOCK_SIZE);
            XMEMCPY(scratch, authIn, partial);
            GCM_GMULT_LEN(aes, x, scratch, WC_AES_BLOCK_SIZE);
        }
    }

    /* do as many blocks as possible */
    blocks = sz / WC_AES_BLOCK_SIZE;
    partial = sz % WC_AES_BLOCK_SIZE;
    if (blocks > 0) {
        AES_GCM_encrypt(in, out, blocks * WC_AES_BLOCK_SIZE,
            (const unsigned char*)aes->key, aes->rounds, counter);
        GCM_GMULT_LEN(aes, x, out, blocks * WC_AES_BLOCK_SIZE);
        in += blocks * WC_AES_BLOCK_SIZE;
        out += blocks * WC_AES_BLOCK_SIZE;
    }

    /* take care of partial block sizes leftover */
    if (partial != 0) {
        AES_GCM_encrypt(in, scratch, WC_AES_BLOCK_SIZE,
            (const unsigned char*)aes->key, aes->rounds, counter);
        XMEMCPY(out, scratch, partial);

        XMEMSET(scratch, 0, WC_AES_BLOCK_SIZE);
        XMEMCPY(scratch, out, partial);
        GCM_GMULT_LEN(aes, x, scratch, WC_AES_BLOCK_SIZE);
    }

    /* Hash in the lengths of A and C in bits */
    XMEMSET(scratch, 0, WC_AES_BLOCK_SIZE);
    FlattenSzInBits(&scratch[0], authInSz);
    FlattenSzInBits(&scratch[8], sz);
    GCM_GMULT_LEN(aes, x, scratch, WC_AES_BLOCK_SIZE);
    if (authTagSz > WC_AES_BLOCK_SIZE) {
        XMEMCPY(authTag, x, WC_AES_BLOCK_SIZE);
    }
    else {
        /* authTagSz can be smaller than WC_AES_BLOCK_SIZE */
        XMEMCPY(authTag, x, authTagSz);
    }

    /* Auth tag calculation. */
    AES_ECB_encrypt(initialCounter, scratch, WC_AES_BLOCK_SIZE,
        (const unsigned char*)aes->key, aes->rounds);
    xorbuf(authTag, scratch, authTagSz);

    return 0;
}

int wc_AesGcmDecrypt(Aes* aes, byte* out, const byte* in, word32 sz,
    const byte* iv, word32 ivSz, const byte* authTag, word32 authTagSz,
    const byte* authIn, word32 authInSz)
{
    word32 blocks;
    word32 partial;
    byte counter[WC_AES_BLOCK_SIZE];
    byte initialCounter[WC_AES_BLOCK_SIZE];
    byte scratch[WC_AES_BLOCK_SIZE];
    byte x[WC_AES_BLOCK_SIZE];

    /* argument checks */
    /* If the sz is non-zero, both in and out must be set. If sz is 0,
     * in and out are don't cares, as this is is the GMAC case. */

    if (aes == NULL || iv == NULL || (sz != 0 && (in == NULL || out == NULL)) ||
        authTag == NULL || authTagSz > WC_AES_BLOCK_SIZE || authTagSz == 0 ||
        ivSz == 0) {
        return BAD_FUNC_ARG;
    }

    XMEMSET(initialCounter, 0, WC_AES_BLOCK_SIZE);
    if (ivSz == GCM_NONCE_MID_SZ) {
        XMEMCPY(initialCounter, iv, ivSz);
        initialCounter[WC_AES_BLOCK_SIZE - 1] = 1;
    }
    else {
        gcm_ghash_arm32(aes, NULL, 0, iv, ivSz, initialCounter,
                        WC_AES_BLOCK_SIZE);
    }
    XMEMCPY(counter, initialCounter, WC_AES_BLOCK_SIZE);

    XMEMSET(x, 0, WC_AES_BLOCK_SIZE);
    /* Hash in the Additional Authentication Data */
    if (authInSz != 0 && authIn != NULL) {
        blocks = authInSz / WC_AES_BLOCK_SIZE;
        partial = authInSz % WC_AES_BLOCK_SIZE;
        if (blocks > 0) {
            GCM_GMULT_LEN(aes, x, authIn, blocks * WC_AES_BLOCK_SIZE);
            authIn += blocks * WC_AES_BLOCK_SIZE;
        }
        if (partial != 0) {
            XMEMSET(scratch, 0, WC_AES_BLOCK_SIZE);
            XMEMCPY(scratch, authIn, partial);
            GCM_GMULT_LEN(aes, x, scratch, WC_AES_BLOCK_SIZE);
        }
    }

    blocks = sz / WC_AES_BLOCK_SIZE;
    partial = sz % WC_AES_BLOCK_SIZE;
    /* do as many blocks as possible */
    if (blocks > 0) {
        GCM_GMULT_LEN(aes, x, in, blocks * WC_AES_BLOCK_SIZE);
        if (in != NULL  && out != NULL) {
            AES_GCM_encrypt(in, out, blocks * WC_AES_BLOCK_SIZE,
                (const unsigned char*)aes->key, aes->rounds, counter);
            in += blocks * WC_AES_BLOCK_SIZE;
            out += blocks * WC_AES_BLOCK_SIZE;
        }
    }
    if (partial != 0) {
        XMEMSET(scratch, 0, WC_AES_BLOCK_SIZE);
        if (in != NULL)
            XMEMCPY(scratch, in, partial);
        GCM_GMULT_LEN(aes, x, scratch, WC_AES_BLOCK_SIZE);
        if (in != NULL  && out != NULL) {
            AES_GCM_encrypt(in, scratch, WC_AES_BLOCK_SIZE,
                (const unsigned char*)aes->key, aes->rounds, counter);
            XMEMCPY(out, scratch, partial);
        }
    }

    XMEMSET(scratch, 0, WC_AES_BLOCK_SIZE);
    FlattenSzInBits(&scratch[0], authInSz);
    FlattenSzInBits(&scratch[8], sz);
    GCM_GMULT_LEN(aes, x, scratch, WC_AES_BLOCK_SIZE);
    AES_ECB_encrypt(initialCounter, scratch, WC_AES_BLOCK_SIZE,
        (const unsigned char*)aes->key, aes->rounds);
    xorbuf(x, scratch, authTagSz);
    if (authTag != NULL) {
        if (ConstantCompare(authTag, x, authTagSz) != 0) {
            return AES_GCM_AUTH_E;
        }
    }

    return 0;
}
#endif /* !NO_AES && WOLFSSL_ARMASM */
