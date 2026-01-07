/* aes.h
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

/*!
    \file wolfssl/wolfcrypt/aes.h
*/
/*

DESCRIPTION
This library provides the interfaces to the Advanced Encryption Standard (AES)
for encrypting and decrypting data. AES is the standard known for a symmetric
block cipher mechanism that uses n-bit binary string parameter key with 128-bits,
192-bits, and 256-bits of key sizes.

*/
#ifndef WOLF_CRYPT_AES_H
#define WOLF_CRYPT_AES_H

#include <wolfssl/wolfcrypt/types.h>

#ifndef NO_AES

typedef struct Gcm {
    ALIGN16 byte H[16];
    ALIGN16 byte M0[32][16];
} Gcm;

WOLFSSL_LOCAL void GenerateM0(Gcm* gcm);

#ifdef __cplusplus
    extern "C" {
#endif

#ifndef WOLFSSL_AES_KEY_SIZE_ENUM
#define WOLFSSL_AES_KEY_SIZE_ENUM
enum {
    AES_128_KEY_SIZE    = 16,  /* for 128 bit             */
    AES_192_KEY_SIZE    = 24,  /* for 192 bit             */
    AES_256_KEY_SIZE    = 32,  /* for 256 bit             */

    AES_IV_SIZE         = 16  /* always block size       */
};
#endif

enum {
    AES_ENC_TYPE   = WC_CIPHER_AES,   /* cipher unique type */
    AES_ENCRYPTION = 0,
    AES_DECRYPTION = 1,

    WC_AES_BLOCK_SIZE      = 16,
    #define AES_BLOCK_SIZE WC_AES_BLOCK_SIZE

    GCM_NONCE_MAX_SZ = 16, /* wolfCrypt's maximum nonce size allowed. */
    GCM_NONCE_MID_SZ = 12, /* The default nonce size for AES-GCM. */
    GCM_NONCE_MIN_SZ = 8,  /* wolfCrypt's minimum nonce size allowed. */
    CTR_SZ   = 4,
    AES_IV_FIXED_SZ = 4 WC_ENUM_TERMINATOR
    WOLF_ENUM_DUMMY_LAST_ELEMENT(AES)
};


struct Aes {
    ALIGN16 word32 key[60];
    word32  rounds;
    int     keylen;
#ifdef HAVE_AESGCM
    word32 invokeCtr[2];
    word32 nonceSz;
    Gcm gcm;
#endif /* HAVE_AESGCM */
    void*  heap; /* memory hint to use */
};

#ifndef WC_AES_TYPE_DEFINED
    typedef struct Aes Aes;
    #define WC_AES_TYPE_DEFINED
#endif

#ifdef HAVE_AESGCM
 WOLFSSL_API int  wc_AesGcmSetKey(Aes* aes, const byte* key, word32 len);
 WOLFSSL_API int  wc_AesGcmEncrypt(Aes* aes, byte* out,
                                   const byte* in, word32 sz,
                                   const byte* iv, word32 ivSz,
                                   byte* authTag, word32 authTagSz,
                                   const byte* authIn, word32 authInSz);
 WOLFSSL_API WARN_UNUSED_RESULT int wc_AesGcmDecrypt(Aes* aes, byte* out,
                                   const byte* in, word32 sz,
                                   const byte* iv, word32 ivSz,
                                   const byte* authTag, word32 authTagSz,
                                   const byte* authIn, word32 authInSz);

#endif /* HAVE_AESGCM */

#ifdef __cplusplus
    } /* extern "C" */
#endif


#endif /* NO_AES */
#endif /* WOLF_CRYPT_AES_H */
