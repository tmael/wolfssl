/* asn.c
 *
 * Copyright (C) 2006-2019 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any XMALLOC version.
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
#ifndef NO_ASN

#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/wc_encrypt.h>
#include <wolfssl/wolfcrypt/logging.h>

#include <wolfssl/wolfcrypt/random.h>
#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#ifndef NO_SHA256
    #include <wolfssl/wolfcrypt/sha256.h>
#endif
#ifdef HAVE_ECC
    #include <wolfssl/wolfcrypt/ecc.h>
#endif
#ifndef NO_RSA
    #include <wolfssl/wolfcrypt/rsa.h>
#if defined(WOLFSSL_XILINX_CRYPT) || defined(WOLFSSL_CRYPTOCELL)
extern int wc_InitRsaHw(RsaKey* key);
#endif
#endif


#ifdef _MSC_VER
    /* 4996 warning to use MS extensions e.g., strcpy_s instead of XSTRNCPY */
    #pragma warning(disable: 4996)
#endif

#define ERROR_OUT(err, eLabel) { ret = (err); goto eLabel; }

WOLFSSL_LOCAL int GetLength(const byte* input, word32* inOutIdx, int* len,
                           word32 maxIdx)
{
    return GetLength_ex(input, inOutIdx, len, maxIdx, 1);
}

/* give option to check length value found against index. 1 to check 0 to not */
WOLFSSL_LOCAL int GetLength_ex(const byte* input, word32* inOutIdx, int* len,
                           word32 maxIdx, int check)
{
    int     length = 0;
    word32  idx = *inOutIdx;
    byte    b;

    *len = 0;    /* default length */

    if ((idx + 1) > maxIdx) {   /* for first read */
        WOLFSSL_MSG("GetLength bad index on input");
        return BUFFER_E;
    }

    b = input[idx++];
    if (b >= ASN_LONG_LENGTH) {
        word32 bytes = b & 0x7F;

        if ((idx + bytes) > maxIdx) {   /* for reading bytes */
            WOLFSSL_MSG("GetLength bad long length");
            return BUFFER_E;
        }

        while (bytes--) {
            b = input[idx++];
            length = (length << 8) | b;
        }
    }
    else
        length = b;

    if (check && (idx + length) > maxIdx) {   /* for user of length */
        WOLFSSL_MSG("GetLength value exceeds buffer length");
        return BUFFER_E;
    }

    *inOutIdx = idx;
    if (length > 0)
        *len = length;

    return length;
}

/* input : buffer to read from
 * inOutIdx : index to start reading from, gets advanced by 1 if successful
 * maxIdx : maximum index value
 * tag : ASN tag value found
 *
 * returns 0 on success
 */
int GetASNTag(const byte* input, word32* inOutIdx, byte* tag, word32 maxIdx)
{
    word32 idx;

    if (tag == NULL || inOutIdx == NULL || input == NULL) {
        return BAD_FUNC_ARG;
    }

    idx = *inOutIdx;
    if (idx + ASN_TAG_SZ > maxIdx) {
        WOLFSSL_MSG("Buffer too small for ASN tag");
        return BUFFER_E;
    }

    *tag = input[idx];
    *inOutIdx = idx + ASN_TAG_SZ;
    return 0;
}

static int GetASNHeader_ex(const byte* input, byte tag, word32* inOutIdx, int* len,
                        word32 maxIdx, int check)
{
    word32 idx = *inOutIdx;
    byte   b;
    int    length;

    if ((idx + 1) > maxIdx)
        return BUFFER_E;

    b = input[idx++];
    if (b != tag)
        return ASN_PARSE_E;

    if (GetLength_ex(input, &idx, &length, maxIdx, check) < 0)
        return ASN_PARSE_E;

    *len      = length;
    *inOutIdx = idx;
    return length;
}


/* Get the DER/BER encoding of an ASN.1 header.
 *
 * input     Buffer holding DER/BER encoded data.
 * tag       ASN.1 tag value expected in header.
 * inOutIdx  Current index into buffer to parse.
 * len       The number of bytes in the ASN.1 data.
 * maxIdx    Length of data in buffer.
 * returns BUFFER_E when there is not enough data to parse.
 *         ASN_PARSE_E when the expected tag is not found or length is invalid.
 *         Otherwise, the number of bytes in the ASN.1 data.
 */
static int GetASNHeader(const byte* input, byte tag, word32* inOutIdx, int* len,
                        word32 maxIdx)
{
    return GetASNHeader_ex(input, tag, inOutIdx, len, maxIdx, 1);
}

WOLFSSL_LOCAL int GetSequence(const byte* input, word32* inOutIdx, int* len,
                           word32 maxIdx)
{
    return GetASNHeader(input, ASN_SEQUENCE | ASN_CONSTRUCTED, inOutIdx, len,
                        maxIdx);
}


WOLFSSL_LOCAL int GetSequence_ex(const byte* input, word32* inOutIdx, int* len,
                           word32 maxIdx, int check)
{
    return GetASNHeader_ex(input, ASN_SEQUENCE | ASN_CONSTRUCTED, inOutIdx, len,
                        maxIdx, check);
}


WOLFSSL_LOCAL int GetSet(const byte* input, word32* inOutIdx, int* len,
                        word32 maxIdx)
{
    return GetASNHeader(input, ASN_SET | ASN_CONSTRUCTED, inOutIdx, len,
                        maxIdx);
}


WOLFSSL_LOCAL int GetSet_ex(const byte* input, word32* inOutIdx, int* len,
                        word32 maxIdx, int check)
{
    return GetASNHeader_ex(input, ASN_SET | ASN_CONSTRUCTED, inOutIdx, len,
                        maxIdx, check);
}

/* Get the DER/BER encoded ASN.1 NULL element.
 * Ensure that the all fields are as expected and move index past the element.
 *
 * input     Buffer holding DER/BER encoded data.
 * inOutIdx  Current index into buffer to parse.
 * maxIdx    Length of data in buffer.
 * returns BUFFER_E when there is not enough data to parse.
 *         ASN_TAG_NULL_E when the NULL tag is not found.
 *         ASN_EXPECT_0_E when the length is not zero.
 *         Otherwise, 0 to indicate success.
 */
static int GetASNNull(const byte* input, word32* inOutIdx, word32 maxIdx)
{
    word32 idx = *inOutIdx;
    byte   b;

    if ((idx + 2) > maxIdx)
        return BUFFER_E;

    b = input[idx++];
    if (b != ASN_TAG_NULL)
        return ASN_TAG_NULL_E;

    if (input[idx++] != 0)
        return ASN_EXPECT_0_E;

    *inOutIdx = idx;
    return 0;
}

/* Get the DER/BER encoding of an ASN.1 INTEGER header.
 * Removes the leading zero byte when found.
 *
 * input     Buffer holding DER/BER encoded data.
 * inOutIdx  Current index into buffer to parse.
 * len       The number of bytes in the ASN.1 data (excluding any leading zero).
 * maxIdx    Length of data in buffer.
 * returns BUFFER_E when there is not enough data to parse.
 *         ASN_PARSE_E when the INTEGER tag is not found, length is invalid,
 *         or invalid use of or missing leading zero.
 *         Otherwise, 0 to indicate success.
 */
static int GetASNInt(const byte* input, word32* inOutIdx, int* len,
                     word32 maxIdx)
{
    int    ret;

    ret = GetASNHeader(input, ASN_INTEGER, inOutIdx, len, maxIdx);
    if (ret < 0)
        return ret;

    if (*len > 0) {
        /* remove leading zero, unless there is only one 0x00 byte */
        if ((input[*inOutIdx] == 0x00) && (*len > 1)) {
            (*inOutIdx)++;
            (*len)--;

            if (*len > 0 && (input[*inOutIdx] & 0x80) == 0)
                return ASN_PARSE_E;
        }
    }

    return 0;
}

#if (!defined(WOLFSSL_KEY_GEN) && !defined(OPENSSL_EXTRA) && defined(RSA_LOW_MEM)) \
    || defined(WOLFSSL_RSA_PUBLIC_ONLY)
#if !defined(NO_RSA) && !defined(HAVE_USER_RSA)
static int SkipInt(const byte* input, word32* inOutIdx, word32 maxIdx)
{
    word32 idx = *inOutIdx;
    int    ret;
    int    length;

    ret = GetASNInt(input, &idx, &length, maxIdx);
    if (ret != 0)
        return ret;

    *inOutIdx = idx + length;

    return 0;
}
#endif
#endif


#if !defined(NO_DSA) && !defined(NO_SHA)
static char sigSha1wDsaName[] = "SHAwDSA";
#endif /* NO_DSA */
#ifndef NO_RSA
#ifndef NO_SHA256
    static char sigSha256wRsaName[] = "SHA256wRSA";
#endif
#endif /* NO_RSA */
static char sigUnknownName[] = "Unknown";


/* Get the human readable string for a signature type
 *
 * oid  Oid value for signature
 */
char* GetSigName(int oid) {
    switch (oid) {
    #if !defined(NO_DSA) && !defined(NO_SHA)
        case CTC_SHAwDSA:
            return sigSha1wDsaName;
    #endif /* NO_DSA && NO_SHA */
    #ifndef NO_RSA

        #ifndef NO_SHA256
        case CTC_SHA256wRSA:
            return sigSha256wRsaName;
        #endif
    #endif /* NO_RSA */
        default:
            return sigUnknownName;
    }
}


/* Windows header clash for WinCE using GetVersion */
WOLFSSL_LOCAL int GetMyVersion(const byte* input, word32* inOutIdx,
                               int* version, word32 maxIdx)
{
    word32 idx = *inOutIdx;

    if ((idx + MIN_VERSION_SZ) > maxIdx)
        return ASN_PARSE_E;

    if (input[idx++] != ASN_INTEGER)
        return ASN_PARSE_E;

    if (input[idx++] != 0x01)
        return ASN_VERSION_E;

    *version  = input[idx++];
    *inOutIdx = idx;

    return *version;
}

int GetInt(mp_int* mpi, const byte* input, word32* inOutIdx, word32 maxIdx)
{
    word32 idx = *inOutIdx;
    int    ret;
    int    length;

    ret = GetASNInt(input, &idx, &length, maxIdx);
    if (ret != 0)
        return ret;

    if (mp_init(mpi) != MP_OKAY)
        return MP_INIT_E;

    if (mp_read_unsigned_bin(mpi, (byte*)input + idx, length) != 0) {
        mp_clear(mpi);
        return ASN_GETINT_E;
    }

#ifdef HAVE_WOLF_BIGINT
    if (wc_bigint_from_unsigned_bin(&mpi->raw, input + idx, length) != 0) {
        mp_clear(mpi);
        return ASN_GETINT_E;
    }
#endif /* HAVE_WOLF_BIGINT */

    *inOutIdx = idx + length;

    return 0;
}

static int CheckBitString(const byte* input, word32* inOutIdx, int* len,
                          word32 maxIdx, int zeroBits, byte* unusedBits)
{
    word32 idx = *inOutIdx;
    int    length;
    byte   b;

    if ((idx + 1) > maxIdx)
        return BUFFER_E;

    if (input[idx++] != ASN_BIT_STRING)
        return ASN_BITSTR_E;

    if (GetLength(input, &idx, &length, maxIdx) < 0)
        return ASN_PARSE_E;

    /* extra sanity check that length is greater than 0 */
    if (length <= 0) {
        WOLFSSL_MSG("Error length was 0 in CheckBitString");
        return BUFFER_E;
    }

    if (idx + 1 > maxIdx) {
        WOLFSSL_MSG("Attempted buffer read larger than input buffer");
        return BUFFER_E;
    }

    b = input[idx];
    if (zeroBits && b != 0x00)
        return ASN_EXPECT_0_E;
    if (b >= 0x08)
        return ASN_PARSE_E;
    if (b != 0) {
        if ((byte)(input[idx + length - 1] << (8 - b)) != 0)
            return ASN_PARSE_E;
    }
    idx++;
    length--; /* length has been checked for greater than 0 */

    *inOutIdx = idx;
    if (len != NULL)
        *len = length;
    if (unusedBits != NULL)
        *unusedBits = b;

    return 0;
}

/* Get the DER/BER encoding of an ASN.1 OBJECT_ID header.
 *
 * input     Buffer holding DER/BER encoded data.
 * inOutIdx  Current index into buffer to parse.
 * len       The number of bytes in the ASN.1 data.
 * maxIdx    Length of data in buffer.
 * returns BUFFER_E when there is not enough data to parse.
 *         ASN_OBJECt_ID_E when the OBJECT_ID tag is not found.
 *         ASN_PARSE_E when length is invalid.
 *         Otherwise, 0 to indicate success.
 */
int GetASNObjectId(const byte* input, word32* inOutIdx, int* len,
                          word32 maxIdx)
{
    word32 idx = *inOutIdx;
    byte   b;
    int    length;

    if ((idx + 1) > maxIdx)
        return BUFFER_E;

    b = input[idx++];
    if (b != ASN_OBJECT_ID)
        return ASN_OBJECT_ID_E;

    if (GetLength(input, &idx, &length, maxIdx) < 0)
        return ASN_PARSE_E;

    *len = length;
    *inOutIdx = idx;
    return 0;
}

/* Set the DER/BER encoding of the ASN.1 OBJECT_ID header.
 *
 * len         Length of the OBJECT_ID data.
 * output      Buffer to write into.
 * returns the number of bytes added to the buffer.
 */
int SetObjectId(int len, byte* output)
{
    int idx = 0;

    output[idx++] = ASN_OBJECT_ID;
    idx += SetLength(len, output + idx);

    return idx;
}

static int SkipObjectId(const byte* input, word32* inOutIdx, word32 maxIdx)
{
    word32 idx = *inOutIdx;
    int    length;
    int ret;

    ret = GetASNObjectId(input, &idx, &length, maxIdx);
    if (ret != 0)
        return ret;

    idx += length;
    *inOutIdx = idx;

    return 0;
}

#ifndef NO_RSA

#ifndef HAVE_USER_RSA
int wc_RsaPrivateKeyDecode(const byte* input, word32* inOutIdx, RsaKey* key,
                        word32 inSz)
{
    int version, length;

    if (inOutIdx == NULL) {
        return BAD_FUNC_ARG;
    }
    if (GetSequence(input, inOutIdx, &length, inSz) < 0)
        return ASN_PARSE_E;

    if (GetMyVersion(input, inOutIdx, &version, inSz) < 0)
        return ASN_PARSE_E;

    key->type = RSA_PRIVATE;

    if (GetInt(&key->n,  input, inOutIdx, inSz) < 0 ||
        GetInt(&key->e,  input, inOutIdx, inSz) < 0 ||
#ifndef WOLFSSL_RSA_PUBLIC_ONLY
        GetInt(&key->d,  input, inOutIdx, inSz) < 0 ||
        GetInt(&key->p,  input, inOutIdx, inSz) < 0 ||
        GetInt(&key->q,  input, inOutIdx, inSz) < 0)
#else
        SkipInt(input, inOutIdx, inSz) < 0 ||
        SkipInt(input, inOutIdx, inSz) < 0 ||
        SkipInt(input, inOutIdx, inSz) < 0 )

#endif
            return ASN_RSA_KEY_E;
#if (defined(WOLFSSL_KEY_GEN) || defined(OPENSSL_EXTRA) || !defined(RSA_LOW_MEM)) \
    && !defined(WOLFSSL_RSA_PUBLIC_ONLY)
    if (GetInt(&key->dP, input, inOutIdx, inSz) < 0 ||
        GetInt(&key->dQ, input, inOutIdx, inSz) < 0 ||
        GetInt(&key->u,  input, inOutIdx, inSz) < 0 )  return ASN_RSA_KEY_E;
#else
    if (SkipInt(input, inOutIdx, inSz) < 0 ||
        SkipInt(input, inOutIdx, inSz) < 0 ||
        SkipInt(input, inOutIdx, inSz) < 0 )  return ASN_RSA_KEY_E;
#endif

#if defined(WOLFSSL_XILINX_CRYPT) || defined(WOLFSSL_CRYPTOCELL)
    if (wc_InitRsaHw(key) != 0) {
        return BAD_STATE_E;
    }
#endif

    return 0;
}
#endif /* HAVE_USER_RSA */
#endif /* NO_RSA */

#ifndef NO_RSA

#ifndef HAVE_USER_RSA
int wc_RsaPublicKeyDecode_ex(const byte* input, word32* inOutIdx, word32 inSz,
    const byte** n, word32* nSz, const byte** e, word32* eSz)
{
    int ret = 0;
    int length = 0;
#if defined(OPENSSL_EXTRA) || defined(RSA_DECODE_EXTRA)
    byte b;
#endif

    if (input == NULL || inOutIdx == NULL)
        return BAD_FUNC_ARG;

    if (GetSequence(input, inOutIdx, &length, inSz) < 0)
        return ASN_PARSE_E;

#if defined(OPENSSL_EXTRA) || defined(RSA_DECODE_EXTRA)
    if ((*inOutIdx + 1) > inSz)
        return BUFFER_E;

    b = input[*inOutIdx];
    if (b != ASN_INTEGER) {
        /* not from decoded cert, will have algo id, skip past */
        if (GetSequence(input, inOutIdx, &length, inSz) < 0)
            return ASN_PARSE_E;

        if (SkipObjectId(input, inOutIdx, inSz) < 0)
            return ASN_PARSE_E;

        /* Option NULL ASN.1 tag */
        if (*inOutIdx  >= inSz) {
            return BUFFER_E;
        }
        if (input[*inOutIdx] == ASN_TAG_NULL) {
            ret = GetASNNull(input, inOutIdx, inSz);
            if (ret != 0)
                return ret;
        }

        /* should have bit tag length and seq next */
        ret = CheckBitString(input, inOutIdx, NULL, inSz, 1, NULL);
        if (ret != 0)
            return ret;

        if (GetSequence(input, inOutIdx, &length, inSz) < 0)
            return ASN_PARSE_E;
    }
#endif /* OPENSSL_EXTRA */

    /* Get modulus */
    ret = GetASNInt(input, inOutIdx, &length, inSz);
    if (ret < 0) {
        return ASN_RSA_KEY_E;
    }
    if (nSz)
        *nSz = length;
    if (n)
        *n = &input[*inOutIdx];
    *inOutIdx += length;

    /* Get exponent */
    ret = GetASNInt(input, inOutIdx, &length, inSz);
    if (ret < 0) {
        return ASN_RSA_KEY_E;
    }
    if (eSz)
        *eSz = length;
    if (e)
        *e = &input[*inOutIdx];
    *inOutIdx += length;

    return ret;
}

int wc_RsaPublicKeyDecode(const byte* input, word32* inOutIdx, RsaKey* key,
                       word32 inSz)
{
    int ret;
    const byte *n = NULL, *e = NULL;
    word32 nSz = 0, eSz = 0;

    if (key == NULL)
        return BAD_FUNC_ARG;

    ret = wc_RsaPublicKeyDecode_ex(input, inOutIdx, inSz, &n, &nSz, &e, &eSz);
    if (ret == 0) {
        ret = wc_RsaPublicKeyDecodeRaw(n, nSz, e, eSz, key);
    }

    return ret;
}

/* import RSA public key elements (n, e) into RsaKey structure (key) */
int wc_RsaPublicKeyDecodeRaw(const byte* n, word32 nSz, const byte* e,
                             word32 eSz, RsaKey* key)
{
    if (n == NULL || e == NULL || key == NULL)
        return BAD_FUNC_ARG;

    key->type = RSA_PUBLIC;

    if (mp_init(&key->n) != MP_OKAY)
        return MP_INIT_E;

    if (mp_read_unsigned_bin(&key->n, n, nSz) != 0) {
        mp_clear(&key->n);
        return ASN_GETINT_E;
    }
#ifdef HAVE_WOLF_BIGINT
    if ((int)nSz > 0 && wc_bigint_from_unsigned_bin(&key->n.raw, n, nSz) != 0) {
        mp_clear(&key->n);
        return ASN_GETINT_E;
    }
#endif /* HAVE_WOLF_BIGINT */

    if (mp_init(&key->e) != MP_OKAY) {
        mp_clear(&key->n);
        return MP_INIT_E;
    }

    if (mp_read_unsigned_bin(&key->e, e, eSz) != 0) {
        mp_clear(&key->n);
        mp_clear(&key->e);
        return ASN_GETINT_E;
    }
#ifdef HAVE_WOLF_BIGINT
    if ((int)eSz > 0 && wc_bigint_from_unsigned_bin(&key->e.raw, e, eSz) != 0) {
        mp_clear(&key->n);
        mp_clear(&key->e);
        return ASN_GETINT_E;
    }
#endif /* HAVE_WOLF_BIGINT */

#ifdef WOLFSSL_XILINX_CRYPT
    if (wc_InitRsaHw(key) != 0) {
        return BAD_STATE_E;
    }
#endif

    return 0;
}
static word32 BytePrecision(word32 value)
{
    word32 i;
    for (i = sizeof(value); i; --i)
        if (value >> ((i - 1) * WOLFSSL_BIT_SIZE))
            break;

    return i;
}


WOLFSSL_LOCAL word32 SetLength(word32 length, byte* output)
{
    word32 i = 0, j;

    if (length < ASN_LONG_LENGTH)
        output[i++] = (byte)length;
    else {
        output[i++] = (byte)(BytePrecision(length) | ASN_LONG_LENGTH);

        for (j = BytePrecision(length); j; --j) {
            output[i] = (byte)(length >> ((j - 1) * WOLFSSL_BIT_SIZE));
            i++;
        }
    }

    return i;
}
#endif /* HAVE_USER_RSA */
#endif /* !NO_RSA */

#ifdef HAVE_ECC


/* hashType */
#ifdef WOLFSSL_MD2
    static const byte hashMd2hOid[] = {42, 134, 72, 134, 247, 13, 2, 2};
#endif
#ifndef NO_MD5
    static const byte hashMd5hOid[] = {42, 134, 72, 134, 247, 13, 2, 5};
#endif
#ifndef NO_SHA
    static const byte hashSha1hOid[] = {43, 14, 3, 2, 26};
#endif
#ifdef WOLFSSL_SHA224
    static const byte hashSha224hOid[] = {96, 134, 72, 1, 101, 3, 4, 2, 4};
#endif
#ifndef NO_SHA256
    static const byte hashSha256hOid[] = {96, 134, 72, 1, 101, 3, 4, 2, 1};
#endif
#ifdef WOLFSSL_SHA384
    static const byte hashSha384hOid[] = {96, 134, 72, 1, 101, 3, 4, 2, 2};
#endif
#ifdef WOLFSSL_SHA512
    static const byte hashSha512hOid[] = {96, 134, 72, 1, 101, 3, 4, 2, 3};
#endif

/* hmacType */
#ifndef NO_HMAC
    #ifdef WOLFSSL_SHA224
    static const byte hmacSha224Oid[] = {42, 134, 72, 134, 247, 13, 2, 8};
    #endif
    #ifndef NO_SHA256
    static const byte hmacSha256Oid[] = {42, 134, 72, 134, 247, 13, 2, 9};
    #endif
    #ifdef WOLFSSL_SHA384
    static const byte hmacSha384Oid[] = {42, 134, 72, 134, 247, 13, 2, 10};
    #endif
    #ifdef WOLFSSL_SHA512
    static const byte hmacSha512Oid[] = {42, 134, 72, 134, 247, 13, 2, 11};
    #endif
#endif

/* sigType */
#if !defined(NO_DSA) && !defined(NO_SHA)
    static const byte sigSha1wDsaOid[] = {42, 134, 72, 206, 56, 4, 3};
#endif /* NO_DSA */
#ifndef NO_RSA
    #ifdef WOLFSSL_MD2
    static const byte sigMd2wRsaOid[] = {42, 134, 72, 134, 247, 13, 1, 1, 2};
    #endif
    #ifndef NO_MD5
    static const byte sigMd5wRsaOid[] = {42, 134, 72, 134, 247, 13, 1, 1, 4};
    #endif
    #ifndef NO_SHA
    static const byte sigSha1wRsaOid[] = {42, 134, 72, 134, 247, 13, 1, 1, 5};
    #endif
    #ifdef WOLFSSL_SHA224
    static const byte sigSha224wRsaOid[] = {42, 134, 72, 134, 247, 13, 1, 1,14};
    #endif
    #ifndef NO_SHA256
    static const byte sigSha256wRsaOid[] = {42, 134, 72, 134, 247, 13, 1, 1,11};
    #endif
    #ifdef WOLFSSL_SHA384
    static const byte sigSha384wRsaOid[] = {42, 134, 72, 134, 247, 13, 1, 1,12};
    #endif
    #ifdef WOLFSSL_SHA512
    static const byte sigSha512wRsaOid[] = {42, 134, 72, 134, 247, 13, 1, 1,13};
    #endif
#endif /* NO_RSA */
#ifdef HAVE_ECC
    #ifndef NO_SHA
    static const byte sigSha1wEcdsaOid[] = {42, 134, 72, 206, 61, 4, 1};
    #endif
    #ifdef WOLFSSL_SHA224
    static const byte sigSha224wEcdsaOid[] = {42, 134, 72, 206, 61, 4, 3, 1};
    #endif
    #ifndef NO_SHA256
    static const byte sigSha256wEcdsaOid[] = {42, 134, 72, 206, 61, 4, 3, 2};
    #endif
    #ifdef WOLFSSL_SHA384
    static const byte sigSha384wEcdsaOid[] = {42, 134, 72, 206, 61, 4, 3, 3};
    #endif
    #ifdef WOLFSSL_SHA512
    static const byte sigSha512wEcdsaOid[] = {42, 134, 72, 206, 61, 4, 3, 4};
    #endif
#endif /* HAVE_ECC */
#ifdef HAVE_ED25519
    static const byte sigEd25519Oid[] = {43, 101, 112};
#endif /* HAVE_ED25519 */

/* keyType */
#ifndef NO_DSA
    static const byte keyDsaOid[] = {42, 134, 72, 206, 56, 4, 1};
#endif /* NO_DSA */
#ifndef NO_RSA
    static const byte keyRsaOid[] = {42, 134, 72, 134, 247, 13, 1, 1, 1};
#endif /* NO_RSA */
#ifdef HAVE_NTRU
    static const byte keyNtruOid[] = {43, 6, 1, 4, 1, 193, 22, 1, 1, 1, 1};
#endif /* HAVE_NTRU */
#ifdef HAVE_ECC
    static const byte keyEcdsaOid[] = {42, 134, 72, 206, 61, 2, 1};
#endif /* HAVE_ECC */
#ifdef HAVE_ED25519
    static const byte keyEd25519Oid[] = {43, 101, 112};
#endif /* HAVE_ED25519 */

/* curveType */
#ifdef HAVE_ECC
    /* See "ecc_sets" table in ecc.c */
#endif /* HAVE_ECC */

#ifdef HAVE_AES_CBC
/* blkType */
    #ifdef WOLFSSL_AES_128
    static const byte blkAes128CbcOid[] = {96, 134, 72, 1, 101, 3, 4, 1, 2};
    #endif
    #ifdef WOLFSSL_AES_192
    static const byte blkAes192CbcOid[] = {96, 134, 72, 1, 101, 3, 4, 1, 22};
    #endif
    #ifdef WOLFSSL_AES_256
    static const byte blkAes256CbcOid[] = {96, 134, 72, 1, 101, 3, 4, 1, 42};
    #endif
#endif /* HAVE_AES_CBC */
#ifdef HAVE_AESGCM
    #ifdef WOLFSSL_AES_128
    static const byte blkAes128GcmOid[] = {96, 134, 72, 1, 101, 3, 4, 1, 6};
    #endif
    #ifdef WOLFSSL_AES_192
    static const byte blkAes192GcmOid[] = {96, 134, 72, 1, 101, 3, 4, 1, 26};
    #endif
    #ifdef WOLFSSL_AES_256
    static const byte blkAes256GcmOid[] = {96, 134, 72, 1, 101, 3, 4, 1, 46};
    #endif
#endif /* HAVE_AESGCM */
#ifdef HAVE_AESCCM
    #ifdef WOLFSSL_AES_128
    static const byte blkAes128CcmOid[] = {96, 134, 72, 1, 101, 3, 4, 1, 7};
    #endif
    #ifdef WOLFSSL_AES_192
    static const byte blkAes192CcmOid[] = {96, 134, 72, 1, 101, 3, 4, 1, 27};
    #endif
    #ifdef WOLFSSL_AES_256
    static const byte blkAes256CcmOid[] = {96, 134, 72, 1, 101, 3, 4, 1, 47};
    #endif
#endif /* HAVE_AESCCM */

#ifndef NO_DES3
    static const byte blkDesCbcOid[]  = {43, 14, 3, 2, 7};
    static const byte blkDes3CbcOid[] = {42, 134, 72, 134, 247, 13, 3, 7};
#endif

/* keyWrapType */
#ifdef WOLFSSL_AES_128
    static const byte wrapAes128Oid[] = {96, 134, 72, 1, 101, 3, 4, 1, 5};
#endif
#ifdef WOLFSSL_AES_192
    static const byte wrapAes192Oid[] = {96, 134, 72, 1, 101, 3, 4, 1, 25};
#endif
#ifdef WOLFSSL_AES_256
    static const byte wrapAes256Oid[] = {96, 134, 72, 1, 101, 3, 4, 1, 45};
#endif
#ifdef HAVE_PKCS7
/* From RFC 3211 */
static const byte wrapPwriKekOid[] = {42, 134, 72, 134, 247, 13, 1, 9, 16, 3,9};
#endif

/* cmsKeyAgreeType */
#ifndef NO_SHA
    static const byte dhSinglePass_stdDH_sha1kdf_Oid[]   =
                                          {43, 129, 5, 16, 134, 72, 63, 0, 2};
#endif
#ifdef WOLFSSL_SHA224
    static const byte dhSinglePass_stdDH_sha224kdf_Oid[] = {43, 129, 4, 1, 11, 0};
#endif
#ifndef NO_SHA256
    static const byte dhSinglePass_stdDH_sha256kdf_Oid[] = {43, 129, 4, 1, 11, 1};
#endif
#ifdef WOLFSSL_SHA384
    static const byte dhSinglePass_stdDH_sha384kdf_Oid[] = {43, 129, 4, 1, 11, 2};
#endif
#ifdef WOLFSSL_SHA512
    static const byte dhSinglePass_stdDH_sha512kdf_Oid[] = {43, 129, 4, 1, 11, 3};
#endif

/* ocspType */
#ifdef HAVE_OCSP
    static const byte ocspBasicOid[] = {43, 6, 1, 5, 5, 7, 48, 1, 1};
    static const byte ocspNonceOid[] = {43, 6, 1, 5, 5, 7, 48, 1, 2};
#endif /* HAVE_OCSP */

/* certExtType */
static const byte extBasicCaOid[] = {85, 29, 19};
static const byte extAltNamesOid[] = {85, 29, 17};
static const byte extCrlDistOid[] = {85, 29, 31};
static const byte extAuthInfoOid[] = {43, 6, 1, 5, 5, 7, 1, 1};
static const byte extAuthKeyOid[] = {85, 29, 35};
static const byte extSubjKeyOid[] = {85, 29, 14};
static const byte extCertPolicyOid[] = {85, 29, 32};
static const byte extKeyUsageOid[] = {85, 29, 15};
static const byte extInhibitAnyOid[] = {85, 29, 54};
static const byte extExtKeyUsageOid[] = {85, 29, 37};
#ifndef IGNORE_NAME_CONSTRAINTS
    static const byte extNameConsOid[] = {85, 29, 30};
#endif

/* certAuthInfoType */
#ifdef HAVE_OCSP
    static const byte extAuthInfoOcspOid[] = {43, 6, 1, 5, 5, 7, 48, 1};
#endif
static const byte extAuthInfoCaIssuerOid[] = {43, 6, 1, 5, 5, 7, 48, 2};

/* certPolicyType */
static const byte extCertPolicyAnyOid[] = {85, 29, 32, 0};

/* certKeyUseType */
static const byte extAltNamesHwNameOid[] = {43, 6, 1, 5, 5, 7, 8, 4};

/* certKeyUseType */
static const byte extExtKeyUsageAnyOid[] = {85, 29, 37, 0};
static const byte extExtKeyUsageServerAuthOid[]   = {43, 6, 1, 5, 5, 7, 3, 1};
static const byte extExtKeyUsageClientAuthOid[]   = {43, 6, 1, 5, 5, 7, 3, 2};
static const byte extExtKeyUsageCodeSigningOid[]  = {43, 6, 1, 5, 5, 7, 3, 3};
static const byte extExtKeyUsageEmailProtectOid[] = {43, 6, 1, 5, 5, 7, 3, 4};
static const byte extExtKeyUsageTimestampOid[]    = {43, 6, 1, 5, 5, 7, 3, 8};
static const byte extExtKeyUsageOcspSignOid[]     = {43, 6, 1, 5, 5, 7, 3, 9};

/* kdfType */
static const byte pbkdf2Oid[] = {42, 134, 72, 134, 247, 13, 1, 5, 12};

/* PKCS5 */
#if !defined(NO_DES3) && !defined(NO_SHA)
static const byte pbeSha1Des[] = {42, 134, 72, 134, 247, 13, 1, 5, 10};
#endif
static const byte pbes2[] = {42, 134, 72, 134, 247, 13, 1, 5, 13};

/* PKCS12 */
#if !defined(NO_RC4) && !defined(NO_SHA)
static const byte pbeSha1RC4128[] = {42, 134, 72, 134, 247, 13, 1, 12, 1, 1};
#endif
#if !defined(NO_DES3) && !defined(NO_SHA)
static const byte pbeSha1Des3[] = {42, 134, 72, 134, 247, 13, 1, 12, 1, 3};
#endif

#ifdef HAVE_LIBZ
/* zlib compression */
static const byte zlibCompress[] = {42, 134, 72, 134, 247, 13, 1, 9, 16, 3, 8};
#endif
#ifdef WOLFSSL_APACHE_HTTPD
/* tlsExtType */
static const byte tlsFeatureOid[] = {43, 6, 1, 5, 5, 7, 1, 24};
/* certNameType */
static const byte dnsSRVOid[] = {43, 6, 1, 5, 5, 7, 8, 7};
#endif


/* returns a pointer to the OID string on success and NULL on fail */
const byte* OidFromId(word32 id, word32 type, word32* oidSz)
{
    const byte* oid = NULL;

    *oidSz = 0;

    switch (type) {

        case oidHashType:
            switch (id) {
            #ifdef WOLFSSL_MD2
                case MD2h:
                    oid = hashMd2hOid;
                    *oidSz = sizeof(hashMd2hOid);
                    break;
            #endif
            #ifndef NO_MD5
                case MD5h:
                    oid = hashMd5hOid;
                    *oidSz = sizeof(hashMd5hOid);
                    break;
            #endif
            #ifndef NO_SHA
                case SHAh:
                    oid = hashSha1hOid;
                    *oidSz = sizeof(hashSha1hOid);
                    break;
            #endif
            #ifdef WOLFSSL_SHA224
                case SHA224h:
                    oid = hashSha224hOid;
                    *oidSz = sizeof(hashSha224hOid);
                    break;
            #endif
            #ifndef NO_SHA256
                case SHA256h:
                    oid = hashSha256hOid;
                    *oidSz = sizeof(hashSha256hOid);
                    break;
            #endif
            #ifdef WOLFSSL_SHA384
                case SHA384h:
                    oid = hashSha384hOid;
                    *oidSz = sizeof(hashSha384hOid);
                    break;
            #endif
            #ifdef WOLFSSL_SHA512
                case SHA512h:
                    oid = hashSha512hOid;
                    *oidSz = sizeof(hashSha512hOid);
                    break;
            #endif
            }
            break;

        case oidSigType:
            switch (id) {
                #if !defined(NO_DSA) && !defined(NO_SHA)
                case CTC_SHAwDSA:
                    oid = sigSha1wDsaOid;
                    *oidSz = sizeof(sigSha1wDsaOid);
                    break;
                #endif /* NO_DSA */
                #ifndef NO_RSA
                #ifdef WOLFSSL_MD2
                case CTC_MD2wRSA:
                    oid = sigMd2wRsaOid;
                    *oidSz = sizeof(sigMd2wRsaOid);
                    break;
                #endif
                #ifndef NO_MD5
                case CTC_MD5wRSA:
                    oid = sigMd5wRsaOid;
                    *oidSz = sizeof(sigMd5wRsaOid);
                    break;
                #endif
                #ifndef NO_SHA
                case CTC_SHAwRSA:
                    oid = sigSha1wRsaOid;
                    *oidSz = sizeof(sigSha1wRsaOid);
                    break;
                #endif
                #ifdef WOLFSSL_SHA224
                case CTC_SHA224wRSA:
                    oid = sigSha224wRsaOid;
                    *oidSz = sizeof(sigSha224wRsaOid);
                    break;
                #endif
                #ifndef NO_SHA256
                case CTC_SHA256wRSA:
                    oid = sigSha256wRsaOid;
                    *oidSz = sizeof(sigSha256wRsaOid);
                    break;
                #endif
                #ifdef WOLFSSL_SHA384
                case CTC_SHA384wRSA:
                    oid = sigSha384wRsaOid;
                    *oidSz = sizeof(sigSha384wRsaOid);
                    break;
                #endif
                #ifdef WOLFSSL_SHA512
                case CTC_SHA512wRSA:
                    oid = sigSha512wRsaOid;
                    *oidSz = sizeof(sigSha512wRsaOid);
                    break;
                #endif /* WOLFSSL_SHA512 */
                #endif /* NO_RSA */
                #ifdef HAVE_ECC
                #ifndef NO_SHA
                case CTC_SHAwECDSA:
                    oid = sigSha1wEcdsaOid;
                    *oidSz = sizeof(sigSha1wEcdsaOid);
                    break;
                #endif
                #ifdef WOLFSSL_SHA224
                case CTC_SHA224wECDSA:
                    oid = sigSha224wEcdsaOid;
                    *oidSz = sizeof(sigSha224wEcdsaOid);
                    break;
                #endif
                #ifndef NO_SHA256
                case CTC_SHA256wECDSA:
                    oid = sigSha256wEcdsaOid;
                    *oidSz = sizeof(sigSha256wEcdsaOid);
                    break;
                #endif
                #ifdef WOLFSSL_SHA384
                case CTC_SHA384wECDSA:
                    oid = sigSha384wEcdsaOid;
                    *oidSz = sizeof(sigSha384wEcdsaOid);
                    break;
                #endif
                #ifdef WOLFSSL_SHA512
                case CTC_SHA512wECDSA:
                    oid = sigSha512wEcdsaOid;
                    *oidSz = sizeof(sigSha512wEcdsaOid);
                    break;
                #endif
                #endif /* HAVE_ECC */
                #ifdef HAVE_ED25519
                case CTC_ED25519:
                    oid = sigEd25519Oid;
                    *oidSz = sizeof(sigEd25519Oid);
                    break;
                #endif
                default:
                    break;
            }
            break;

        case oidKeyType:
            switch (id) {
                #ifndef NO_DSA
                case DSAk:
                    oid = keyDsaOid;
                    *oidSz = sizeof(keyDsaOid);
                    break;
                #endif /* NO_DSA */
                #ifndef NO_RSA
                case RSAk:
                    oid = keyRsaOid;
                    *oidSz = sizeof(keyRsaOid);
                    break;
                #endif /* NO_RSA */
                #ifdef HAVE_NTRU
                case NTRUk:
                    oid = keyNtruOid;
                    *oidSz = sizeof(keyNtruOid);
                    break;
                #endif /* HAVE_NTRU */
                #ifdef HAVE_ECC
                case ECDSAk:
                    oid = keyEcdsaOid;
                    *oidSz = sizeof(keyEcdsaOid);
                    break;
                #endif /* HAVE_ECC */
                #ifdef HAVE_ED25519
                case ED25519k:
                    oid = keyEd25519Oid;
                    *oidSz = sizeof(keyEd25519Oid);
                    break;
                #endif /* HAVE_ED25519 */
                default:
                    break;
            }
            break;

        #ifdef HAVE_ECC
        case oidCurveType:
            if (wc_ecc_get_oid(id, &oid, oidSz) < 0) {
                WOLFSSL_MSG("ECC OID not found");
            }
            break;
        #endif /* HAVE_ECC */

        case oidBlkType:
            switch (id) {
    #ifdef HAVE_AES_CBC
        #ifdef WOLFSSL_AES_128
                case AES128CBCb:
                    oid = blkAes128CbcOid;
                    *oidSz = sizeof(blkAes128CbcOid);
                    break;
        #endif
        #ifdef WOLFSSL_AES_192
                case AES192CBCb:
                    oid = blkAes192CbcOid;
                    *oidSz = sizeof(blkAes192CbcOid);
                    break;
        #endif
        #ifdef WOLFSSL_AES_256
                case AES256CBCb:
                    oid = blkAes256CbcOid;
                    *oidSz = sizeof(blkAes256CbcOid);
                    break;
        #endif
    #endif /* HAVE_AES_CBC */
    #ifdef HAVE_AESGCM
        #ifdef WOLFSSL_AES_128
                case AES128GCMb:
                    oid = blkAes128GcmOid;
                    *oidSz = sizeof(blkAes128GcmOid);
                    break;
        #endif
        #ifdef WOLFSSL_AES_192
                case AES192GCMb:
                    oid = blkAes192GcmOid;
                    *oidSz = sizeof(blkAes192GcmOid);
                    break;
        #endif
        #ifdef WOLFSSL_AES_256
                case AES256GCMb:
                    oid = blkAes256GcmOid;
                    *oidSz = sizeof(blkAes256GcmOid);
                    break;
        #endif
    #endif /* HAVE_AESGCM */
    #ifdef HAVE_AESCCM
        #ifdef WOLFSSL_AES_128
                case AES128CCMb:
                    oid = blkAes128CcmOid;
                    *oidSz = sizeof(blkAes128CcmOid);
                    break;
        #endif
        #ifdef WOLFSSL_AES_192
                case AES192CCMb:
                    oid = blkAes192CcmOid;
                    *oidSz = sizeof(blkAes192CcmOid);
                    break;
        #endif
        #ifdef WOLFSSL_AES_256
                case AES256CCMb:
                    oid = blkAes256CcmOid;
                    *oidSz = sizeof(blkAes256CcmOid);
                    break;
        #endif
    #endif /* HAVE_AESCCM */
    #ifndef NO_DES3
                case DESb:
                    oid = blkDesCbcOid;
                    *oidSz = sizeof(blkDesCbcOid);
                    break;
                case DES3b:
                    oid = blkDes3CbcOid;
                    *oidSz = sizeof(blkDes3CbcOid);
                    break;
    #endif /* !NO_DES3 */
            }
            break;

        #ifdef HAVE_OCSP
        case oidOcspType:
            switch (id) {
                case OCSP_BASIC_OID:
                    oid = ocspBasicOid;
                    *oidSz = sizeof(ocspBasicOid);
                    break;
                case OCSP_NONCE_OID:
                    oid = ocspNonceOid;
                    *oidSz = sizeof(ocspNonceOid);
                    break;
            }
            break;
        #endif /* HAVE_OCSP */

        case oidCertExtType:
            switch (id) {
                case BASIC_CA_OID:
                    oid = extBasicCaOid;
                    *oidSz = sizeof(extBasicCaOid);
                    break;
                case ALT_NAMES_OID:
                    oid = extAltNamesOid;
                    *oidSz = sizeof(extAltNamesOid);
                    break;
                case CRL_DIST_OID:
                    oid = extCrlDistOid;
                    *oidSz = sizeof(extCrlDistOid);
                    break;
                case AUTH_INFO_OID:
                    oid = extAuthInfoOid;
                    *oidSz = sizeof(extAuthInfoOid);
                    break;
                case AUTH_KEY_OID:
                    oid = extAuthKeyOid;
                    *oidSz = sizeof(extAuthKeyOid);
                    break;
                case SUBJ_KEY_OID:
                    oid = extSubjKeyOid;
                    *oidSz = sizeof(extSubjKeyOid);
                    break;
                case CERT_POLICY_OID:
                    oid = extCertPolicyOid;
                    *oidSz = sizeof(extCertPolicyOid);
                    break;
                case KEY_USAGE_OID:
                    oid = extKeyUsageOid;
                    *oidSz = sizeof(extKeyUsageOid);
                    break;
                case INHIBIT_ANY_OID:
                    oid = extInhibitAnyOid;
                    *oidSz = sizeof(extInhibitAnyOid);
                    break;
                case EXT_KEY_USAGE_OID:
                    oid = extExtKeyUsageOid;
                    *oidSz = sizeof(extExtKeyUsageOid);
                    break;
            #ifndef IGNORE_NAME_CONSTRAINTS
                case NAME_CONS_OID:
                    oid = extNameConsOid;
                    *oidSz = sizeof(extNameConsOid);
                    break;
            #endif
            }
            break;

        case oidCertAuthInfoType:
            switch (id) {
            #ifdef HAVE_OCSP
                case AIA_OCSP_OID:
                    oid = extAuthInfoOcspOid;
                    *oidSz = sizeof(extAuthInfoOcspOid);
                    break;
            #endif
                case AIA_CA_ISSUER_OID:
                    oid = extAuthInfoCaIssuerOid;
                    *oidSz = sizeof(extAuthInfoCaIssuerOid);
                    break;
            }
            break;

        case oidCertPolicyType:
            switch (id) {
                case CP_ANY_OID:
                    oid = extCertPolicyAnyOid;
                    *oidSz = sizeof(extCertPolicyAnyOid);
                    break;
            }
            break;

        case oidCertAltNameType:
            switch (id) {
                case HW_NAME_OID:
                    oid = extAltNamesHwNameOid;
                    *oidSz = sizeof(extAltNamesHwNameOid);
                    break;
            }
            break;

        case oidCertKeyUseType:
            switch (id) {
                case EKU_ANY_OID:
                    oid = extExtKeyUsageAnyOid;
                    *oidSz = sizeof(extExtKeyUsageAnyOid);
                    break;
                case EKU_SERVER_AUTH_OID:
                    oid = extExtKeyUsageServerAuthOid;
                    *oidSz = sizeof(extExtKeyUsageServerAuthOid);
                    break;
                case EKU_CLIENT_AUTH_OID:
                    oid = extExtKeyUsageClientAuthOid;
                    *oidSz = sizeof(extExtKeyUsageClientAuthOid);
                    break;
                case EKU_CODESIGNING_OID:
                    oid = extExtKeyUsageCodeSigningOid;
                    *oidSz = sizeof(extExtKeyUsageCodeSigningOid);
                    break;
                case EKU_EMAILPROTECT_OID:
                    oid = extExtKeyUsageEmailProtectOid;
                    *oidSz = sizeof(extExtKeyUsageEmailProtectOid);
                    break;
                case EKU_TIMESTAMP_OID:
                    oid = extExtKeyUsageTimestampOid;
                    *oidSz = sizeof(extExtKeyUsageTimestampOid);
                    break;
                case EKU_OCSP_SIGN_OID:
                    oid = extExtKeyUsageOcspSignOid;
                    *oidSz = sizeof(extExtKeyUsageOcspSignOid);
                    break;
            }
            break;

        case oidKdfType:
            switch (id) {
                case PBKDF2_OID:
                    oid = pbkdf2Oid;
                    *oidSz = sizeof(pbkdf2Oid);
                    break;
            }
            break;

        case oidPBEType:
            switch (id) {
        #if !defined(NO_SHA) && !defined(NO_RC4)
                case PBE_SHA1_RC4_128:
                    oid = pbeSha1RC4128;
                    *oidSz = sizeof(pbeSha1RC4128);
                    break;
        #endif
        #if !defined(NO_SHA) && !defined(NO_DES3)
                case PBE_SHA1_DES:
                    oid = pbeSha1Des;
                    *oidSz = sizeof(pbeSha1Des);
                    break;

        #endif
        #if !defined(NO_SHA) && !defined(NO_DES3)
                case PBE_SHA1_DES3:
                    oid = pbeSha1Des3;
                    *oidSz = sizeof(pbeSha1Des3);
                    break;
        #endif
                case PBES2:
                    oid = pbes2;
                    *oidSz = sizeof(pbes2);
                    break;
            }
            break;

        case oidKeyWrapType:
            switch (id) {
            #ifdef WOLFSSL_AES_128
                case AES128_WRAP:
                    oid = wrapAes128Oid;
                    *oidSz = sizeof(wrapAes128Oid);
                    break;
            #endif
            #ifdef WOLFSSL_AES_192
                case AES192_WRAP:
                    oid = wrapAes192Oid;
                    *oidSz = sizeof(wrapAes192Oid);
                    break;
            #endif
            #ifdef WOLFSSL_AES_256
                case AES256_WRAP:
                    oid = wrapAes256Oid;
                    *oidSz = sizeof(wrapAes256Oid);
                    break;
            #endif
            #ifdef HAVE_PKCS7
                case PWRI_KEK_WRAP:
                    oid = wrapPwriKekOid;
                    *oidSz = sizeof(wrapPwriKekOid);
                    break;
            #endif
            }
            break;

        case oidCmsKeyAgreeType:
            switch (id) {
            #ifndef NO_SHA
                case dhSinglePass_stdDH_sha1kdf_scheme:
                    oid = dhSinglePass_stdDH_sha1kdf_Oid;
                    *oidSz = sizeof(dhSinglePass_stdDH_sha1kdf_Oid);
                    break;
            #endif
            #ifdef WOLFSSL_SHA224
                case dhSinglePass_stdDH_sha224kdf_scheme:
                    oid = dhSinglePass_stdDH_sha224kdf_Oid;
                    *oidSz = sizeof(dhSinglePass_stdDH_sha224kdf_Oid);
                    break;
            #endif
            #ifndef NO_SHA256
                case dhSinglePass_stdDH_sha256kdf_scheme:
                    oid = dhSinglePass_stdDH_sha256kdf_Oid;
                    *oidSz = sizeof(dhSinglePass_stdDH_sha256kdf_Oid);
                    break;
            #endif
            #ifdef WOLFSSL_SHA384
                case dhSinglePass_stdDH_sha384kdf_scheme:
                    oid = dhSinglePass_stdDH_sha384kdf_Oid;
                    *oidSz = sizeof(dhSinglePass_stdDH_sha384kdf_Oid);
                    break;
            #endif
            #ifdef WOLFSSL_SHA512
                case dhSinglePass_stdDH_sha512kdf_scheme:
                    oid = dhSinglePass_stdDH_sha512kdf_Oid;
                    *oidSz = sizeof(dhSinglePass_stdDH_sha512kdf_Oid);
                    break;
            #endif
            }
            break;

#ifndef NO_HMAC
        case oidHmacType:
            switch (id) {
        #ifdef WOLFSSL_SHA224
                case HMAC_SHA224_OID:
                    oid = hmacSha224Oid;
                    *oidSz = sizeof(hmacSha224Oid);
                    break;
        #endif
        #ifndef NO_SHA256
                case HMAC_SHA256_OID:
                    oid = hmacSha256Oid;
                    *oidSz = sizeof(hmacSha256Oid);
                    break;
        #endif
        #ifdef WOLFSSL_SHA384
                case HMAC_SHA384_OID:
                    oid = hmacSha384Oid;
                    *oidSz = sizeof(hmacSha384Oid);
                    break;
        #endif
        #ifdef WOLFSSL_SHA512
                case HMAC_SHA512_OID:
                    oid = hmacSha512Oid;
                    *oidSz = sizeof(hmacSha512Oid);
                    break;
        #endif
            }
            break;
#endif /* !NO_HMAC */

#ifdef HAVE_LIBZ
        case oidCompressType:
            switch (id) {
                case ZLIBc:
                    oid = zlibCompress;
                    *oidSz = sizeof(zlibCompress);
                    break;
            }
            break;
#endif /* HAVE_LIBZ */
#ifdef WOLFSSL_APACHE_HTTPD
        case oidCertNameType:
            switch (id) {
                 case NID_id_on_dnsSRV:
                    oid = dnsSRVOid;
                    *oidSz = sizeof(dnsSRVOid);
                    break;
            }
            break;
        case oidTlsExtType:
            switch (id) {
                case TLS_FEATURE_OID:
                    oid = tlsFeatureOid;
                    *oidSz = sizeof(tlsFeatureOid);
                    break;
            }
            break;
#endif /* WOLFSSL_APACHE_HTTPD */
        case oidIgnoreType:
        default:
            break;
    }

    return oid;
}

int GetObjectId(const byte* input, word32* inOutIdx, word32* oid,
                                  word32 oidType, word32 maxIdx)
{
    int    ret = 0, length;
    word32 idx = *inOutIdx;
#ifndef NO_VERIFY_OID
    word32 actualOidSz = 0;
    const byte* actualOid;
#endif /* NO_VERIFY_OID */

    (void)oidType;
    WOLFSSL_ENTER("GetObjectId()");
    *oid = 0;

    ret = GetASNObjectId(input, &idx, &length, maxIdx);
    if (ret != 0)
        return ret;

#ifndef NO_VERIFY_OID
    actualOid = &input[idx];
    if (length > 0)
        actualOidSz = (word32)length;
#endif /* NO_VERIFY_OID */

    while (length--) {
        /* odd HC08 compiler behavior here when input[idx++] */
        *oid += (word32)input[idx];
        idx++;
    }
    /* just sum it up for now */

    *inOutIdx = idx;

#ifndef NO_VERIFY_OID
    {
        const byte* checkOid = NULL;
        word32 checkOidSz;
    #ifdef ASN_DUMP_OID
        word32 i;
    #endif

        if (oidType != oidIgnoreType) {
            checkOid = OidFromId(*oid, oidType, &checkOidSz);

        #ifdef ASN_DUMP_OID
            /* support for dumping OID information */
            printf("OID (Type %d, Sz %d, Sum %d): ", oidType, actualOidSz, *oid);
            for (i=0; i<actualOidSz; i++) {
                printf("%d, ", actualOid[i]);
            }
            printf("\n");
            #ifdef HAVE_OID_DECODING
            {
                word16 decOid[16];
                word32 decOidSz = sizeof(decOid);
                ret = DecodeObjectId(actualOid, actualOidSz, decOid, &decOidSz);
                if (ret == 0) {
                    printf("  Decoded (Sz %d): ", decOidSz);
                    for (i=0; i<decOidSz; i++) {
                        printf("%d.", decOid[i]);
                    }
                    printf("\n");
                }
                else {
                    printf("DecodeObjectId failed: %d\n", ret);
                }
            }
            #endif /* HAVE_OID_DECODING */
        #endif /* ASN_DUMP_OID */

            if (checkOid != NULL &&
                (checkOidSz != actualOidSz ||
                    XMEMCMP(actualOid, checkOid, checkOidSz) != 0)) {
                WOLFSSL_MSG("OID Check Failed");
                return ASN_UNKNOWN_OID_E;
            }
        }
    }
#endif /* NO_VERIFY_OID */

    return ret;
}
/* return 0 on success if the ECC curve oid sum is supported */
static int CheckCurve(word32 oid)
{
    int ret = 0;
    word32 oidSz = 0;

    ret = wc_ecc_get_oid(oid, NULL, &oidSz);
    if (ret < 0 || oidSz <= 0) {
        WOLFSSL_MSG("CheckCurve not found");
        ret = ALGO_ID_E;
    }

    return ret;
}

/* Set the DER/BER encoding of the ASN.1 INTEGER header.
 *
 * len        Length of data to encode.
 * firstByte  First byte of data, most significant byte of integer, to encode.
 * output     Buffer to write into.
 * returns the number of bytes added to the buffer.
 */
static int SetASNInt(int len, byte firstByte, byte* output)
{
    word32 idx = 0;

    if (output)
        output[idx] = ASN_INTEGER;
    idx++;
    if (firstByte & 0x80)
        len++;
    idx += SetLength(len, output ? output + idx : NULL);
    if (firstByte & 0x80) {
        if (output)
            output[idx] = 0x00;
        idx++;
    }

    return idx;
}

/* Set the DER/BER encoding of the ASN.1 INTEGER element with an mp_int.
 * The number is assumed to be positive.
 *
 * n       Multi-precision integer to encode.
 * maxSz   Maximum size of the encoded integer.
 *         A negative value indicates no check of length requested.
 * output  Buffer to write into.
 * returns BUFFER_E when the data is too long for the buffer.
 *         MP_TO_E when encoding the integer fails.
 *         Otherwise, the number of bytes added to the buffer.
 */
static int SetASNIntMP(mp_int* n, int maxSz, byte* output)
{
    int idx = 0;
    int leadingBit;
    int length;
    int err;

    leadingBit = mp_leading_bit(n);
    length = mp_unsigned_bin_size(n);
    idx = SetASNInt(length, leadingBit ? 0x80 : 0x00, output);
    if (maxSz >= 0 && (idx + length) > maxSz)
        return BUFFER_E;

    if (output) {
        err = mp_to_unsigned_bin(n, output + idx);
        if (err != MP_OKAY)
            return MP_TO_E;
    }
    idx += length;

    return idx;
}

WOLFSSL_LOCAL word32 SetSequence(word32 len, byte* output)
{
    if (output)
        output[0] = ASN_SEQUENCE | ASN_CONSTRUCTED;
    return SetLength(len, output ? output + 1 : NULL) + 1;
}

/* Der Encode r & s ints into out, outLen is (in/out) size */
int StoreECC_DSA_Sig(byte* out, word32* outLen, mp_int* r, mp_int* s)
{
    word32 idx = 0;
    int    rSz;                           /* encoding size */
    int    sSz;
    word32 headerSz = 4;   /* 2*ASN_TAG + 2*LEN(ENUM) */

    /* If the leading bit on the INTEGER is a 1, add a leading zero */
    int rLeadingZero = mp_leading_bit(r);
    int sLeadingZero = mp_leading_bit(s);
    int rLen = mp_unsigned_bin_size(r);   /* big int size */
    int sLen = mp_unsigned_bin_size(s);

    if (*outLen < (rLen + rLeadingZero + sLen + sLeadingZero +
                   headerSz + 2))  /* SEQ_TAG + LEN(ENUM) */
        return BUFFER_E;

    idx = SetSequence(rLen + rLeadingZero + sLen+sLeadingZero + headerSz, out);

    /* store r */
    rSz = SetASNIntMP(r, -1, &out[idx]);
    if (rSz < 0)
        return rSz;
    idx += rSz;

    /* store s */
    sSz = SetASNIntMP(s, -1, &out[idx]);
    if (sSz < 0)
        return sSz;
    idx += sSz;

    *outLen = idx;

    return 0;
}


/* Der Decode ECC-DSA Signature, r & s stored as big ints */
int DecodeECC_DSA_Sig(const byte* sig, word32 sigLen, mp_int* r, mp_int* s)
{
    word32 idx = 0;
    int    len = 0;

    if (GetSequence(sig, &idx, &len, sigLen) < 0) {
        return ASN_ECC_KEY_E;
    }

#ifndef NO_STRICT_ECDSA_LEN
    /* enable strict length checking for signature */
    if (sigLen != idx + (word32)len) {
        return ASN_ECC_KEY_E;
    }
#else
    /* allow extra signature bytes at end */
    if ((word32)len > (sigLen - idx)) {
        return ASN_ECC_KEY_E;
    }
#endif

    if (GetInt(r, sig, &idx, sigLen) < 0) {
        return ASN_ECC_KEY_E;
    }

    if (GetInt(s, sig, &idx, sigLen) < 0) {
        return ASN_ECC_KEY_E;
    }

    return 0;
}


int wc_EccPrivateKeyDecode(const byte* input, word32* inOutIdx, ecc_key* key,
                        word32 inSz)
{
    word32 oidSum;
    int    version, length;
    int    privSz, pubSz = 0;
    byte   b;
    int    ret = 0;
    int    curve_id = ECC_CURVE_DEF;
#ifdef WOLFSSL_SMALL_STACK
    byte* priv;
    byte* pub;
#else
    byte priv[ECC_MAXSIZE+1];
    byte pub[2*(ECC_MAXSIZE+1)]; /* public key has two parts plus header */
#endif
    byte* pubData = NULL;

    if (input == NULL || inOutIdx == NULL || key == NULL || inSz == 0)
        return BAD_FUNC_ARG;

    if (GetSequence(input, inOutIdx, &length, inSz) < 0)
        return ASN_PARSE_E;

    if (GetMyVersion(input, inOutIdx, &version, inSz) < 0)
        return ASN_PARSE_E;

    if (*inOutIdx >= inSz)
        return ASN_PARSE_E;

    b = input[*inOutIdx];
    *inOutIdx += 1;

    /* priv type */
    if (b != 4 && b != 6 && b != 7)
        return ASN_PARSE_E;

    if (GetLength(input, inOutIdx, &length, inSz) < 0)
        return ASN_PARSE_E;

    if (length > ECC_MAXSIZE)
        return BUFFER_E;

#ifdef WOLFSSL_SMALL_STACK
    priv = (byte*)XMALLOC(ECC_MAXSIZE+1, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
    if (priv == NULL)
        return MEMORY_E;

    pub = (byte*)XMALLOC(2*(ECC_MAXSIZE+1), key->heap, DYNAMIC_TYPE_TMP_BUFFER);
    if (pub == NULL) {
        XFREE(priv, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
        return MEMORY_E;
    }
#endif

    /* priv key */
    privSz = length;
    XMEMCPY(priv, &input[*inOutIdx], privSz);
    *inOutIdx += length;

    if (ret == 0 && (*inOutIdx + 1) < inSz) {
        /* prefix 0, may have */
        b = input[*inOutIdx];
        if (b == ECC_PREFIX_0) {
            *inOutIdx += 1;

            if (GetLength(input, inOutIdx, &length, inSz) <= 0)
                ret = ASN_PARSE_E;
            else {
                ret = GetObjectId(input, inOutIdx, &oidSum, oidIgnoreType,
                                  inSz);
                if (ret == 0) {
                    if ((ret = CheckCurve(oidSum)) < 0)
                        ret = ECC_CURVE_OID_E;
                    else {
                        curve_id = ret;
                        ret = 0;
                    }
                }
            }
        }
    }

    if (ret == 0 && (*inOutIdx + 1) < inSz) {
        /* prefix 1 */
        b = input[*inOutIdx];
        *inOutIdx += 1;

        if (b != ECC_PREFIX_1) {
            ret = ASN_ECC_KEY_E;
        }
        else if (GetLength(input, inOutIdx, &length, inSz) <= 0) {
            ret = ASN_PARSE_E;
        }
        else {
            /* key header */
            ret = CheckBitString(input, inOutIdx, &length, inSz, 0, NULL);
            if (ret == 0) {
                /* pub key */
                pubSz = length;
                if (pubSz < 2*(ECC_MAXSIZE+1)) {
                    XMEMCPY(pub, &input[*inOutIdx], pubSz);
                    *inOutIdx += length;
                    pubData = pub;
                }
                else
                    ret = BUFFER_E;
            }
        }
    }

    if (ret == 0) {
        ret = wc_ecc_import_private_key_ex(priv, privSz, pubData, pubSz, key,
                                                                      curve_id);
    }

#ifdef WOLFSSL_SMALL_STACK
    XFREE(priv, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(pub,  key->heap, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return ret;
}


#ifdef WOLFSSL_CUSTOM_CURVES
static void ByteToHex(byte n, char* str)
{
    static const char hexChar[] = { '0', '1', '2', '3', '4', '5', '6', '7',
                                    '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

    str[0] = hexChar[n >> 4];
    str[1] = hexChar[n & 0xf];
}

/* returns 0 on success */
static int ASNToHexString(const byte* input, word32* inOutIdx, char** out,
                          word32 inSz, void* heap, int heapType)
{
    int len;
    int i;
    char* str;
    word32 localIdx;
    byte   tag;

    if (*inOutIdx >= inSz) {
        return BUFFER_E;
    }

    localIdx = *inOutIdx;
    if (GetASNTag(input, &localIdx, &tag, inSz) == 0 && tag == ASN_INTEGER) {
        if (GetASNInt(input, inOutIdx, &len, inSz) < 0)
            return ASN_PARSE_E;
    }
    else {
        if (GetOctetString(input, inOutIdx, &len, inSz) < 0)
            return ASN_PARSE_E;
    }

    str = (char*)XMALLOC(len * 2 + 1, heap, heapType);
    for (i=0; i<len; i++)
        ByteToHex(input[*inOutIdx + i], str + i*2);
    str[len*2] = '\0';

    *inOutIdx += len;
    *out = str;

    return 0;
}
#endif /* WOLFSSL_CUSTOM_CURVES */

int wc_EccPublicKeyDecode(const byte* input, word32* inOutIdx,
                          ecc_key* key, word32 inSz)
{
    int    length;
    int    ret;
    int    curve_id = ECC_CURVE_DEF;
    word32 oidSum, localIdx;
    byte   tag;

    if (input == NULL || inOutIdx == NULL || key == NULL || inSz == 0)
        return BAD_FUNC_ARG;

    if (GetSequence(input, inOutIdx, &length, inSz) < 0)
        return ASN_PARSE_E;

    if (GetSequence(input, inOutIdx, &length, inSz) < 0)
        return ASN_PARSE_E;

    ret = SkipObjectId(input, inOutIdx, inSz);
    if (ret != 0)
        return ret;

    if (*inOutIdx >= inSz) {
        return BUFFER_E;
    }

    localIdx = *inOutIdx;
    if (GetASNTag(input, &localIdx, &tag, inSz) == 0 &&
            tag == (ASN_SEQUENCE | ASN_CONSTRUCTED)) {
#ifdef WOLFSSL_CUSTOM_CURVES
        ecc_set_type* curve;
        int len;
        char* point = NULL;

        ret = 0;

        curve = (ecc_set_type*)XMALLOC(sizeof(*curve), key->heap,
                                                       DYNAMIC_TYPE_ECC_BUFFER);
        if (curve == NULL)
            ret = MEMORY_E;

        if (ret == 0) {
            static char customName[] = "Custom";
            XMEMSET(curve, 0, sizeof(*curve));
        #ifndef USE_WINDOWS_API
            curve->name = customName;
        #else
            XMEMCPY((void*)curve->name, customName, sizeof(customName));
        #endif
            curve->id = ECC_CURVE_CUSTOM;

            if (GetSequence(input, inOutIdx, &length, inSz) < 0)
                ret = ASN_PARSE_E;
        }

        if (ret == 0) {
            GetInteger7Bit(input, inOutIdx, inSz);
            if (GetSequence(input, inOutIdx, &length, inSz) < 0)
                ret = ASN_PARSE_E;
        }
        if (ret == 0) {
            SkipObjectId(input, inOutIdx, inSz);
            ret = ASNToHexString(input, inOutIdx, (char**)&curve->prime, inSz,
                                            key->heap, DYNAMIC_TYPE_ECC_BUFFER);
        }
        if (ret == 0) {
            curve->size = (int)XSTRLEN(curve->prime) / 2;

            if (GetSequence(input, inOutIdx, &length, inSz) < 0)
                ret = ASN_PARSE_E;
        }
        if (ret == 0) {
            ret = ASNToHexString(input, inOutIdx, (char**)&curve->Af, inSz,
                                            key->heap, DYNAMIC_TYPE_ECC_BUFFER);
        }
        if (ret == 0) {
            ret = ASNToHexString(input, inOutIdx, (char**)&curve->Bf, inSz,
                                            key->heap, DYNAMIC_TYPE_ECC_BUFFER);
        }
        if (ret == 0) {
            localIdx = *inOutIdx;
            if (*inOutIdx < inSz && GetASNTag(input, &localIdx, &tag, inSz)
                    == 0 && tag == ASN_BIT_STRING) {
                len = 0;
                ret = GetASNHeader(input, ASN_BIT_STRING, inOutIdx, &len, inSz);
                *inOutIdx += len;
            }
        }
        if (ret == 0) {
            ret = ASNToHexString(input, inOutIdx, (char**)&point, inSz,
                                            key->heap, DYNAMIC_TYPE_ECC_BUFFER);

            /* sanity check that point buffer is not smaller than the expected
             * size to hold ( 0 4 || Gx || Gy )
             * where Gx and Gy are each the size of curve->size * 2 */
            if (ret == 0 && (int)XSTRLEN(point) < (curve->size * 4) + 2) {
                XFREE(point, key->heap, DYNAMIC_TYPE_ECC_BUFFER);
                ret = BUFFER_E;
            }
        }
        if (ret == 0) {
        #ifndef USE_WINDOWS_API
            curve->Gx = (const char*)XMALLOC(curve->size * 2 + 2, key->heap,
                                                       DYNAMIC_TYPE_ECC_BUFFER);
            curve->Gy = (const char*)XMALLOC(curve->size * 2 + 2, key->heap,
                                                       DYNAMIC_TYPE_ECC_BUFFER);
            if (curve->Gx == NULL || curve->Gy == NULL) {
                XFREE(point, key->heap, DYNAMIC_TYPE_ECC_BUFFER);
                ret = MEMORY_E;
            }
        #else
            if (curve->size * 2 + 2 > MAX_ECC_STRING) {
                WOLFSSL_MSG("curve size is too large to fit in buffer");
                ret = BUFFER_E;
            }
        #endif
        }
        if (ret == 0) {
            XMEMCPY((char*)curve->Gx, point + 2, curve->size * 2);
            XMEMCPY((char*)curve->Gy, point + curve->size * 2 + 2,
                                                               curve->size * 2);
            ((char*)curve->Gx)[curve->size * 2] = '\0';
            ((char*)curve->Gy)[curve->size * 2] = '\0';
            XFREE(point, key->heap, DYNAMIC_TYPE_ECC_BUFFER);
            ret = ASNToHexString(input, inOutIdx, (char**)&curve->order, inSz,
                                            key->heap, DYNAMIC_TYPE_ECC_BUFFER);
        }
        if (ret == 0) {
            curve->cofactor = GetInteger7Bit(input, inOutIdx, inSz);

        #ifndef USE_WINDOWS_API
            curve->oid = NULL;
        #else
            XMEMSET((void*)curve->oid, 0, sizeof(curve->oid));
        #endif
            curve->oidSz = 0;
            curve->oidSum = 0;

            if (wc_ecc_set_custom_curve(key, curve) < 0) {
                ret = ASN_PARSE_E;
            }
        #ifndef USE_WINDOWS_API
            key->deallocSet = 1;
        #endif
            curve = NULL;
        }
        if (curve != NULL)
            wc_ecc_free_curve(curve, key->heap);

        if (ret < 0)
            return ret;
#else
        return ASN_PARSE_E;
#endif /* WOLFSSL_CUSTOM_CURVES */
    }
    else {
        /* ecc params information */
        ret = GetObjectId(input, inOutIdx, &oidSum, oidIgnoreType, inSz);
        if (ret != 0)
            return ret;

        /* get curve id */
        curve_id = wc_ecc_get_oid(oidSum, NULL, 0);
        if (curve_id < 0)
            return ECC_CURVE_OID_E;
    }

    /* key header */
    ret = CheckBitString(input, inOutIdx, &length, inSz, 1, NULL);
    if (ret != 0)
        return ret;

    /* This is the raw point data compressed or uncompressed. */
    if (wc_ecc_import_x963_ex(input + *inOutIdx, inSz - *inOutIdx, key,
                                                            curve_id) != 0) {
        return ASN_ECC_KEY_E;
    }

    *inOutIdx += length;

    return 0;
}

#endif /* HAVE_ECC */

#undef ERROR_OUT

#endif /* !NO_ASN */

#endif /* HAVE_DO178 */
