/* asn.c
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

/*

DESCRIPTION
This library provides the interface to Abstract Syntax Notation One (ASN.1) objects.
ASN.1 is a standard interface description language for defining data structures
that can be serialized and deserialized in a cross-platform way.

*/
#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

/*
ASN Options:
 * WOLFSSL_CERT_GEN: Cert generation. Saves extra certificate info in GetName.
*/

#ifndef NO_ASN

#ifdef HAVE_DO178
#undef WOLFSSL_ENTER
#undef WOLFSSL_LEAVE

#define WOLFSSL_ENTER(m)
#define WOLFSSL_LEAVE(m, r)
#endif

#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/random.h>

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#if defined(WOLFSSL_SHA512) || defined(WOLFSSL_SHA384)
    #include <wolfssl/wolfcrypt/sha512.h>
#endif

#ifndef NO_SHA256
    #include <wolfssl/wolfcrypt/sha256.h>
#endif

#ifdef HAVE_ECC
    #include <wolfssl/wolfcrypt/ecc.h>
#endif

#include <wolfssl/internal.h>
#include <wolfssl/ssl.h>
#include <wolfssl/error-ssl.h>

#ifndef NO_SHA256
    static const byte hashSha256hOid[] = {96, 134, 72, 1, 101, 3, 4, 2, 1};
#endif
#ifdef WOLFSSL_SHA384
    static const byte hashSha384hOid[] = {96, 134, 72, 1, 101, 3, 4, 2, 2};
#endif

/* hmacType */
#ifndef NO_HMAC
    #ifndef NO_SHA256
    static const byte hmacSha256Oid[] = {42, 134, 72, 134, 247, 13, 2, 9};
    #endif
    #ifdef WOLFSSL_SHA384
    static const byte hmacSha384Oid[] = {42, 134, 72, 134, 247, 13, 2, 10};
    #endif
#endif

#ifdef HAVE_ECC
    #ifndef NO_SHA256
    static const byte sigSha256wEcdsaOid[] = {42, 134, 72, 206, 61, 4, 3, 2};
    #endif
    #ifdef WOLFSSL_SHA384
    static const byte sigSha384wEcdsaOid[] = {42, 134, 72, 206, 61, 4, 3, 3};
    #endif
#endif /* HAVE_ECC */

#ifdef HAVE_ECC
    static const byte keyEcdsaOid[] = {42, 134, 72, 206, 61, 2, 1};
#endif /* HAVE_ECC */

#define ERROR_OUT(err, eLabel) { ret = (err); goto eLabel; }
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
/* cmsKeyAgreeType */
#ifndef NO_SHA256
    static const byte dhSinglePass_stdDH_sha256kdf_Oid[] = {43, 129, 4, 1, 11, 1};
#endif
#ifdef WOLFSSL_SHA384
    static const byte dhSinglePass_stdDH_sha384kdf_Oid[] = {43, 129, 4, 1, 11, 2};
#endif

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
/* certAuthInfoType */
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
static const byte pbes2[] = {42, 134, 72, 134, 247, 13, 1, 5, 13};

int GetLength(const byte* input, word32* inOutIdx, int* len,
                           word32 maxIdx)
{
    return GetLength_ex(input, inOutIdx, len, maxIdx, 1);
}


/* give option to check length value found against index. 1 to check 0 to not */
int GetLength_ex(const byte* input, word32* inOutIdx, int* len,
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

        if (bytes > sizeof(length)) {
            return ASN_PARSE_E;
        }
        while (bytes--) {
            b = input[idx++];
            length = (length << 8) | b;
        }
        if (length < 0) {
            return ASN_PARSE_E;
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
    byte   tagFound;
    int    length;

    if (GetASNTag(input, &idx, &tagFound, maxIdx) != 0)
        return ASN_PARSE_E;

    if (tagFound != tag)
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

int GetSequence(const byte* input, word32* inOutIdx, int* len,
                           word32 maxIdx)
{
    return GetASNHeader(input, ASN_SEQUENCE | ASN_CONSTRUCTED, inOutIdx, len,
                        maxIdx);
}


int GetSequence_ex(const byte* input, word32* inOutIdx, int* len,
                           word32 maxIdx, int check)
{
    return GetASNHeader_ex(input, ASN_SEQUENCE | ASN_CONSTRUCTED, inOutIdx, len,
                        maxIdx, check);
}


int GetSet(const byte* input, word32* inOutIdx, int* len,
                        word32 maxIdx)
{
    return GetASNHeader(input, ASN_SET | ASN_CONSTRUCTED, inOutIdx, len,
                        maxIdx);
}


int GetSet_ex(const byte* input, word32* inOutIdx, int* len,
                        word32 maxIdx, int check)
{
    return GetASNHeader_ex(input, ASN_SET | ASN_CONSTRUCTED, inOutIdx, len,
                        maxIdx, check);
}

/* Get the DER/BER encoding of an ASN.1 OCTET_STRING header.
 *
 * input     Buffer holding DER/BER encoded data.
 * inOutIdx  Current index into buffer to parse.
 * len       The number of bytes in the ASN.1 data.
 * maxIdx    Length of data in buffer.
 * returns BUFFER_E when there is not enough data to parse.
 *         ASN_PARSE_E when the OCTET_STRING tag is not found or length is
 *         invalid.
 *         Otherwise, the number of bytes in the ASN.1 data.
 */
int GetOctetString(const byte* input, word32* inOutIdx, int* len,
                          word32 maxIdx)
{
    return GetASNHeader(input, ASN_OCTET_STRING, inOutIdx, len, maxIdx);
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

#ifndef WOLFSSL_ASN_INT_LEAD_0_ANY
        /* check for invalid padding on negative integer.
         * c.f. X.690 (ISO/IEC 8825-2:2003 (E)) 10.4.6; RFC 5280 4.1
         */
        if (*len > 1) {
            if ((input[*inOutIdx] == 0xff) && (input[*inOutIdx + 1] & 0x80))
                return ASN_PARSE_E;
        }
#endif

        /* remove leading zero, unless there is only one 0x00 byte */
        if ((input[*inOutIdx] == 0x00) && (*len > 1)) {
            (*inOutIdx)++;
            (*len)--;

#ifndef WOLFSSL_ASN_INT_LEAD_0_ANY
            if (*len > 0 && (input[*inOutIdx] & 0x80) == 0)
                return ASN_PARSE_E;
#endif
        }
    }

    return 0;
}

#ifdef HAVE_ECC
#ifndef NO_SHA256
    static const char sigSha256wEcdsaName[] = "SHA256wECDSA";
#endif
#ifdef WOLFSSL_SHA384
    static const char sigSha384wEcdsaName[] = "SHA384wECDSA";
#endif
#endif /* HAVE_ECC */
static const char sigUnknownName[] = "Unknown";


/* Get the human readable string for a signature type
 *
 * oid  Oid value for signature
 */
const char* GetSigName(int oid) {
    switch (oid) {
    #ifdef HAVE_ECC
        #ifndef NO_SHA256
        case CTC_SHA256wECDSA:
            return sigSha256wEcdsaName;
        #endif
        #ifdef WOLFSSL_SHA384
        case CTC_SHA384wECDSA:
            return sigSha384wEcdsaName;
        #endif
    #endif /* HAVE_ECC */
        default:
            return sigUnknownName;
    }
}
#if !defined(NO_DSA) || defined(HAVE_ECC) || (defined(WOLFSSL_CERT_GEN) && \
    !defined(NO_RSA)) || ((defined(WOLFSSL_KEY_GEN) || \
    defined(OPENSSL_EXTRA)) && !defined(NO_RSA) && !defined(HAVE_USER_RSA))
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
    if (maxSz >= 0 && (1 + length + (leadingBit ? 1 : 0)) > maxSz)
        return BUFFER_E;
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
#endif

#if !defined(NO_DSA) || defined(HAVE_ECC) || !defined(NO_CERTS) || \
   (!defined(NO_RSA) && \
        (defined(WOLFSSL_CERT_GEN) || \
        ((defined(WOLFSSL_KEY_GEN) || defined(OPENSSL_EXTRA)) && !defined(HAVE_USER_RSA))))
/* Set the DER/BER encoding of the ASN.1 INTEGER header.
 *
 * len        Length of data to encode.
 * firstByte  First byte of data, most significant byte of integer, to encode.
 * output     Buffer to write into.
 * returns the number of bytes added to the buffer.
 */
int SetASNInt(int len, byte firstByte, byte* output)
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
#endif

/* Windows header clash for WinCE using GetVersion */
int GetMyVersion(const byte* input, word32* inOutIdx,
                               int* version, word32 maxIdx)
{
    word32 idx = *inOutIdx;
    byte   tag;

    if ((idx + MIN_VERSION_SZ) > maxIdx)
        return ASN_PARSE_E;

    if (GetASNTag(input, &idx, &tag, maxIdx) != 0)
        return ASN_PARSE_E;

    if (tag != ASN_INTEGER)
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

    *inOutIdx = idx + length;

    return 0;
}

int CheckBitString(const byte* input, word32* inOutIdx, int* len,
                          word32 maxIdx, int zeroBits, byte* unusedBits)
{
    word32 idx = *inOutIdx;
    int    length;
    byte   b;

    if (GetASNTag(input, &idx, &b, maxIdx) != 0) {
        return ASN_BITSTR_E;
    }

    if (b != ASN_BIT_STRING) {
        return ASN_BITSTR_E;
    }

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
    int    length;
    byte   tag;

    if ((idx + 1) > maxIdx)
        return BUFFER_E;

    if (GetASNTag(input, &idx, &tag, maxIdx) != 0)
        return ASN_PARSE_E;

    if (tag != ASN_OBJECT_ID)
        return ASN_OBJECT_ID_E;

    if (GetLength(input, &idx, &length, maxIdx) < 0)
        return ASN_PARSE_E;

    *len = length;
    *inOutIdx = idx;
    return 0;
}
int GetObjectId(const byte* input, word32* inOutIdx, word32* oid,
                                  word32 oidType, word32 maxIdx)
{
    int    ret = 0, length;
    word32 idx = *inOutIdx;

    (void)oidType;
    WOLFSSL_ENTER("GetObjectId()");
    *oid = 0;

    ret = GetASNObjectId(input, &idx, &length, maxIdx);
    if (ret != 0)
        return ret;

    while (length--) {
        /* odd HC08 compiler behavior here when input[idx++] */
        *oid += (word32)input[idx];
        idx++;
    }
    /* just sum it up for now */

    *inOutIdx = idx;

    return ret;
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

/* Get date buffer, format and length. Returns 0=success or error */
static int GetDateInfo(const byte* source, word32* idx, const byte** pDate,
                        byte* pFormat, int* pLength, word32 maxIdx)
{
    int length;
    byte format;

    if (source == NULL || idx == NULL)
        return BAD_FUNC_ARG;

    /* get ASN format header */
    if (*idx+1 > maxIdx)
        return BUFFER_E;
    format = source[*idx];
    *idx += 1;
    if (format != ASN_UTC_TIME && format != ASN_GENERALIZED_TIME)
        return ASN_TIME_E;

    /* get length */
    if (GetLength(source, idx, &length, maxIdx) < 0)
        return ASN_PARSE_E;
    if (length > MAX_DATE_SIZE || length < MIN_DATE_SIZE)
        return ASN_DATE_SZ_E;

    /* return format, date and length */
    if (pFormat)
        *pFormat = format;
    if (pDate)
        *pDate = &source[*idx];
    if (pLength)
        *pLength = length;

    *idx += length;

    return 0;
}
int wc_GetDateInfo(const byte* certDate, int certDateSz, const byte** date,
    byte* format, int* length)
{
    int ret;
    word32 idx = 0;

    ret = GetDateInfo(certDate, &idx, date, format, length, certDateSz);
    if (ret < 0)
        return ret;

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


word32 SetLength(word32 length, byte* output)
{
    word32 i = 0, j;

    if (length < ASN_LONG_LENGTH) {
        if (output)
            output[i] = (byte)length;
        i++;
    }
    else {
        if (output)
            output[i] = (byte)(BytePrecision(length) | ASN_LONG_LENGTH);
        i++;

        for (j = BytePrecision(length); j; --j) {
            if (output)
                output[i] = (byte)(length >> ((j - 1) * WOLFSSL_BIT_SIZE));
            i++;
        }
    }

    return i;
}

word32 SetSequence(word32 len, byte* output)
{
    if (output)
        output[0] = ASN_SEQUENCE | ASN_CONSTRUCTED;
    return SetLength(len, output ? output + 1 : NULL) + 1;
}

word32 SetOctetString(word32 len, byte* output)
{
    output[0] = ASN_OCTET_STRING;
    return SetLength(len, output + 1) + 1;
}

/* Write a set header to output */
word32 SetSet(word32 len, byte* output)
{
    output[0] = ASN_SET | ASN_CONSTRUCTED;
    return SetLength(len, output + 1) + 1;
}

word32 SetImplicit(byte tag, byte number, word32 len, byte* output)
{

    output[0] = ((tag == ASN_SEQUENCE || tag == ASN_SET) ? ASN_CONSTRUCTED : 0)
                    | ASN_CONTEXT_SPECIFIC | number;
    return SetLength(len, output + 1) + 1;
}

word32 SetExplicit(byte number, word32 len, byte* output)
{
    output[0] = ASN_CONSTRUCTED | ASN_CONTEXT_SPECIFIC | number;
    return SetLength(len, output + 1) + 1;
}

static WC_INLINE int IsSigAlgoECDSA(int algoOID)
{
    /* ECDSA sigAlgo must not have ASN1 NULL parameters */
    if (algoOID == CTC_SHAwECDSA || algoOID == CTC_SHA256wECDSA ||
        algoOID == CTC_SHA384wECDSA || algoOID == CTC_SHA512wECDSA) {
        return 1;
    }

    return 0;
}

int GetSerialNumber(const byte* input, word32* inOutIdx,
    byte* serial, int* serialSz, word32 maxIdx)
{
    int result = 0;
    int ret;

    WOLFSSL_ENTER("GetSerialNumber");

    if (serial == NULL || input == NULL || serialSz == NULL) {
        return BAD_FUNC_ARG;
    }

    /* First byte is ASN type */
    if ((*inOutIdx+1) > maxIdx) {
        WOLFSSL_MSG("Bad idx first");
        return BUFFER_E;
    }

    ret = GetASNInt(input, inOutIdx, serialSz, maxIdx);
    if (ret != 0)
        return ret;

    if (*serialSz > EXTERNAL_SERIAL_SIZE) {
        WOLFSSL_MSG("Serial size bad");
        return ASN_PARSE_E;
    }

    /* return serial */
    XMEMCPY(serial, &input[*inOutIdx], *serialSz);
    *inOutIdx += *serialSz;

    return result;
}


#ifdef HAVE_ECC

/* return 0 on success if the ECC curve oid sum is supported */
static int CheckCurve(word32 oid)
{
    int ret = 0;
    word32 oidSz = 0;

    ret = wc_ecc_get_oid(oid, NULL, &oidSz);
    if (ret < 0 || oidSz == 0) {
        WOLFSSL_MSG("CheckCurve not found");
        ret = ALGO_ID_E;
    }

    return ret;
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
    rSz = SetASNIntMP(r, *outLen - idx, &out[idx]);
    if (rSz < 0)
        return rSz;
    idx += rSz;

    /* store s */
    sSz = SetASNIntMP(s, *outLen - idx, &out[idx]);
    if (sSz < 0)
        return sSz;
    idx += sSz;

    *outLen = idx;

    return 0;
}

/* determine if leading bit is set */
static int is_leading_bit_set(const byte* input, word32 sz)
{
    byte c = 0;
    if (sz > 0)
        c = input[0];
    return (c & 0x80) != 0;
}
static int trim_leading_zeros(const byte** input, word32 sz)
{
    int i, leadingZeroCount = 0;
    const byte* tmp = *input;
    for (i=0; i<(int)sz; i++) {
        if (tmp[i] != 0)
            break;
        leadingZeroCount++;
    }
    /* catch all zero case */
    if (sz > 0 && leadingZeroCount == (int)sz) {
        leadingZeroCount--;
    }
    *input += leadingZeroCount;
    sz -= leadingZeroCount;
    return sz;
}

/* Der Encode r & s ints into out, outLen is (in/out) size */
/* All input/outputs are assumed to be big-endian */
int StoreECC_DSA_Sig_Bin(byte* out, word32* outLen, const byte* r, word32 rLen, 
    const byte* s, word32 sLen)
{
    int ret;
    word32 idx;
    word32 headerSz = 4;   /* 2*ASN_TAG + 2*LEN(ENUM) */
    int rAddLeadZero, sAddLeadZero;

    if ((out == NULL) || (outLen == NULL) || (r == NULL) || (s == NULL))
        return BAD_FUNC_ARG;

    /* Trim leading zeros */
    rLen = trim_leading_zeros(&r, rLen);
    sLen = trim_leading_zeros(&s, sLen);
    /* If the leading bit on the INTEGER is a 1, add a leading zero */
    /* Add leading zero if MSB is set */
    rAddLeadZero = is_leading_bit_set(r, rLen);
    sAddLeadZero = is_leading_bit_set(s, sLen);

    if (*outLen < (rLen + rAddLeadZero + sLen + sAddLeadZero +
                   headerSz + 2))  /* SEQ_TAG + LEN(ENUM) */
        return BUFFER_E;

    idx = SetSequence(rLen+rAddLeadZero + sLen+sAddLeadZero + headerSz, out);

    /* store r */
    ret = SetASNInt(rLen, rAddLeadZero ? 0x80 : 0x00, &out[idx]);
    if (ret < 0)
        return ret;
    idx += ret;
    XMEMCPY(&out[idx], r, rLen);
    idx += rLen;

    /* store s */
    ret = SetASNInt(sLen, sAddLeadZero ? 0x80 : 0x00, &out[idx]);
    if (ret < 0)
        return ret;
    idx += ret;
    XMEMCPY(&out[idx], s, sLen);
    idx += sLen;

    *outLen = idx;

    return 0;
}

/* Der Decode ECC-DSA Signature with R/S as unsigned bin */
/* All input/outputs are assumed to be big-endian */
int DecodeECC_DSA_Sig_Bin(const byte* sig, word32 sigLen, byte* r, word32* rLen,
    byte* s, word32* sLen)
{
    int    ret;
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

    ret = GetASNInt(sig, &idx, &len, sigLen);
    if (ret != 0)
        return ret;
    if (rLen)
        *rLen = len;
    if (r)
        XMEMCPY(r, (byte*)sig + idx, len);
    idx += len;

    ret = GetASNInt(sig, &idx, &len, sigLen);
    if (ret != 0)
        return ret;
    if (sLen)
        *sLen = len;
    if (s)
        XMEMCPY(s, (byte*)sig + idx, len);

    return ret;
}


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
        mp_clear(r);
        return ASN_ECC_KEY_E;
    }

    return 0;
}

/*!
    \ingroup ECC

    \brief This function parses a DER-formatted ECC private key, extracts the
    public key and stores it in the given ecc_key structure. It also sets the
    distance parsed in idx.

    \return 0 Returned upon successfully parsing the private key from the DER
    encoded input
    \return BAD_FUNC_ARG Returned if key or output is null
    \return ASN_PARSE_E Returned if there is an error parsing the public key
    from the input buffer. This may happen if the input public key is not
    properly formatted according to ASN.1 standards
    \return BUFFER_E when there is not enough data to parse.
    \return ASN_EXPECT_0_E Returned if the input key is not correctly
    formatted according to ASN.1 standards
    \return ASN_BITSTR_E Returned if the input key is not correctly formatted
    according to ASN.1 standards
    \return ASN_ECC_KEY_E returned if there is an error reading the public key
    elements of the ECC key input
    \return ECC_CURVE_OID_E if ECC curve oid sum is unsupported

    \param input pointer to the buffer containing the DER formatted private
    key to decode
    \param inOutIdx pointer to the index in the buffer at which the key begins
    (usually 0). As a side effect of this function, inOutIdx will store the
    distance parsed through the input buffer
    \param key pointer to the ecc_key structure in which to store the decoded
    private key
    \param inSz size of the input buffer

*/

int wc_EccPrivateKeyDecode(const byte* input, word32* inOutIdx, ecc_key* key,
                        word32 inSz)
{
    word32 oidSum;
    int    version, length;
    int    privSz, pubSz = 0;
    byte   b;
    int    ret = 0;
    int    curve_id = ECC_CURVE_DEF;
    byte priv[ECC_MAXSIZE+1];
    byte pub[2*(ECC_MAXSIZE+1)]; /* public key has two parts plus header */
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
    privSz = length;

    if (privSz > ECC_MAXSIZE)
        return BUFFER_E;

    /* priv key */
    XMEMCPY(priv, &input[*inOutIdx], privSz);
    *inOutIdx += length;

    if ((*inOutIdx + 1) < inSz) {
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
                if (pubSz > 2*(ECC_MAXSIZE+1))
                    ret = BUFFER_E;
                else {
                     XMEMCPY(pub, &input[*inOutIdx], pubSz);
                     *inOutIdx += length;
                     pubData = pub;
                }
            }
        }
    }

    if (ret == 0) {
        ret = wc_ecc_import_private_key_ex(priv, privSz, pubData, pubSz, key,
                                                                      curve_id);
    }

    return ret;
}

/*!
    \ingroup ECC

    \brief This function parses a DER-formatted ECC public key, extracts the
    public key and stores it in the given ecc_key structure. It also sets the
    distance parsed in idx.

    \return 0 Returned upon successfully parsing the public key from the DER
    encoded input
    \return BAD_FUNC_ARG Returned if key or output is null
    \return ASN_PARSE_E Returned if there is an error parsing the public key
    from the input buffer. This may happen if the input public key is not
    properly formatted according to ASN.1 standards
    \return BUFFER_E when there is not enough data to parse.
    \return ASN_EXPECT_0_E Returned if the input key is not correctly
    formatted according to ASN.1 standards
    \return ASN_BITSTR_E Returned if the input key is not correctly formatted
    according to ASN.1 standards
    \return ASN_ECC_KEY_E returned if there is an error reading the public key
    elements of the ECC key input
    \return ECC_CURVE_OID_E if ECC curve oid sum is unsupported

    \param input pointer to the buffer containing the DER formatted public
    key to decode
    \param inOutIdx pointer to the index in the buffer at which the key begins
    (usually 0). As a side effect of this function, inOutIdx will store the
    distance parsed through the input buffer
    \param key pointer to the ecc_key structure in which to store the decoded
    private key
    \param inSz size of the input buffer

*/

int wc_EccPublicKeyDecode(const byte* input, word32* inOutIdx,
                          ecc_key* key, word32 inSz)
{
    int    ret;
    int    version, length;
    int    curve_id = ECC_CURVE_DEF;
    word32 oidSum, localIdx;
    byte   tag, isPrivFormat = 0;

    if (input == NULL || inOutIdx == NULL || key == NULL || inSz == 0)
        return BAD_FUNC_ARG;

    if (GetSequence(input, inOutIdx, &length, inSz) < 0)
        return ASN_PARSE_E;

    /* Check if ECC private key is being used and skip private portion */
    if (GetMyVersion(input, inOutIdx, &version, inSz) >= 0) {
        isPrivFormat = 1;

        /* Type private key */
        if (*inOutIdx >= inSz)
            return ASN_PARSE_E;
        tag = input[*inOutIdx];
        *inOutIdx += 1;
        if (tag != 4 && tag != 6 && tag != 7)
            return ASN_PARSE_E;

        /* Skip Private Key */
        if (GetLength(input, inOutIdx, &length, inSz) < 0)
            return ASN_PARSE_E;
        if (length > ECC_MAXSIZE)
            return BUFFER_E;
        *inOutIdx += length;

        /* Private Curve Header */
        if (*inOutIdx >= inSz)
            return ASN_PARSE_E;
        tag = input[*inOutIdx];
        *inOutIdx += 1;
        if (tag != ECC_PREFIX_0)
            return ASN_ECC_KEY_E;
        if (GetLength(input, inOutIdx, &length, inSz) <= 0)
            return ASN_PARSE_E;
    }
    /* Standard ECC public key */
    else {
        if (GetSequence(input, inOutIdx, &length, inSz) < 0)
            return ASN_PARSE_E;

        ret = SkipObjectId(input, inOutIdx, inSz);
        if (ret != 0)
            return ret;
    }

    if (*inOutIdx >= inSz) {
        return BUFFER_E;
    }

    localIdx = *inOutIdx;
    if (GetASNTag(input, &localIdx, &tag, inSz) == 0 &&
            tag == (ASN_SEQUENCE | ASN_CONSTRUCTED)) {
        return ASN_PARSE_E;
    }
    else {
        /* ecc params information */
        ret = GetObjectId(input, inOutIdx, &oidSum, oidIgnoreType, inSz);
        if (ret != 0)
            return ret;

        /* get curve id */
        if ((ret = CheckCurve(oidSum)) < 0)
            return ECC_CURVE_OID_E;
        else {
            curve_id = ret;
        }
    }

    if (isPrivFormat) {
        /* Public Curve Header - skip */
        if (*inOutIdx >= inSz)
            return ASN_PARSE_E;
        tag = input[*inOutIdx];
        *inOutIdx += 1;
        if (tag != ECC_PREFIX_1)
            return ASN_ECC_KEY_E;
        if (GetLength(input, inOutIdx, &length, inSz) <= 0)
            return ASN_PARSE_E;
    }

    /* key header */
    ret = CheckBitString(input, inOutIdx, &length, inSz, 1, NULL);
    if (ret != 0)
        return ret;

    /* This is the raw point data compressed or uncompressed. */
    if (wc_ecc_import_x963_ex(input + *inOutIdx, length, key,
                                                            curve_id) != 0) {
        return ASN_ECC_KEY_E;
    }

    *inOutIdx += length;

    return 0;
}

#if defined(HAVE_ECC) && defined(HAVE_ECC_KEY_EXPORT)

#ifndef CA_TABLE_SIZE
    #define CA_TABLE_SIZE 11
#endif
#if !defined(NO_SHA256)
static int wc_Sha256Hash_(const byte* data, word32 len, byte* hash)
    {
        int ret = 0;
        wc_Sha256 sha256[1];
        int devId = INVALID_DEVID;

        if ((ret = wc_InitSha256_ex(sha256, NULL, devId)) != 0) {
            WOLFSSL_MSG("InitSha256 failed");
        }
        else {
            if ((ret = wc_Sha256Update(sha256, data, len)) != 0) {
                WOLFSSL_MSG("Sha256Update failed");
            }
            else if ((ret = wc_Sha256Final(sha256, hash)) != 0) {
                WOLFSSL_MSG("Sha256Final failed");
            }
            wc_Sha256Free(sha256);
        }
        return ret;
    }
#endif /* !NO_SHA256 */
#if defined(WOLFSSL_SHA384)
static int wc_Sha384Hash_(const byte* data, word32 len, byte* hash)
    {
        int ret = 0;
        wc_Sha384 sha384[1];

        if ((ret = wc_InitSha384(sha384)) != 0) {
            WOLFSSL_MSG("InitSha384 failed");
        }
        else {
            if ((ret = wc_Sha384Update(sha384, data, len)) != 0) {
                WOLFSSL_MSG("Sha384Update failed");
            }
            else if ((ret = wc_Sha384Final(sha384, hash)) != 0) {
                WOLFSSL_MSG("Sha384Final failed");
            }
            wc_Sha384Free(sha384);
        }

        return ret;
    }
#endif /* WOLFSSL_SHA384 */
/* Routine for calculating hashId */
int CalcHashId(const byte* data, word32 len, byte* hash)
{
    int ret = NOT_COMPILED_IN;

#if defined(NO_SHA) && !defined(NO_SHA256)
    ret = wc_Sha256Hash_(data, len, hash);
#endif
    return ret;
}
static int GetHeader(const byte* input, byte* tag, word32* inOutIdx, int* len,
                     word32 maxIdx, int check)
{
    word32 idx = *inOutIdx;
    int    length;

    if ((idx + 1) > maxIdx)
        return BUFFER_E;

    *tag = input[idx++];

    if (GetLength_ex(input, &idx, &length, maxIdx, check) < 0)
        return ASN_PARSE_E;

    *len      = length;
    *inOutIdx = idx;
    return length;
}

/* process NAME, either issuer or subject
 * returns 0 on success and negative values on fail */
int GetName(DecodedCert* cert, int nameType, int maxIdx)
{
    int    length;  /* length of all distinguished names */
    int    dummy;
    int    ret;
    char*  full;
    byte*  hash;
    word32 idx, localIdx = 0;
    byte   tag;

    WOLFSSL_MSG("Getting Cert Name");

    if (nameType == ISSUER) {
        full = cert->issuer;
        hash = cert->issuerHash;
    }
    else {
        full = cert->subject;
        hash = cert->subjectHash;
    }

    if (cert->srcIdx >= (word32)maxIdx) {
        return BUFFER_E;
    }

    localIdx = cert->srcIdx;
    if (GetASNTag(cert->source, &localIdx, &tag, maxIdx) < 0) {
        return ASN_PARSE_E;
    }

    if (tag == ASN_OBJECT_ID) {
        WOLFSSL_MSG("Trying optional prefix...");

        if (SkipObjectId(cert->source, &cert->srcIdx, maxIdx) < 0)
            return ASN_PARSE_E;
        WOLFSSL_MSG("Got optional prefix");
    }

    /* For OCSP, RFC2560 section 4.1.1 states the issuer hash should be
     * calculated over the entire DER encoding of the Name field, including
     * the tag and length. */
    idx = cert->srcIdx;
    if (GetSequence(cert->source, &cert->srcIdx, &length, maxIdx) < 0)
        return ASN_PARSE_E;

    ret = CalcHashId(&cert->source[idx], length + cert->srcIdx - idx, hash);
    if (ret != 0)
        return ret;

    length += cert->srcIdx;
    idx = 0;

#ifndef IGNORE_NAME_CONSTRAINTS
    if (nameType == SUBJECT) {
        cert->subjectRaw = &cert->source[cert->srcIdx];
        cert->subjectRawLen = length - cert->srcIdx;
    }
#endif

    while (cert->srcIdx < (word32)length) {
        byte        b       = 0;
        byte        joint[3];
        byte        tooBig  = FALSE;
        int         oidSz;
        const char* copy    = NULL;
        int         copyLen = 0;
        int         strLen  = 0;
        byte        id      = 0;

        if (GetSet(cert->source, &cert->srcIdx, &dummy, maxIdx) < 0) {
            WOLFSSL_MSG("Cert name lacks set header, trying sequence");
        }

        if (GetSequence(cert->source, &cert->srcIdx, &dummy, maxIdx) <= 0) {
            return ASN_PARSE_E;
        }

        ret = GetASNObjectId(cert->source, &cert->srcIdx, &oidSz, maxIdx);
        if (ret != 0) {
            return ret;
        }

        /* make sure there is room for joint */
        if ((cert->srcIdx + sizeof(joint)) > (word32)maxIdx) {
            return ASN_PARSE_E;
        }

        XMEMCPY(joint, &cert->source[cert->srcIdx], sizeof(joint));

        /* v1 name types */
        if (joint[0] == 0x55 && joint[1] == 0x04) {
            cert->srcIdx += 3;
            id = joint[2];
            if (GetHeader(cert->source, &b, &cert->srcIdx, &strLen,
                          maxIdx, 1) < 0) {
                return ASN_PARSE_E;
            }

            if (id == ASN_COMMON_NAME) {
                if (nameType == SUBJECT) {
                    cert->subjectCNLen = strLen;
                    cert->subjectCNEnc = b;
#ifndef WOLFSSL_NO_MALLOC                       
                    cert->subjectCN = (char *)&cert->source[cert->srcIdx];
#else
                    XMEMCPY(cert->subjectCN, &cert->source[cert->srcIdx], strLen);
                    cert->subjectCN[strLen] = '\0';
                    cert->subjectCNStored = 1;
#endif   

                }

                copy = WOLFSSL_COMMON_NAME;
                copyLen = sizeof(WOLFSSL_COMMON_NAME) - 1;
            }
            else if (id == ASN_SUR_NAME) {
                copy = WOLFSSL_SUR_NAME;
                copyLen = sizeof(WOLFSSL_SUR_NAME) - 1;
            }
            else if (id == ASN_COUNTRY_NAME) {
                copy = WOLFSSL_COUNTRY_NAME;
                copyLen = sizeof(WOLFSSL_COUNTRY_NAME) - 1;
            }
            else if (id == ASN_LOCALITY_NAME) {
                copy = WOLFSSL_LOCALITY_NAME;
                copyLen = sizeof(WOLFSSL_LOCALITY_NAME) - 1;
            }
            else if (id == ASN_STATE_NAME) {
                copy = WOLFSSL_STATE_NAME;
                copyLen = sizeof(WOLFSSL_STATE_NAME) - 1;
            }
            else if (id == ASN_ORG_NAME) {
                copy = WOLFSSL_ORG_NAME;
                copyLen = sizeof(WOLFSSL_ORG_NAME) - 1;
            }
            else if (id == ASN_ORGUNIT_NAME) {
                copy = WOLFSSL_ORGUNIT_NAME;
                copyLen = sizeof(WOLFSSL_ORGUNIT_NAME) - 1;
            }
            else if (id == ASN_SERIAL_NUMBER) {
                copy = WOLFSSL_SERIAL_NUMBER;
                copyLen = sizeof(WOLFSSL_SERIAL_NUMBER) - 1;
            }
        }
        else {
            /* skip */
            byte email = FALSE;
            byte pilot = FALSE;

            if (joint[0] == 0x2a && joint[1] == 0x86) {  /* email id hdr */
                id = ASN_EMAIL_NAME;
                email = TRUE;
            }

            if (joint[0] == 0x9  && joint[1] == 0x92) { /* uid id hdr */
                /* last value of OID is the type of pilot attribute */
                id    = cert->source[cert->srcIdx + oidSz - 1];
                pilot = TRUE;
            }

            cert->srcIdx += oidSz + 1;

            if (GetLength(cert->source, &cert->srcIdx, &strLen, maxIdx) < 0) {
                return ASN_PARSE_E;
            }

            if (strLen > (int)(ASN_NAME_MAX - idx)) {
                WOLFSSL_MSG("ASN name too big, skipping");
                tooBig = TRUE;
            }

            if (email) {
                copyLen = sizeof(WOLFSSL_EMAIL_ADDR) - 1;
                if ((copyLen + strLen) > (int)(ASN_NAME_MAX - idx)) {
                    WOLFSSL_MSG("ASN name too big, skipping");
                    tooBig = TRUE;
                }
                else {
                    copy = WOLFSSL_EMAIL_ADDR;
                }
                #ifndef IGNORE_NAME_CONSTRAINTS
                    {
                        DNS_entry* emailName;

                        emailName = (DNS_entry*)XMALLOC(sizeof(DNS_entry),
                                              cert->heap, DYNAMIC_TYPE_ALTNAME);
                        if (emailName == NULL) {
                            WOLFSSL_MSG("\tOut of Memory");
                            return MEMORY_E;
                        }
                        emailName->type = 0;
                        emailName->name = (char*)XMALLOC(strLen + 1,
                                              cert->heap, DYNAMIC_TYPE_ALTNAME);
                        if (emailName->name == NULL) {
                            WOLFSSL_MSG("\tOut of Memory");
                            XFREE(emailName, cert->heap, DYNAMIC_TYPE_ALTNAME);
                            return MEMORY_E;
                        }
                        emailName->len = strLen;
                        XMEMCPY(emailName->name, &cert->source[cert->srcIdx],
                                                                        strLen);
                        emailName->name[strLen] = '\0';

                        emailName->next = cert->altEmailNames;
                        cert->altEmailNames = emailName;
                    }
                #endif /* IGNORE_NAME_CONSTRAINTS */
            }

            if (pilot) {
                switch (id) {
                    case ASN_USER_ID:
                        copy = WOLFSSL_USER_ID;
                        copyLen = sizeof(WOLFSSL_USER_ID) - 1;
                        break;

                    case ASN_DOMAIN_COMPONENT:
                        copy = WOLFSSL_DOMAIN_COMPONENT;
                        copyLen = sizeof(WOLFSSL_DOMAIN_COMPONENT) - 1;
                        break;
                    case ASN_FAVOURITE_DRINK:
                        copy = WOLFSSL_FAVOURITE_DRINK;
                        copyLen = sizeof(WOLFSSL_FAVOURITE_DRINK) - 1;
                        break;

                    default:
                        WOLFSSL_MSG("Unknown pilot attribute type");
                        return ASN_PARSE_E;
                }
            }
        }
        if ((copyLen + strLen) > (int)(ASN_NAME_MAX - idx))
        {
            WOLFSSL_MSG("ASN Name too big, skipping");
            tooBig = TRUE;
        }
        if ((copy != NULL) && !tooBig) {
            XMEMCPY(&full[idx], copy, copyLen);
            idx += copyLen;
            XMEMCPY(&full[idx], &cert->source[cert->srcIdx], strLen);
            idx += strLen;
        }
        cert->srcIdx += strLen;
    }
    full[idx++] = 0;

    return 0;
}

static int GetDate(DecodedCert* cert, int dateType, int verify, int maxIdx)
{
    int    ret, length;
    const byte *datePtr = NULL;
    byte   date[MAX_DATE_SIZE];
    byte   format;
    word32 startIdx = 0;

    if (dateType == BEFORE)
        cert->beforeDate = &cert->source[cert->srcIdx];
    else
        cert->afterDate = &cert->source[cert->srcIdx];
    startIdx = cert->srcIdx;

    ret = GetDateInfo(cert->source, &cert->srcIdx, &datePtr, &format,
                      &length, maxIdx);
    if (ret < 0)
        return ret;

    XMEMSET(date, 0, MAX_DATE_SIZE);
    XMEMCPY(date, datePtr, length);

    if (dateType == BEFORE)
        cert->beforeDateLen = cert->srcIdx - startIdx;
    else
        cert->afterDateLen  = cert->srcIdx - startIdx;

#ifndef NO_ASN_TIME
    if (verify != NO_VERIFY && verify != VERIFY_SKIP_DATE &&
            !XVALIDATE_DATE(date, format, dateType)) {
        if (dateType == BEFORE)
            return ASN_BEFORE_DATE_E;
        else
            return ASN_AFTER_DATE_E;
    }
#else
    (void)verify;
#endif

    return 0;
}
static int GetValidity(DecodedCert* cert, int verify, int maxIdx)
{
    int length;
    int badDate = 0;

    if (GetSequence(cert->source, &cert->srcIdx, &length, maxIdx) < 0)
        return ASN_PARSE_E;

    maxIdx = cert->srcIdx + length;

    if (GetDate(cert, BEFORE, verify, maxIdx) < 0)
        badDate = ASN_BEFORE_DATE_E; /* continue parsing */

    if (GetDate(cert, AFTER, verify, maxIdx) < 0)
        return ASN_AFTER_DATE_E;

    if (badDate != 0)
        return badDate;

    return 0;
}
/* May not have one, not an error */
static int GetExplicitVersion(const byte* input, word32* inOutIdx, int* version,
                              word32 maxIdx)
{
    word32 idx = *inOutIdx;
    byte tag;

    WOLFSSL_ENTER("GetExplicitVersion");

    if (GetASNTag(input, &idx, &tag, maxIdx) != 0)
        return ASN_PARSE_E;

    if (tag == (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED)) {
        int ret;

        *inOutIdx = ++idx;  /* skip header */
        ret = GetMyVersion(input, inOutIdx, version, maxIdx);
        if (ret >= 0) {
            /* check if version is expected value rfc 5280 4.1 {0, 1, 2} */
            if (*version > MAX_X509_VERSION || *version < MIN_X509_VERSION) {
                WOLFSSL_MSG("Unexpected certificate version");
                ret = ASN_VERSION_E;
            }
        }
        return ret;
    }

    /* go back as is */
    *version = 0;

    return 0;
}
void FreeDecodedCert(DecodedCert* cert)
{
    if (cert == NULL)
        return;


//    if (cert->subjectCNStored == 1) {
//        XMEMSET(&cert->subjectCN, 0, sizeof(cert->subjectCN));
//        cert->subjectCNStored = 0;
//    }
//    if (cert->pubKeyStored == 1) {
//        XMEMSET(&cert->publicKey, 0, sizeof(cert->publicKey));
//        cert->pubKeyStored = 1;
//    }
#ifndef IGNORE_NAME_CONSTRAINTS
    if (cert->altEmailNames)
        FreeAltNames(cert->altEmailNames, cert->heap);
    if (cert->altDirNames)
        FreeAltNames(cert->altDirNames, cert->heap);
    if (cert->permittedNames)
        FreeNameSubtrees(cert->permittedNames, cert->heap);
    if (cert->excludedNames)
        FreeNameSubtrees(cert->excludedNames, cert->heap);
#endif /* IGNORE_NAME_CONSTRAINTS */

#ifndef NO_CERTS
    FreeSignatureCtx(&cert->sigCtx);
#endif
}

static int GetCertHeader(DecodedCert* cert)
{
    int ret = 0, len;

    if (GetSequence(cert->source, &cert->srcIdx, &len, cert->maxIdx) < 0)
        return ASN_PARSE_E;

    /* Reset the max index for the size indicated in the outer wrapper. */
    cert->maxIdx = len + cert->srcIdx;
    cert->certBegin = cert->srcIdx;

    if (GetSequence(cert->source, &cert->srcIdx, &len, cert->maxIdx) < 0)
        return ASN_PARSE_E;

    cert->sigIndex = len + cert->srcIdx;
    if (cert->sigIndex > cert->maxIdx)
        return ASN_PARSE_E;

    if (GetExplicitVersion(cert->source, &cert->srcIdx, &cert->version,
                                                            cert->sigIndex) < 0)
        return ASN_PARSE_E;

    if (GetSerialNumber(cert->source, &cert->srcIdx, cert->serial,
                                           &cert->serialSz, cert->sigIndex) < 0)
        return ASN_PARSE_E;

    return ret;
}

/* parses certificate up to point of X.509 public key
 *
 * if cert date is invalid then badDate gets set to error value, otherwise is 0
 *
 * returns a negative value on fail case
 */
int wc_GetPubX509(DecodedCert* cert, int verify, int* badDate)
{
    int ret;

    if (cert == NULL || badDate == NULL)
        return BAD_FUNC_ARG;

    *badDate = 0;
    if ( (ret = GetCertHeader(cert)) < 0)
        return ret;

    WOLFSSL_MSG("Got Cert Header");

    /* Using the sigIndex as the upper bound because that's where the
     * actual certificate data ends. */
    if ( (ret = GetAlgoId(cert->source, &cert->srcIdx, &cert->signatureOID,
                          oidSigType, cert->sigIndex)) < 0)
        return ret;

    WOLFSSL_MSG("Got Algo ID");

    if ( (ret = GetName(cert, ISSUER, cert->sigIndex)) < 0)
        return ret;

    if ( (ret = GetValidity(cert, verify, cert->sigIndex)) < 0)
        *badDate = ret;

    if ( (ret = GetName(cert, SUBJECT, cert->sigIndex)) < 0)
        return ret;

    WOLFSSL_MSG("Got Subject Name");
    return ret;
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

int GetAlgoId(const byte* input, word32* inOutIdx, word32* oid,
                     word32 oidType, word32 maxIdx)
{
    int    length;
    word32 idx = *inOutIdx;
    int    ret;
    *oid = 0;

    WOLFSSL_ENTER("GetAlgoId");

    if (GetSequence(input, &idx, &length, maxIdx) < 0)
        return ASN_PARSE_E;

    if (GetObjectId(input, &idx, oid, oidType, maxIdx) < 0)
        return ASN_OBJECT_ID_E;

    /* could have NULL tag and 0 terminator, but may not */
    if (idx < maxIdx) {
        word32 localIdx = idx; /*use localIdx to not advance when checking tag*/
        byte   tag;

        if (GetASNTag(input, &localIdx, &tag, maxIdx) == 0) {
            if (tag == ASN_TAG_NULL) {
                ret = GetASNNull(input, &idx, maxIdx);
                if (ret != 0)
                    return ret;
            }
        }
    }

    *inOutIdx = idx;

    return 0;
}

static int GetKey(DecodedCert* cert)
{
    int length;
#if defined(HAVE_ECC) || defined(HAVE_NTRU) || !defined(NO_DSA)
    int tmpIdx = cert->srcIdx;
#endif

    if (GetSequence(cert->source, &cert->srcIdx, &length, cert->maxIdx) < 0)
        return ASN_PARSE_E;

    if (GetAlgoId(cert->source, &cert->srcIdx,
                  &cert->keyOID, oidKeyType, cert->maxIdx) < 0)
        return ASN_PARSE_E;

    switch (cert->keyOID) {
    #ifdef HAVE_ECC
        case ECDSAk:
        {
            int ret;
            byte seq[5];
            int pubLen = length + 1 + SetLength(length, seq);
            word32 localIdx;
            byte  tag;

            localIdx = cert->srcIdx;
            if (GetASNTag(cert->source, &localIdx, &tag, cert->maxIdx) < 0)
                return ASN_PARSE_E;

            if (tag != (ASN_SEQUENCE | ASN_CONSTRUCTED)) {
                if (GetObjectId(cert->source, &cert->srcIdx,
                            &cert->pkCurveOID, oidCurveType, cert->maxIdx) < 0)
                    return ASN_PARSE_E;

                if (CheckCurve(cert->pkCurveOID) < 0)
                    return ECC_CURVE_OID_E;

                /* key header */
                ret = CheckBitString(cert->source, &cert->srcIdx, &length,
                                                         cert->maxIdx, 1, NULL);
                if (ret != 0)
                    return ret;
            }
            XMEMCPY(&cert->publicKey, &cert->source[tmpIdx], pubLen);
            cert->pubKeyStored = 1;            
            cert->pubKeySize   = pubLen;

            cert->srcIdx = tmpIdx + pubLen;

            return 0;
        }
    #endif /* HAVE_ECC */
        default:
            WOLFSSL_MSG("Unknown or not compiled in key OID");
            return ASN_UNKNOWN_OID_E;
    }
}
int DecodeToKey(DecodedCert* cert, int verify)
{
    int badDate = 0;
    int ret;

    if ( (ret = wc_GetPubX509(cert, verify, &badDate)) < 0)
        return ret;

    /* Determine if self signed */
    cert->selfSigned = XMEMCMP(cert->issuerHash,
                               cert->subjectHash,
                               KEYID_SIZE) == 0 ? 1 : 0;

    if ( (ret = GetKey(cert)) < 0)
        return ret;

    WOLFSSL_MSG("Got Key");

    if (badDate != 0)
        return badDate;

    return ret;
}


int wc_GetCTC_HashOID(int type)
{
    int ret = 0;
#ifndef NO_SHA256
    if (type == WC_SHA256) {
        ret = SHA256h;
    }
#endif

#ifdef WOLFSSL_SHA384
    if (type == WC_SHA384) {
        ret = SHA384h;
    }
#endif /* WOLFSSL_SHA384 */

    return ret;
}

void InitSignatureCtx(SignatureCtx* sigCtx, void* heap, int devId)
{
    if (sigCtx) {
        XMEMSET(sigCtx, 0, sizeof(SignatureCtx));
        sigCtx->devId = devId;
        sigCtx->heap = heap;
    }
}
void FreeSignatureCtx(SignatureCtx* sigCtx)
{
    if (sigCtx == NULL)
        return;
    else
        return;
}

/* Make a work from the front of random hash */
static WC_INLINE word32 MakeWordFromHash(const byte* hashID)
{
    return ((word32)hashID[0] << 24) | ((word32)hashID[1] << 16) |
           ((word32)hashID[2] <<  8) |  (word32)hashID[3];
}

/* hash is the SHA digest of name, just use first 32 bits as hash */
static WC_INLINE word32 HashSigner(const byte* hash)
{
    return MakeWordFromHash(hash) % CA_TABLE_SIZE;
}

#ifndef WOLFSSL_DO178_MAX_SIGNERS
    #define WOLFSSL_DO178_MAX_SIGNERS 4
#endif
static byte signer_buffer[WOLFSSL_DO178_MAX_SIGNERS][sizeof(Signer)];
static int signer_in_use[WOLFSSL_DO178_MAX_SIGNERS] = {0};

/* Create and init an new signer */
Signer* MakeSigner(void* heap)
{
#ifndef WOLFSSL_NO_MALLOC
    Signer* signer = (Signer*) XMALLOC(sizeof(Signer), heap,
                                       DYNAMIC_TYPE_SIGNER);
    if (signer) {
        XMEMSET(signer, 0, sizeof(Signer));
    }
    (void)heap;
    return signer;

#else
    int i;
    (void)heap;
    for (i = 0; i < WOLFSSL_DO178_MAX_SIGNERS; i++) {
        if (signer_in_use[i] == 0) {
            signer_in_use[i]++;
            return (Signer*)signer_buffer[i];
        }
    }
    return NULL;
#endif

}
/* Free an individual signer */
void FreeSigner(Signer* signer, void* heap)
{
    (void)signer;
    (void)heap;

    for (int i = 0; i < WOLFSSL_DO178_MAX_SIGNERS; i++) {
        if (signer == (Signer*)signer_buffer[i]) {
            signer_in_use[i] = 0;
            return;
        }
    }
}
/* does CA already exist on signer list */
int AlreadySigner(WOLFSSL_CERT_MANAGER* cm, byte* hash)
{
    Signer* signers;
    int     ret = 0;
    word32  row;

    if (cm == NULL || hash == NULL) {
        return ret;
    }

    row = HashSigner(hash);
#ifndef SINGLE_THREADED
    if (wc_LockMutex(&cm->caLock) != 0) {
        return ret;
    }
#endif
    signers = cm->caTable[row];
    while (signers) {
        byte* subjectHash;

    #ifndef NO_SKID
        subjectHash = signers->subjectKeyIdHash;
    #else
        subjectHash = signers->subjectNameHash;
    #endif

        if (XMEMCMP(hash, subjectHash, SIGNER_DIGEST_SIZE) == 0) {
            ret = 1; /* success */
            break;
        }
        signers = signers->next;
    }
#ifndef SINGLE_THREADED
    wc_UnLockMutex(&cm->caLock);
#endif
    return ret;
}
void FreeDer(DerBuffer** pDer)
{
    if (pDer && *pDer)
    {
        DerBuffer* der = (DerBuffer*)*pDer;

        /* ForceZero private keys */
        if (der->type == PRIVATEKEY_TYPE) {
            ForceZero(der->buffer, der->length);
        }
#ifndef WOLFSSL_NO_MALLOC
        der->buffer = NULL;
#endif
        XMEMSET(der, 0, der->length);
        der->length = 0;
    }
}

/* owns der, internal now uses too */
/* type flag ids from user or from chain received during verify
   don't allow chain ones to be added w/o isCA extension */
int AddCA(WOLFSSL_CERT_MANAGER* cm, DerBuffer** pDer, int type, int verify)
{
    int         ret;
    Signer*     signer = NULL;
    word32      row;
    byte*       subjectHash;
    DecodedCert  cert[1];

    DerBuffer*   der = *pDer;

    WOLFSSL_MSG("Adding a CA");

    if (cm == NULL) {
        FreeDer(pDer);
        return BAD_FUNC_ARG;
    }

    InitDecodedCert(cert, der->buffer, der->length, cm->heap);
    ret = ParseCert(cert, CA_TYPE, verify, cm);
    WOLFSSL_MSG("\tParsed new CA");

#ifndef NO_SKID
    subjectHash = cert->extSubjKeyId;
#else
    subjectHash = cert->subjectHash;
#endif

    /* check CA key size */
    if (verify) {
        switch (cert->keyOID) {
            #ifdef HAVE_ECC
            case ECDSAk:
                if (cm->minEccKeySz < 0 ||
                                   cert->pubKeySize < (word16)cm->minEccKeySz) {
                    ret = ECC_KEY_SIZE_E;
                    WOLFSSL_MSG("\tCA ECC key size error");
                }
                break;
            #endif /* HAVE_ECC */
            default:
                WOLFSSL_MSG("\tNo key size check done on CA");
                break; /* no size check if key type is not in switch */
        }
    }

    if (ret == 0 && cert->isCA == 0 && type != WOLFSSL_USER_CA) {
        WOLFSSL_MSG("\tCan't add as CA if not actually one");
        ret = NOT_CA_ERROR;
    }
#ifndef ALLOW_INVALID_CERTSIGN
    else if (ret == 0 && cert->isCA == 1 && type != WOLFSSL_USER_CA &&
        !cert->selfSigned && (cert->extKeyUsage & KEYUSE_KEY_CERT_SIGN) == 0) {
        /* Intermediate CA certs are required to have the keyCertSign
        * extension set. User loaded root certs are not. */
        WOLFSSL_MSG("\tDoesn't have key usage certificate signing");
        ret = NOT_CA_ERROR;
    }
#endif
    else if (ret == 0 && AlreadySigner(cm, subjectHash)) {
        WOLFSSL_MSG("\tAlready have this CA, not adding again");
        (void)ret;
    }
    else if (ret == 0) {
        /* take over signer parts */
        signer = MakeSigner(cm->heap);
        if (!signer)
            ret = MEMORY_ERROR;
    }
    if (ret == 0 && signer != NULL) {
    #ifdef WOLFSSL_SIGNER_DER_CERT
        ret = AllocDer(&signer->derCert, der->length, der->type, NULL);
    }
    if (ret == 0 && signer != NULL) {
        XMEMCPY(signer->derCert->buffer, der->buffer, der->length);
    #endif
        signer->keyOID         = cert->keyOID;
        if (cert->pubKeyStored) {
            signer->publicKey      = cert->publicKey;
            signer->pubKeySize     = cert->pubKeySize;
        }
        if (cert->subjectCNStored) {
            signer->nameLen        = cert->subjectCNLen;
            signer->name           = cert->subjectCN;
        }
        signer->pathLength     = cert->pathLength;
        signer->maxPathLen     = cert->maxPathLen;
        signer->pathLengthSet  = cert->pathLengthSet;
        signer->selfSigned     = cert->selfSigned;
    #ifndef IGNORE_NAME_CONSTRAINTS
        signer->permittedNames = cert->permittedNames;
        signer->excludedNames  = cert->excludedNames;
    #endif
        XMEMCPY(signer->subjectNameHash, cert->subjectHash,
                SIGNER_DIGEST_SIZE);

        signer->keyUsage = cert->extKeyUsageSet ? cert->extKeyUsage
                                                : 0xFFFF;
        signer->next    = NULL; /* If Key Usage not set, all uses valid. */

    #ifndef IGNORE_NAME_CONSTRAINTS
        cert->permittedNames = NULL;
        cert->excludedNames = NULL;
    #endif

    #ifndef NO_SKID
        row = HashSigner(signer->subjectKeyIdHash);
    #else
        row = HashSigner(signer->subjectNameHash);
    #endif
#ifndef SINGLE_THREADED
        if (wc_LockMutex(&cm->caLock) == 0) {
#endif
            signer->next = cm->caTable[row];
            cm->caTable[row] = signer;   /* takes ownership */
#ifndef SINGLE_THREADED
            wc_UnLockMutex(&cm->caLock);
#endif
            if (cm->caCacheCallback)
                cm->caCacheCallback(der->buffer, (int)der->length, type);
#ifndef SINGLE_THREADED
        }
        else {
            WOLFSSL_MSG("\tCA Mutex Lock failed");
            ret = BAD_MUTEX_E;
            FreeSigner(signer, cm->heap);
        }
#endif
    }

    WOLFSSL_MSG("\tFreeing Parsed CA");
    FreeDecodedCert(cert);
    WOLFSSL_MSG("\tFreeing der CA");
    FreeDer(pDer);
    WOLFSSL_MSG("\t\tOK Freeing der CA");

    WOLFSSL_LEAVE("AddCA", ret);

    return ret == 0 ? WOLFSSL_SUCCESS : ret;
}


/* return CA if found, otherwise NULL */
Signer* GetCA(void* vp, byte* hash)
{
    WOLFSSL_CERT_MANAGER* cm = (WOLFSSL_CERT_MANAGER*)vp;
    Signer* ret = NULL;
    Signer* signers;
    word32  row = 0;

    if (cm == NULL || hash == NULL)
        return NULL;

    row = HashSigner(hash);
#ifndef SINGLE_THREADED
    if (wc_LockMutex(&cm->caLock) != 0)
        return ret;
#endif
    signers = cm->caTable[row];
    while (signers) {
        byte* subjectHash;

        subjectHash = signers->subjectNameHash;

        if (XMEMCMP(hash, subjectHash, SIGNER_DIGEST_SIZE) == 0) {
            ret = signers;
            break;
        }
        signers = signers->next;
    }
#ifndef SINGLE_THREADED
    wc_UnLockMutex(&cm->caLock);
#endif
    return ret;
}

int SetMyVersion(word32 version, byte* output, int header)
{
    int i = 0;

    if (output == NULL)
        return BAD_FUNC_ARG;

    if (header) {
        output[i++] = ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED;
        output[i++] = 3;
    }
    output[i++] = ASN_INTEGER;
    output[i++] = 0x01;
    output[i++] = (byte)version;

    return i;
}

static word32 SetOctetString8Bit(word32 len, byte* output)
{
    output[0] = ASN_OCTET_STRING;
    output[1] = (byte)len;
    return 2;
}

static int SetCurve(ecc_key* key, byte* output)
{

    int idx = 0;
    word32 oidSz = 0;

    /* validate key */
    if (key == NULL || key->dp == NULL) {
        return BAD_FUNC_ARG;
    }

    oidSz = key->dp->oidSz;

    idx += SetObjectId(oidSz, output);

    XMEMCPY(output+idx, key->dp->oid, oidSz);
    idx += oidSz;

    return idx;
}

/* build DER formatted ECC key, include optional public key if requested,
 * return length on success, negative on error */
static int wc_BuildEccKeyDer(ecc_key* key, byte* output, word32 *inLen,
                             int pubIn)
{
    byte   curve[MAX_ALGO_SZ+2];
    byte   ver[MAX_VERSION_SZ];
    byte   seq[MAX_SEQ_SZ];
    int    ret, totalSz, curveSz, verSz;
    int    privHdrSz  = ASN_ECC_HEADER_SZ;
    int    pubHdrSz   = ASN_ECC_CONTEXT_SZ + ASN_ECC_HEADER_SZ;
#ifdef WOLFSSL_NO_MALLOC
    byte   prv[MAX_ECC_BYTES + ASN_ECC_HEADER_SZ + MAX_SEQ_SZ];
    byte   pub[(MAX_ECC_BYTES * 2) + 1 + ASN_ECC_CONTEXT_SZ + 
                              ASN_ECC_HEADER_SZ + MAX_SEQ_SZ];
#else
    byte   *prv = NULL, *pub = NULL;
#endif

    word32 idx = 0, prvidx = 0, pubidx = 0, curveidx = 0;
    word32 seqSz, privSz, pubSz = ECC_BUFSIZE;

    if (key == NULL || (output == NULL && inLen == NULL))
        return BAD_FUNC_ARG;

    /* curve */
    curve[curveidx++] = ECC_PREFIX_0;
    curveidx++ /* to put the size after computation */;
    curveSz = SetCurve(key, curve+curveidx);
    if (curveSz < 0)
        return curveSz;
    /* set computed size */
    curve[1] = (byte)curveSz;
    curveidx += curveSz;

    /* private */
    privSz = key->dp->size;

#ifndef WOLFSSL_NO_MALLOC
#else
    if (sizeof(prv) < privSz + privHdrSz + MAX_SEQ_SZ) {
        return BUFFER_E;
    }
#endif
    if (privSz < ASN_LONG_LENGTH) {
        prvidx += SetOctetString8Bit(privSz, &prv[prvidx]);
    }
    else {
        prvidx += SetOctetString(privSz, &prv[prvidx]);
    }
    ret = wc_ecc_export_private_only(key, prv + prvidx, &privSz);
    if (ret < 0) {
        return ret;
    }
    prvidx += privSz;

    /* pubIn */
    if (pubIn) {
        ret = wc_ecc_export_x963(key, NULL, &pubSz);
        if (ret != LENGTH_ONLY_E) {
            return ret;
        }

    #ifndef WOLFSSL_NO_MALLOC
    #else
        if (sizeof(pub) < pubSz + pubHdrSz + MAX_SEQ_SZ) {
            return BUFFER_E;
        }
    #endif

        pub[pubidx++] = ECC_PREFIX_1;
        if (pubSz > 128) /* leading zero + extra size byte */
            pubidx += SetLength(pubSz + ASN_ECC_CONTEXT_SZ + 2, pub+pubidx);
        else /* leading zero */
            pubidx += SetLength(pubSz + ASN_ECC_CONTEXT_SZ + 1, pub+pubidx);

        /* SetBitString adds leading zero */
        pubidx += SetBitString(pubSz, 0, pub + pubidx);
        ret = wc_ecc_export_x963(key, pub + pubidx, &pubSz);
        if (ret != 0) {
            return ret;
        }
        pubidx += pubSz;
    }

    /* make headers */
    verSz = SetMyVersion(1, ver, FALSE);
    seqSz = SetSequence(verSz + prvidx + pubidx + curveidx, seq);

    totalSz = prvidx + pubidx + curveidx + verSz + seqSz;
    if (output == NULL) {
        *inLen = totalSz;
        return LENGTH_ONLY_E;
    }
    if (inLen != NULL && totalSz > (int)*inLen) {
        return BAD_FUNC_ARG;
    }

    /* write out */
    /* seq */
    XMEMCPY(output + idx, seq, seqSz);
    idx = seqSz;

    /* ver */
    XMEMCPY(output + idx, ver, verSz);
    idx += verSz;

    /* private */
    XMEMCPY(output + idx, prv, prvidx);
    idx += prvidx;
    /* curve */
    XMEMCPY(output + idx, curve, curveidx);
    idx += curveidx;

    /* pubIn */
    if (pubIn) {
        XMEMCPY(output + idx, pub, pubidx);
        /* idx += pubidx;  not used after write, if more data remove comment */
    }

    return totalSz;
}

/* Write a Private ecc key, including public to DER format,
 * length on success else < 0 */
int wc_EccKeyToDer(ecc_key* key, byte* output, word32 inLen)
{
    return wc_BuildEccKeyDer(key, output, &inLen, 1);
}

/* Write only private ecc key to DER format,
 * length on success else < 0 */
int wc_EccKeyDerSize(ecc_key* key, int pub)
{
    word32 sz = 0;
    int ret;

    ret = wc_BuildEccKeyDer(key, NULL, &sz, pub);

    if (ret != LENGTH_ONLY_E) {
        return ret;
    }
    return sz;
 }

/* Write only private ecc key to DER format,
 * length on success else < 0 */
int wc_EccPrivateKeyToDer(ecc_key* key, byte* output, word32 inLen)
{
    return wc_BuildEccKeyDer(key, output, &inLen, 0);
}


/* returns a pointer to the OID string on success and NULL on fail */
const byte* OidFromId(word32 id, word32 type, word32* oidSz)
{
    const byte* oid = NULL;

    *oidSz = 0;

    switch (type) {

        case oidHashType:
            switch (id) {
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
                default:
                    break;
            }
            break;

        case oidSigType:
            switch (id) {
                #ifdef HAVE_ECC
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
                #endif /* HAVE_ECC */
                default:
                    break;
            }
            break;

        case oidKeyType:
            switch (id) {
                #ifdef HAVE_ECC
                case ECDSAk:
                    oid = keyEcdsaOid;
                    *oidSz = sizeof(keyEcdsaOid);
                    break;
                #endif /* HAVE_ECC */
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
                default:
                    break;
            }
            break;

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
                default:
                    break;
            }
            break;

        case oidCrlExtType:
            break;

        case oidCertAuthInfoType:
            switch (id) {
                case AIA_CA_ISSUER_OID:
                    oid = extAuthInfoCaIssuerOid;
                    *oidSz = sizeof(extAuthInfoCaIssuerOid);
                    break;
                default:
                    break;
            }
            break;

        case oidCertPolicyType:
            switch (id) {
                case CP_ANY_OID:
                    oid = extCertPolicyAnyOid;
                    *oidSz = sizeof(extCertPolicyAnyOid);
                    break;
                default:
                    break;
            }
            break;

        case oidCertAltNameType:
            switch (id) {
                case HW_NAME_OID:
                    oid = extAltNamesHwNameOid;
                    *oidSz = sizeof(extAltNamesHwNameOid);
                    break;
                default:
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
                default:
                    break;
            }
            break;

        case oidKdfType:
            switch (id) {
                case PBKDF2_OID:
                    oid = pbkdf2Oid;
                    *oidSz = sizeof(pbkdf2Oid);
                    break;
                default:
                    break;
            }
            break;

        case oidPBEType:
            switch (id) {
                case PBES2:
                    oid = pbes2;
                    *oidSz = sizeof(pbes2);
                    break;
                default:
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
                default:
                    break;
            }
            break;

        case oidCmsKeyAgreeType:
            switch (id) {
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
                default:
                    break;
            }
            break;

#ifndef NO_HMAC
        case oidHmacType:
            switch (id) {
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
                default:
                    break;
            }
            break;
#endif /* !NO_HMAC */

        case oidIgnoreType:
        default:
            break;
    }

    return oid;
}

/* Set the DER/BER encoding of the ASN.1 BIT_STRING header.
 *
 * len         Length of data to encode.
 * unusedBits  The number of unused bits in the last byte of data.
 *             That is, the number of least significant zero bits before a one.
 *             The last byte is the most-significant non-zero byte of a number.
 * output      Buffer to write into.
 * returns the number of bytes added to the buffer.
 */
word32 SetBitString(word32 len, byte unusedBits, byte* output)
{
    word32 idx = 0;

    if (output)
        output[idx] = ASN_BIT_STRING;
    idx++;

    idx += SetLength(len + 1, output ? output + idx : NULL);
    if (output)
        output[idx] = unusedBits;
    idx++;

    return idx;
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

    if (output)
        output[idx++] = ASN_OBJECT_ID;
    else
        idx++;
    idx += SetLength(len, output ? output + idx : NULL);

    return idx;
}

/* Set the DER/BER encoding of the ASN.1 NULL element.
 *
 * output  Buffer to write into.
 * returns the number of bytes added to the buffer.
 */
static int SetASNNull(byte* output)
{
    output[0] = ASN_TAG_NULL;
    output[1] = 0;

    return 2;
}

word32 SetAlgoID(int algoOID, byte* output, int type, int curveSz)
{
    word32 tagSz, idSz, seqSz, algoSz = 0;
    const  byte* algoName = 0;
    byte   ID_Length[1 + MAX_LENGTH_SZ];
    byte   seqArray[MAX_SEQ_SZ + 1];  /* add object_id to end */
    int    length = 0;

    tagSz = (type == oidHashType ||
             (type == oidSigType
        #ifdef HAVE_ECC
              && !IsSigAlgoECDSA(algoOID)
        #endif
              ) ||
             (type == oidKeyType && algoOID == RSAk)) ? 2 : 0;

    algoName = OidFromId(algoOID, type, &algoSz);

    if (algoName == NULL) {
        WOLFSSL_MSG("Unknown Algorithm");
        return 0;
    }

    idSz  = SetObjectId(algoSz, ID_Length);
    seqSz = SetSequence(idSz + algoSz + tagSz + curveSz, seqArray);

    /* Copy only algo to output for DSA keys */
    if (algoOID == DSAk && output) {
        XMEMCPY(output, ID_Length, idSz);
        XMEMCPY(output + idSz, algoName, algoSz);
        if (tagSz == 2)
            SetASNNull(&output[seqSz + idSz + algoSz]);
    }
    else if (output) {
        XMEMCPY(output, seqArray, seqSz);
        XMEMCPY(output + seqSz, ID_Length, idSz);
        XMEMCPY(output + seqSz + idSz, algoName, algoSz);
        if (tagSz == 2)
            SetASNNull(&output[seqSz + idSz + algoSz]);
    }

    if (algoOID == DSAk)
        length = idSz + algoSz + tagSz;
    else
        length = seqSz + idSz + algoSz + tagSz;

    return length;
}

/* Write a public ECC key to output */
static int SetEccPublicKey(byte* output, ecc_key* key, int with_header)
{
    byte bitString[1 + MAX_LENGTH_SZ + 1];
    int  algoSz;
    int  curveSz;
    int  bitStringSz;
    int  idx;
    word32 pubSz = ECC_BUFSIZE;
    byte algo[MAX_ALGO_SZ];
    byte curve[MAX_ALGO_SZ];
    byte pub[ECC_BUFSIZE];
    int ret;

    ret = wc_ecc_export_x963(key, pub, &pubSz);
    if (ret != 0) {
        return ret;
    }

    /* headers */
    if (with_header) {
        curveSz = SetCurve(key, curve);
        if (curveSz <= 0) {
            return curveSz;
        }

        algoSz  = SetAlgoID(ECDSAk, algo, oidKeyType, curveSz);

        bitStringSz = SetBitString(pubSz, 0, bitString);

        idx = SetSequence(pubSz + curveSz + bitStringSz + algoSz, output);
        /* algo */
        if (output)
            XMEMCPY(output + idx, algo, algoSz);
        idx += algoSz;
        /* curve */
        if (output)
            XMEMCPY(output + idx, curve, curveSz);
        idx += curveSz;
        /* bit string */
        if (output)
            XMEMCPY(output + idx, bitString, bitStringSz);
        idx += bitStringSz;
    }
    else
        idx = 0;

    /* pub */
    if (output)
        XMEMCPY(output + idx, pub, pubSz);
    idx += pubSz;

    return idx;
}


/* returns the size of buffer used, the public ECC key in DER format is stored
   in output buffer
   with_AlgCurve is a flag for when to include a header that has the Algorithm
   and Curve information */
int wc_EccPublicKeyToDer(ecc_key* key, byte* output, word32 inLen,
                                                              int with_AlgCurve)
{
    word32 infoSz = 0;
    word32 keySz  = 0;
    int ret;

    if (key == NULL) {
        return BAD_FUNC_ARG;
    }

    if (with_AlgCurve) {
        /* buffer space for algorithm/curve */
        infoSz += MAX_SEQ_SZ;
        infoSz += 2 * MAX_ALGO_SZ;

        /* buffer space for public key sequence */
        infoSz += MAX_SEQ_SZ;
        infoSz += TRAILING_ZERO;
    }

    ret = wc_ecc_export_x963(key, NULL, &keySz);
    if (ret != LENGTH_ONLY_E) {
        WOLFSSL_MSG("Error in getting ECC public key size");
        return ret;
    }

    /* if output null then just return size */
    if (output == NULL) {
        return keySz + infoSz;
    }

    if (inLen < keySz + infoSz) {
        return BUFFER_E;
    }

    return SetEccPublicKey(output, key, with_AlgCurve);
}

int wc_EccPublicKeyDerSize(ecc_key* key, int with_AlgCurve)
{
    return wc_EccPublicKeyToDer(key, NULL, 0, with_AlgCurve);
}

#endif /* HAVE_ECC && HAVE_ECC_KEY_EXPORT */


void InitDecodedCert(DecodedCert* cert,
                     const byte* source, word32 inSz, void* heap)
{
    if (cert != NULL) {
        XMEMSET(cert, 0, sizeof(DecodedCert));

        cert->subjectCNEnc    = CTC_UTF8;
        cert->issuer[0]       = '\0';
        cert->subject[0]      = '\0';
        cert->source          = source;  /* don't own */
        cert->maxIdx          = inSz;    /* can't go over this index */
        cert->heap            = heap;
        cert->maxPathLen      = WOLFSSL_MAX_PATH_LEN;
    #ifndef NO_CERTS
        InitSignatureCtx(&cert->sigCtx, heap, INVALID_DEVID);
    #endif
    }
}
#ifndef NO_ASN_CRYPT
static int HashForSignature(const byte* buf, word32 bufSz, word32 sigOID,
                            byte* digest, int* typeH, int* digestSz, int verify)
{
    int ret = 0;

    switch (sigOID) {
    #ifndef NO_SHA256
        case CTC_SHA256wRSA:
        case CTC_SHA256wECDSA:
        case CTC_SHA256wDSA:
            if ((ret = wc_Sha256Hash_(buf, bufSz, digest)) == 0) {
                *typeH    = SHA256h;
                *digestSz = WC_SHA256_DIGEST_SIZE;
            }
            break;
    #endif
    #ifdef WOLFSSL_SHA384
        case CTC_SHA384wRSA:
        case CTC_SHA384wECDSA:
            if ((ret = wc_Sha384Hash_(buf, bufSz, digest)) == 0) {
                *typeH    = SHA384h;
                *digestSz = WC_SHA384_DIGEST_SIZE;
            }
            break;
    #endif
        default:
            ret = HASH_TYPE_E;
            WOLFSSL_MSG("Hash for Signature has unsupported type");
    }

    (void)buf;
    (void)bufSz;
    (void)sigOID;
    (void)digest;
    (void)digestSz;
    (void)typeH;
    (void)verify;

    return ret;
}
#endif /* !NO_ASN_CRYPT */

/* Return codes: 0=Success, Negative (see error-crypt.h), ASN_SIG_CONFIRM_E */
static int ConfirmSignature(SignatureCtx* sigCtx,
    const byte* buf, word32 bufSz,
    const byte* key, word32 keySz, word32 keyOID,
    const byte* sig, word32 sigSz, word32 sigOID, byte* rsaKeyIdx)
{
    int ret = 0;
    ecc_key  eccKey;
#ifndef WOLFSSL_RENESAS_TSIP_TLS
    (void)rsaKeyIdx;
#endif
    if (sigCtx == NULL || buf == NULL || bufSz == 0 || key == NULL ||
        keySz == 0 || sig == NULL || sigSz == 0) {
        return BAD_FUNC_ARG;
    }

    (void)key;
    (void)keySz;
    (void)sig;
    (void)sigSz;

    WOLFSSL_ENTER("ConfirmSignature");

#ifndef NO_ASN_CRYPT
    switch (sigCtx->state) {
        case SIG_STATE_BEGIN:
        {
            sigCtx->keyOID = keyOID; /* must set early for cleanup */

#ifndef WOLFSSL_NO_MALLOC
            sigCtx->digest = (byte*)XMALLOC(WC_MAX_DIGEST_SIZE, sigCtx->heap,
                                                    DYNAMIC_TYPE_DIGEST);
            if (sigCtx->digest == NULL) {
                ERROR_OUT(MEMORY_E, exit_cs);
            }
#endif
            sigCtx->state = SIG_STATE_HASH;
        } /* SIG_STATE_BEGIN */
        FALL_THROUGH;

        case SIG_STATE_HASH:
        {
            ret = HashForSignature(buf, bufSz, sigOID, sigCtx->digest,
                                   &sigCtx->typeH, &sigCtx->digestSz, 1);
            if (ret != 0) {
                goto exit_cs;
            }

            sigCtx->state = SIG_STATE_KEY;
        } /* SIG_STATE_HASH */
        FALL_THROUGH;

        case SIG_STATE_KEY:
        {
            switch (keyOID) {
            #ifdef HAVE_ECC
                case ECDSAk:
                {
                    word32 idx = 0;

                    sigCtx->verify = 0;
#ifndef WOLFSSL_NO_MALLOC
                    sigCtx->key.ecc = (ecc_key*)XMALLOC(sizeof(ecc_key),
                                                sigCtx->heap, DYNAMIC_TYPE_ECC);
                    if (sigCtx->key.ecc == NULL) {
                        ERROR_OUT(MEMORY_E, exit_cs);
                    }
#else
                    sigCtx->key.ecc = &eccKey;
#endif
                    if ((ret = wc_ecc_init_ex(sigCtx->key.ecc, sigCtx->heap,
                                                          sigCtx->devId)) < 0) {
                        goto exit_cs;
                    }
                    ret = wc_EccPublicKeyDecode(key, &idx, sigCtx->key.ecc,
                                                                         keySz);
                    if (ret < 0) {
                        WOLFSSL_MSG("ASN Key import error ECC");
                        goto exit_cs;
                    }
                    break;
                }
            #endif /* HAVE_ECC */
                default:
                    WOLFSSL_MSG("Verify Key type unknown");
                    ret = ASN_UNKNOWN_OID_E;
                    break;
            } /* switch (keyOID) */

            if (ret != 0) {
                goto exit_cs;
            }

            sigCtx->state = SIG_STATE_DO;
        } /* SIG_STATE_KEY */
        FALL_THROUGH;

        case SIG_STATE_DO:
        {
            switch (keyOID) {
            #if defined(HAVE_ECC)
                case ECDSAk:
                {
                    {
                        ret = wc_ecc_verify_hash(sig, sigSz, sigCtx->digest,
                                            sigCtx->digestSz, &sigCtx->verify,
                                            sigCtx->key.ecc);
                    }
                    break;
                }
            #endif /* HAVE_ECC */
                default:
                    break;
            }  /* switch (keyOID) */

            if (ret < 0) {
                /* treat all RSA errors as ASN_SIG_CONFIRM_E */
                ret = ASN_SIG_CONFIRM_E;
                goto exit_cs;
            }

            sigCtx->state = SIG_STATE_CHECK;
        } /* SIG_STATE_DO */
        FALL_THROUGH;

        case SIG_STATE_CHECK:
        {
            switch (keyOID) {
            #ifdef HAVE_ECC
                case ECDSAk:
                {
                    if (sigCtx->verify == 1) {
                        ret = 0;
                    }
                    else {
                        WOLFSSL_MSG("ECC Verify didn't match");
                        ret = ASN_SIG_CONFIRM_E;
                    }
                    break;
                }
            #endif /* HAVE_ECC */
                default:
                    break;
            }  /* switch (keyOID) */

            break;
        } /* SIG_STATE_CHECK */

        default:
            break;
    } /* switch (sigCtx->state) */

exit_cs:

#endif /* !NO_ASN_CRYPT */

    (void)keyOID;
    (void)sigOID;

    WOLFSSL_LEAVE("ConfirmSignature", ret);

    FreeSignatureCtx(sigCtx);

    return ret;
}


static int GetSignature(DecodedCert* cert)
{
    int length;
    int ret;

    ret = CheckBitString(cert->source, &cert->srcIdx, &length, cert->maxIdx, 1,
                         NULL);
    if (ret != 0)
        return ret;

    cert->sigLength = length;
    cert->signature = &cert->source[cert->srcIdx];
    cert->srcIdx += cert->sigLength;

    if (cert->srcIdx != cert->maxIdx)
        return ASN_PARSE_E;

    return 0;
}
int ParseCertRelative(DecodedCert* cert, int type, int verify, void* cm)
{
    int    ret = 0;
    int    checkPathLen = 0;
    int    decrementMaxPathLen = 0;
    word32 confirmOID = 0;
    if (cert == NULL) {
        return BAD_FUNC_ARG;
    }

    if (cert->sigCtx.state == SIG_STATE_BEGIN) {
        cert->badDate = 0;
        cert->criticalExt = 0;
        if ((ret = DecodeToKey(cert, verify)) < 0) {
            if (ret == ASN_BEFORE_DATE_E || ret == ASN_AFTER_DATE_E)
                cert->badDate = ret;
            else
                return ret;
        }

        WOLFSSL_MSG("Parsed Past Key");

        if (cert->srcIdx < cert->sigIndex) {
        #ifndef ALLOW_V1_EXTENSIONS
            if (cert->version < 2) {
                WOLFSSL_MSG("\tv1 and v2 certs not allowed extensions");
                return ASN_VERSION_E;
            }
        #endif

            /* save extensions */
            cert->extensions    = &cert->source[cert->srcIdx];
            cert->extensionsSz  = cert->sigIndex - cert->srcIdx;
            cert->extensionsIdx = cert->srcIdx;   /* for potential later use */

            /* advance past extensions */
            cert->srcIdx = cert->sigIndex;
        }

        if ((ret = GetAlgoId(cert->source, &cert->srcIdx,
#ifdef WOLFSSL_CERT_REQ
                !cert->isCSR ? &confirmOID : &cert->signatureOID,
#else
                &confirmOID,
#endif
                oidSigType, cert->maxIdx)) < 0)
            return ret;

        if ((ret = GetSignature(cert)) < 0)
            return ret;

        if (confirmOID != cert->signatureOID)
            return ASN_SIG_OID_E;

        if (!cert->selfSigned || (verify != NO_VERIFY && type != CA_TYPE &&
                                                   type != TRUSTED_PEER_TYPE)) {
            cert->ca = NULL;
            cert->ca = GetCA(cm, cert->issuerHash);

            if (cert->ca) {
                WOLFSSL_MSG("CA found");
            }
        }

        if (cert->selfSigned) {
            cert->maxPathLen = WOLFSSL_MAX_PATH_LEN;
        } else {
            /* RFC 5280 Section 4.2.1.9:
             *
             * load/receive check
             *
             * 1) Is CA boolean set?
             *      No  - SKIP CHECK
             *      Yes - Check key usage
             * 2) Is Key usage extension present?
             *      No  - goto 3
             *      Yes - check keyCertSign assertion
             *     2.a) Is keyCertSign asserted?
             *          No  - goto 4
             *          Yes - goto 3
             * 3) Is pathLen set?
             *      No  - goto 4
             *      Yes - check pathLen against maxPathLen.
             *      3.a) Is pathLen less than maxPathLen?
             *           No - goto 4
             *           Yes - set maxPathLen to pathLen and EXIT
             * 4) Is maxPathLen > 0?
             *      Yes - Reduce by 1
             *      No  - ERROR
             */

            if (cert->ca && cert->pathLengthSet) {
                cert->maxPathLen = cert->pathLength;
                if (cert->isCA) {
                    WOLFSSL_MSG("\tCA boolean set");
                    if (cert->extKeyUsageSet) {
                         WOLFSSL_MSG("\tExtension Key Usage Set");
                         if ((cert->extKeyUsage & KEYUSE_KEY_CERT_SIGN) != 0) {
                            checkPathLen = 1;
                         } else {
                            decrementMaxPathLen = 1;
                         }
                    } else {
                        checkPathLen = 1;
                    } /* !cert->ca check */
                } /* cert is not a CA (assuming entity cert) */

                if (checkPathLen && cert->pathLengthSet) {
                    if (cert->pathLength < cert->ca->maxPathLen) {
                        WOLFSSL_MSG("\tmaxPathLen status: set to pathLength");
                        cert->maxPathLen = cert->pathLength;
                    } else {
                        decrementMaxPathLen = 1;
                    }
                }

                if (decrementMaxPathLen && cert->ca->maxPathLen > 0) {
                    WOLFSSL_MSG("\tmaxPathLen status: reduce by 1");
                    cert->maxPathLen = cert->ca->maxPathLen - 1;
                    if (verify != NO_VERIFY && type != CA_TYPE &&
                                                    type != TRUSTED_PEER_TYPE) {
                        WOLFSSL_MSG("\tmaxPathLen status: OK");
                    }
                } else if (decrementMaxPathLen && cert->ca->maxPathLen == 0) {
                    cert->maxPathLen = 0;
                    if (verify != NO_VERIFY && type != CA_TYPE &&
                                                    type != TRUSTED_PEER_TYPE) {
                        WOLFSSL_MSG("\tNon-entity cert, maxPathLen is 0");
                        WOLFSSL_MSG("\tmaxPathLen status: ERROR");
                        return ASN_PATHLEN_INV_E;
                    }
                }
            } else if (cert->ca && cert->isCA) {
                /* case where cert->pathLength extension is not set */
                if (cert->ca->maxPathLen > 0) {
                    cert->maxPathLen = cert->ca->maxPathLen - 1;
                } else {
                    cert->maxPathLen = 0;
                    if (verify != NO_VERIFY && type != CA_TYPE &&
                                                    type != TRUSTED_PEER_TYPE) {
                        WOLFSSL_MSG("\tNon-entity cert, maxPathLen is 0");
                        WOLFSSL_MSG("\tmaxPathLen status: ERROR");
                        return ASN_PATHLEN_INV_E;
                    }
                }
            }
        }
    }
    if (verify != NO_VERIFY && type != CA_TYPE && type != TRUSTED_PEER_TYPE) {
        if (cert->ca) {
            if (verify == VERIFY || verify == VERIFY_OCSP ||
                                                 verify == VERIFY_SKIP_DATE) {
                /* try to confirm/verify signature */
                if ((ret = ConfirmSignature(&cert->sigCtx,
                        cert->source + cert->certBegin,
                        cert->sigIndex - cert->certBegin,
                        cert->ca->publicKey, cert->ca->pubKeySize,
                        cert->ca->keyOID, cert->signature,
                        cert->sigLength, cert->signatureOID,
                        NULL)) != 0) {
                    if (ret != WC_PENDING_E) {
                        WOLFSSL_MSG("Confirm signature failed");
                    }
                    return ret;
                }
            }
        }
        else {
            /* no signer */
            WOLFSSL_MSG("No CA signer to verify with");
            return ASN_NO_SIGNER_E;
        }
    }
    if (cert->badDate != 0) {
        if (verify != VERIFY_SKIP_DATE) {
            return cert->badDate;
        }
        WOLFSSL_MSG("Date error: Verify option is skipping");
    }

    if (cert->criticalExt != 0)
        return cert->criticalExt;

    return ret;
}


int ParseCert(DecodedCert* cert, int type, int verify, void* cm)
{
    int   ret;

    ret = ParseCertRelative(cert, type, verify, cm);

    return ret;
}
#endif /* HAVE_ECC */

#endif /* !NO_ASN */

