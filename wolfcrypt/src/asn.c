/* asn.c
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
 * NO_ASN_TIME: Disables time parts of the ASN code for systems without an RTC
    or wishing to save space.
 * IGNORE_NAME_CONSTRAINTS: Skip ASN name checks.
 * ASN_DUMP_OID: Allows dump of OID information for debugging.
 * RSA_DECODE_EXTRA: Decodes extra information in RSA public key.
 * WOLFSSL_CERT_GEN: Cert generation. Saves extra certificate info in GetName.
 * WOLFSSL_NO_ASN_STRICT: Disable strict RFC compliance checks to
    restore 3.13.0 behavior.
 * WOLFSSL_NO_OCSP_OPTIONAL_CERTS: Skip optional OCSP certs (responder issuer
    must still be trusted)
 * WOLFSSL_NO_TRUSTED_CERTS_VERIFY: Workaround for situation where entire cert
    chain is not loaded. This only matches on subject and public key and
    does not perform a PKI validation, so it is not a secure solution.
    Only enabled for OCSP.
 * WOLFSSL_NO_OCSP_ISSUER_CHECK: Can be defined for backwards compatibility to
    disable checking of OCSP subject hash with issuer hash.
 * WOLFSSL_SMALL_CERT_VERIFY: Verify the certificate signature without using
    DecodedCert. Doubles up on some code but allows smaller dynamic memory
    usage.
 * WOLFSSL_NO_OCSP_DATE_CHECK: Disable date checks for OCSP responses. This
    may be required when the system's real-time clock is not very accurate.
    It is recommended to enforce the nonce check instead if possible.
 * WOLFSSL_FORCE_OCSP_NONCE_CHECK: Require nonces to be available in OCSP
    responses. The nonces are optional and may not be supported by all
    responders. If it can be ensured that the used responder sends nonces this
    option may improve security.
*/

#ifndef NO_ASN

#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/coding.h>
#include <wolfssl/wolfcrypt/md2.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/pwdbased.h>
#include <wolfssl/wolfcrypt/des3.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/rc2.h>
#include <wolfssl/wolfcrypt/wc_encrypt.h>
#include <wolfssl/wolfcrypt/logging.h>

#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/hash.h>
#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#ifndef NO_RC4
    #include <wolfssl/wolfcrypt/arc4.h>
#endif

#ifdef HAVE_NTRU
    #include "libntruencrypt/ntru_crypto.h"
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

#ifdef HAVE_ED25519
    #include <wolfssl/wolfcrypt/ed25519.h>
#endif

#ifdef HAVE_ED448
    #include <wolfssl/wolfcrypt/ed448.h>
#endif

#ifndef NO_RSA
    #include <wolfssl/wolfcrypt/rsa.h>
#if defined(WOLFSSL_XILINX_CRYPT) || defined(WOLFSSL_CRYPTOCELL)
extern int wc_InitRsaHw(RsaKey* key);
#endif
#endif

#ifndef NO_DSA
    #include <wolfssl/wolfcrypt/dsa.h>
#else
    typedef void* DsaKey;
#endif

#ifdef WOLF_CRYPTO_CB
    #include <wolfssl/wolfcrypt/cryptocb.h>
#endif

#ifdef _MSC_VER
    /* 4996 warning to use MS extensions e.g., strcpy_s instead of XSTRNCPY */
    #pragma warning(disable: 4996)
#endif

#define ERROR_OUT(err, eLabel) { ret = (err); goto eLabel; }

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
#ifndef NO_SHA
    static const char sigSha1wEcdsaName[] = "SHAwECDSA";
#endif
#ifdef WOLFSSL_SHA224
    static const char sigSha224wEcdsaName[] = "SHA224wECDSA";
#endif
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

#ifdef HAVE_WOLF_BIGINT
    if (wc_bigint_from_unsigned_bin(&mpi->raw, input + idx, length) != 0) {
        mp_clear(mpi);
        return ASN_GETINT_E;
    }
#endif /* HAVE_WOLF_BIGINT */

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

/* RSA (with CertGen or KeyGen) OR ECC OR ED25519 OR ED448 (with CertGen or
 * KeyGen) */
#if (!defined(NO_RSA) && !defined(HAVE_USER_RSA) && \
        (defined(WOLFSSL_CERT_GEN) || defined(WOLFSSL_KEY_GEN) || defined(OPENSSL_EXTRA))) || \
    (defined(HAVE_ECC) && defined(HAVE_ECC_KEY_EXPORT)) || \
    ((defined(HAVE_ED25519) || defined(HAVE_ED448)) && \
        (defined(WOLFSSL_CERT_GEN) || defined(WOLFSSL_KEY_GEN) || defined(OPENSSL_EXTRA))) || \
    (!defined(NO_DSA) && !defined(HAVE_SELFTEST) && defined(WOLFSSL_KEY_GEN))

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
#endif /* !NO_RSA || HAVE_ECC || HAVE_ED25519 || HAVE_ED448 */
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
    byte* pub = NULL;
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
    privSz = length;

    if (privSz > ECC_MAXSIZE)
        return BUFFER_E;

#ifdef WOLFSSL_SMALL_STACK
    priv = (byte*)XMALLOC(privSz, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
    if (priv == NULL)
        return MEMORY_E;
#endif

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
            #ifdef WOLFSSL_SMALL_STACK
                    pub = (byte*)XMALLOC(pubSz, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
                    if (pub == NULL)
                        ret = MEMORY_E;
                    else
            #endif
                    {
                        XMEMCPY(pub, &input[*inOutIdx], pubSz);
                        *inOutIdx += length;
                        pubData = pub;
                    }
                }
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
    const char hexChar[] = { '0', '1', '2', '3', '4', '5', '6', '7',
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

    (void)heap;
    (void)heapType;

    return 0;
}
#endif /* WOLFSSL_CUSTOM_CURVES */

#ifdef WOLFSSL_CUSTOM_CURVES
static int EccKeyParamCopy(char** dst, char* src)
{
    int ret = 0;
#ifdef WOLFSSL_ECC_CURVE_STATIC
    word32 length;
#endif

    if (dst == NULL || src == NULL)
        return BAD_FUNC_ARG;

#ifndef WOLFSSL_ECC_CURVE_STATIC
    *dst = src;
#else
    length = (int)XSTRLEN(src) + 1;
    if (length > MAX_ECC_STRING) {
        WOLFSSL_MSG("ECC Param too large for buffer");
        ret = BUFFER_E;
    }
    else {
        XSTRNCPY(*dst, src, length);
    }
    XFREE(src, key->heap, DYNAMIC_TYPE_ECC_BUFFER);
#endif

    return ret;
}
#endif /* WOLFSSL_CUSTOM_CURVES */

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
            static const char customName[] = "Custom";
            XMEMSET(curve, 0, sizeof(*curve));
        #ifndef WOLFSSL_ECC_CURVE_STATIC
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
            char* p = NULL;
            SkipObjectId(input, inOutIdx, inSz);
            ret = ASNToHexString(input, inOutIdx, &p, inSz,
                                            key->heap, DYNAMIC_TYPE_ECC_BUFFER);
            if (ret == 0)
                ret = EccKeyParamCopy((char**)&curve->prime, p);
        }
        if (ret == 0) {
            curve->size = (int)XSTRLEN(curve->prime) / 2;

            if (GetSequence(input, inOutIdx, &length, inSz) < 0)
                ret = ASN_PARSE_E;
        }
        if (ret == 0) {
            char* af = NULL;
            ret = ASNToHexString(input, inOutIdx, &af, inSz,
                                            key->heap, DYNAMIC_TYPE_ECC_BUFFER);
            if (ret == 0)
                ret = EccKeyParamCopy((char**)&curve->Af, af);
        }
        if (ret == 0) {
            char* bf = NULL;
            ret = ASNToHexString(input, inOutIdx, &bf, inSz,
                                            key->heap, DYNAMIC_TYPE_ECC_BUFFER);
            if (ret == 0)
                ret = EccKeyParamCopy((char**)&curve->Bf, bf);
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
        #ifndef WOLFSSL_ECC_CURVE_STATIC
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
            char* o = NULL;

            XMEMCPY((char*)curve->Gx, point + 2, curve->size * 2);
            XMEMCPY((char*)curve->Gy, point + curve->size * 2 + 2,
                                                               curve->size * 2);
            ((char*)curve->Gx)[curve->size * 2] = '\0';
            ((char*)curve->Gy)[curve->size * 2] = '\0';
            XFREE(point, key->heap, DYNAMIC_TYPE_ECC_BUFFER);
            ret = ASNToHexString(input, inOutIdx, &o, inSz,
                                            key->heap, DYNAMIC_TYPE_ECC_BUFFER);
            if (ret == 0)
                ret = EccKeyParamCopy((char**)&curve->order, o);
        }
        if (ret == 0) {
            curve->cofactor = GetInteger7Bit(input, inOutIdx, inSz);

        #ifndef WOLFSSL_ECC_CURVE_STATIC
            curve->oid = NULL;
        #else
            XMEMSET((void*)curve->oid, 0, sizeof(curve->oid));
        #endif
            curve->oidSz = 0;
            curve->oidSum = 0;

            if (wc_ecc_set_custom_curve(key, curve) < 0) {
                ret = ASN_PARSE_E;
            }
        #ifdef WOLFSSL_CUSTOM_CURVES
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

#endif /* HAVE_ECC */

#undef ERROR_OUT

#endif /* !NO_ASN */

