/* random.c
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
This library contains implementation for the random number generator.

*/
#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

/* on HPUX 11 you may need to install /dev/random see
   http://h20293.www2.hp.com/portal/swdepot/displayProductInfo.do?productNumber=KRNG11I

*/

#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/cpuid.h>

#ifndef WC_NO_RNG /* if not FIPS and RNG is disabled then do not compile */

#include <wolfssl/wolfcrypt/sha256.h>

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#if defined(WOLFSSL_SGX)
    #include <sgx_trts.h>
#elif defined(NO_DEV_RANDOM)
#elif defined(CUSTOM_RAND_GENERATE)
#elif defined(CUSTOM_RAND_GENERATE_BLOCK)
#elif defined(CUSTOM_RAND_GENERATE_SEED)
#elif defined(WOLFSSL_GENSEED_FORTEST)
#elif defined(WOLFSSL_MDK_ARM)
#else
    /* include headers that may be needed to get good seed */
    #include <fcntl.h>
    #ifndef EBSNET
        #include <unistd.h>
    #endif
#endif


/* Start NIST DRBG code */
#ifdef HAVE_HASHDRBG

#define OUTPUT_BLOCK_LEN  (WC_SHA256_DIGEST_SIZE)
#define MAX_REQUEST_LEN   (0x10000)
#define RESEED_INTERVAL   WC_RESEED_INTERVAL


/* The security strength for the RNG is the target number of bits of
 * entropy you are looking for in a seed. */
#ifndef RNG_SECURITY_STRENGTH
    #if defined(HAVE_FIPS) && \
        defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION >= 2)
        /* SHA-256 requires a minimum of 256-bits of entropy. The goal
         * of 1024 will provide 4 times that. */
        #define RNG_SECURITY_STRENGTH (1024)
    #else
        /* If not using FIPS or using old FIPS, set the number down a bit.
         * More is better, but more is also slower. */
        #define RNG_SECURITY_STRENGTH (256)
    #endif
#endif

#ifndef ENTROPY_SCALE_FACTOR
    /* The entropy scale factor should be the whole number inverse of the
     * minimum bits of entropy per bit of NDRNG output. */
    #if defined(HAVE_INTEL_RDSEED) || defined(HAVE_INTEL_RDRAND)
        /* The value of 2 applies to Intel's RDSEED which provides about
         * 0.5 bits minimum of entropy per bit. */
        #define ENTROPY_SCALE_FACTOR 2
    #else
        /* Setting the default to 1. */
        #define ENTROPY_SCALE_FACTOR 1
    #endif
#endif

#ifndef SEED_BLOCK_SZ
    /* The seed block size, is the size of the output of the underlying NDRNG.
     * This value is used for testing the output of the NDRNG. */
    #if defined(HAVE_INTEL_RDSEED) || defined(HAVE_INTEL_RDRAND)
        /* RDSEED outputs in blocks of 64-bits. */
        #define SEED_BLOCK_SZ sizeof(word64)
    #else
        /* Setting the default to 4. */
        #define SEED_BLOCK_SZ 4
    #endif
#endif

#define SEED_SZ        (RNG_SECURITY_STRENGTH*ENTROPY_SCALE_FACTOR/8)

/* The maximum seed size will be the seed size plus a seed block for the
 * test, and an additional half of the seed size. This additional half
 * is in case the user does not supply a nonce. A nonce will be obtained
 * from the NDRNG. */
#define MAX_SEED_SZ    (SEED_SZ + SEED_SZ/2 + SEED_BLOCK_SZ)


/* Internal return codes */
#define DRBG_SUCCESS      0
#define DRBG_FAILURE      1
#define DRBG_NEED_RESEED  2
#define DRBG_CONT_FAILURE 3

/* RNG health states */
#define DRBG_NOT_INIT     0
#define DRBG_OK           1
#define DRBG_FAILED       2
#define DRBG_CONT_FAILED  3

#define RNG_HEALTH_TEST_CHECK_SIZE (WC_SHA256_DIGEST_SIZE * 4)

/* Verify max gen block len */
#if RNG_MAX_BLOCK_LEN > MAX_REQUEST_LEN
    #error RNG_MAX_BLOCK_LEN is larger than NIST DBRG max request length
#endif

enum {
    drbgInitC     = 0,
    drbgReseed    = 1,
    drbgGenerateW = 2,
    drbgGenerateH = 3,
    drbgInitV     = 4
};

typedef struct DRBG_internal DRBG_internal;

static int wc_RNG_HealthTestLocal(int reseed);

/* Hash Derivation Function */
/* Returns: DRBG_SUCCESS or DRBG_FAILURE */
static int Hash_df(DRBG_internal* drbg, byte* out, word32 outSz, byte type,
                                                  const byte* inA, word32 inASz,
                                                  const byte* inB, word32 inBSz)
{
    int ret = DRBG_FAILURE;
    byte ctr;
    int i;
    int len;
    word32 bits = (outSz * 8); /* reverse byte order */
#ifdef WOLFSSL_SMALL_STACK_CACHE
    wc_Sha256* sha = &drbg->sha256;
#else
    wc_Sha256 sha[1];
#endif
    byte digest[WC_SHA256_DIGEST_SIZE];

    (void)drbg;

#ifdef LITTLE_ENDIAN_ORDER
    bits = ByteReverseWord32(bits);
#endif
    len = (outSz / OUTPUT_BLOCK_LEN)
        + ((outSz % OUTPUT_BLOCK_LEN) ? 1 : 0);

    for (i = 0, ctr = 1; i < len; i++, ctr++) {
#ifndef WOLFSSL_SMALL_STACK_CACHE
        ret = wc_InitSha256(sha);
        if (ret != 0)
            break;

        if (ret == 0)
#endif
            ret = wc_Sha256Update(sha, &ctr, sizeof(ctr));
        if (ret == 0)
            ret = wc_Sha256Update(sha, (byte*)&bits, sizeof(bits));

        if (ret == 0) {
            /* churning V is the only string that doesn't have the type added */
            if (type != drbgInitV)
                ret = wc_Sha256Update(sha, &type, sizeof(type));
        }
        if (ret == 0)
            ret = wc_Sha256Update(sha, inA, inASz);
        if (ret == 0) {
            if (inB != NULL && inBSz > 0)
                ret = wc_Sha256Update(sha, inB, inBSz);
        }
        if (ret == 0)
            ret = wc_Sha256Final(sha, digest);

#ifndef WOLFSSL_SMALL_STACK_CACHE
        wc_Sha256Free(sha);
#endif
        if (ret == 0) {
            if (outSz > OUTPUT_BLOCK_LEN) {
                XMEMCPY(out, digest, OUTPUT_BLOCK_LEN);
                outSz -= OUTPUT_BLOCK_LEN;
                out += OUTPUT_BLOCK_LEN;
            }
            else {
                XMEMCPY(out, digest, outSz);
            }
        }
    }

    ForceZero(digest, WC_SHA256_DIGEST_SIZE);

    return (ret == 0) ? DRBG_SUCCESS : DRBG_FAILURE;
}

/* Returns: DRBG_SUCCESS or DRBG_FAILURE */
static int Hash_DRBG_Reseed(DRBG_internal* drbg, const byte* seed, word32 seedSz)
{
    byte newV[DRBG_SEED_LEN];

    XMEMSET(newV, 0, DRBG_SEED_LEN);

    if (Hash_df(drbg, newV, sizeof(newV), drbgReseed,
                drbg->V, sizeof(drbg->V), seed, seedSz) != DRBG_SUCCESS) {
        return DRBG_FAILURE;
    }

    XMEMCPY(drbg->V, newV, sizeof(drbg->V));
    ForceZero(newV, sizeof(newV));

    if (Hash_df(drbg, drbg->C, sizeof(drbg->C), drbgInitC, drbg->V,
                                    sizeof(drbg->V), NULL, 0) != DRBG_SUCCESS) {
        return DRBG_FAILURE;
    }

    drbg->reseedCtr = 1;
    drbg->lastBlock = 0;
    drbg->matchCount = 0;
    return DRBG_SUCCESS;
}

/* Returns: DRBG_SUCCESS and DRBG_FAILURE or BAD_FUNC_ARG on fail */
int wc_RNG_DRBG_Reseed(WC_RNG* rng, const byte* seed, word32 seedSz)
{
    if (rng == NULL || seed == NULL) {
        return BAD_FUNC_ARG;
    }

    return Hash_DRBG_Reseed((DRBG_internal *)rng->drbg, seed, seedSz);
}

static WC_INLINE void array_add_one(byte* data, word32 dataSz)
{
    int i;

    for (i = dataSz - 1; i >= 0; i--)
    {
        data[i]++;
        if (data[i] != 0) break;
    }
}

/* Returns: DRBG_SUCCESS or DRBG_FAILURE */
static int Hash_gen(DRBG_internal* drbg, byte* out, word32 outSz, const byte* V)
{
    int ret = DRBG_FAILURE;
    byte data[DRBG_SEED_LEN];
    int i;
    int len;
    word32 checkBlock;
    wc_Sha256 sha[1];
    byte digest[WC_SHA256_DIGEST_SIZE];

    /* Special case: outSz is 0 and out is NULL. wc_Generate a block to save for
     * the continuous test. */

    if (outSz == 0) outSz = 1;

    len = (outSz / OUTPUT_BLOCK_LEN) + ((outSz % OUTPUT_BLOCK_LEN) ? 1 : 0);

    XMEMCPY(data, V, sizeof(data));
    for (i = 0; i < len; i++) {
#ifndef WOLFSSL_SMALL_STACK_CACHE
        ret = wc_InitSha256(sha);
        if (ret == 0)
#endif
            ret = wc_Sha256Update(sha, data, sizeof(data));
        if (ret == 0)
            ret = wc_Sha256Final(sha, digest);
#ifndef WOLFSSL_SMALL_STACK_CACHE
        wc_Sha256Free(sha);
#endif

        if (ret == 0) {
            XMEMCPY(&checkBlock, digest, sizeof(word32));
            if (drbg->reseedCtr > 1 && checkBlock == drbg->lastBlock) {
                if (drbg->matchCount == 1) {
                    return DRBG_CONT_FAILURE;
                }
                else {
                    if (i == (len-1)) {
                        len++;
                    }
                    drbg->matchCount = 1;
                }
            }
            else {
                drbg->matchCount = 0;
                drbg->lastBlock = checkBlock;
            }

            if (out != NULL && outSz != 0) {
                if (outSz >= OUTPUT_BLOCK_LEN) {
                    XMEMCPY(out, digest, OUTPUT_BLOCK_LEN);
                    outSz -= OUTPUT_BLOCK_LEN;
                    out += OUTPUT_BLOCK_LEN;
                    array_add_one(data, DRBG_SEED_LEN);
                }
                else {
                    XMEMCPY(out, digest, outSz);
                    outSz = 0;
                }
            }
        }
        else {
            /* wc_Sha256Update or wc_Sha256Final returned error */
            break;
        }
    }
    ForceZero(data, sizeof(data));

    return (ret == 0) ? DRBG_SUCCESS : DRBG_FAILURE;
}

static WC_INLINE void array_add(byte* d, word32 dLen, const byte* s, word32 sLen)
{
    word16 carry = 0;

    if (dLen > 0 && sLen > 0 && dLen >= sLen) {
        int sIdx, dIdx;

        for (sIdx = sLen - 1, dIdx = dLen - 1; sIdx >= 0; dIdx--, sIdx--) {
            carry += (word16)d[dIdx] + (word16)s[sIdx];
            d[dIdx] = (byte)carry;
            carry >>= 8;
        }

        for (; carry != 0 && dIdx >= 0; dIdx--) {
            carry += (word16)d[dIdx];
            d[dIdx] = (byte)carry;
            carry >>= 8;
        }
    }
}

/* Returns: DRBG_SUCCESS, DRBG_NEED_RESEED, or DRBG_FAILURE */
static int Hash_DRBG_Generate(DRBG_internal* drbg, byte* out, word32 outSz)
{
    int ret;
    wc_Sha256 sha[1];
    byte type;
    word32 reseedCtr;

    if (drbg->reseedCtr == RESEED_INTERVAL) {
        return DRBG_NEED_RESEED;
    } else {
        byte digest[WC_SHA256_DIGEST_SIZE];
        type = drbgGenerateH;
        reseedCtr = drbg->reseedCtr;

        ret = Hash_gen(drbg, out, outSz, drbg->V);
        if (ret == DRBG_SUCCESS) {
#ifndef WOLFSSL_SMALL_STACK_CACHE
            ret = wc_InitSha256(sha);
            if (ret == 0)
#endif
                ret = wc_Sha256Update(sha, &type, sizeof(type));
            if (ret == 0)
                ret = wc_Sha256Update(sha, drbg->V, sizeof(drbg->V));
            if (ret == 0)
                ret = wc_Sha256Final(sha, digest);

#ifndef WOLFSSL_SMALL_STACK_CACHE
            wc_Sha256Free(sha);
#endif

            if (ret == 0) {
                array_add(drbg->V, sizeof(drbg->V), digest, WC_SHA256_DIGEST_SIZE);
                array_add(drbg->V, sizeof(drbg->V), drbg->C, sizeof(drbg->C));
            #ifdef LITTLE_ENDIAN_ORDER
                reseedCtr = ByteReverseWord32(reseedCtr);
            #endif
                array_add(drbg->V, sizeof(drbg->V),
                                          (byte*)&reseedCtr, sizeof(reseedCtr));
                ret = DRBG_SUCCESS;
            }
            drbg->reseedCtr++;
        }
        ForceZero(digest, WC_SHA256_DIGEST_SIZE);
    }

    return (ret == 0) ? DRBG_SUCCESS : DRBG_FAILURE;
}

/* Returns: DRBG_SUCCESS or DRBG_FAILURE */
static int Hash_DRBG_Instantiate(DRBG_internal* drbg, const byte* seed, word32 seedSz,
                                             const byte* nonce, word32 nonceSz,
                                             void* heap, int devId)
{
    int ret = DRBG_FAILURE;

    XMEMSET(drbg, 0, sizeof(DRBG_internal));
    (void)heap;
    (void)devId;

    if (Hash_df(drbg, drbg->V, sizeof(drbg->V), drbgInitV, seed, seedSz,
                                              nonce, nonceSz) == DRBG_SUCCESS &&
        Hash_df(drbg, drbg->C, sizeof(drbg->C), drbgInitC, drbg->V,
                                    sizeof(drbg->V), NULL, 0) == DRBG_SUCCESS) {

        drbg->reseedCtr = 1;
        drbg->lastBlock = 0;
        drbg->matchCount = 0;
        ret = DRBG_SUCCESS;
    }

    return ret;
}

/* Returns: DRBG_SUCCESS or DRBG_FAILURE */
static int Hash_DRBG_Uninstantiate(DRBG_internal* drbg)
{
    word32 i;
    int    compareSum = 0;
    byte*  compareDrbg = (byte*)drbg;

    ForceZero(drbg, sizeof(DRBG_internal));

    for (i = 0; i < sizeof(DRBG_internal); i++)
        compareSum |= compareDrbg[i] ^ 0;

    return (compareSum == 0) ? DRBG_SUCCESS : DRBG_FAILURE;
}


int wc_RNG_TestSeed(const byte* seed, word32 seedSz)
{
    int ret = 0;

    /* Check the seed for duplicate words. */
    word32 seedIdx = 0;
    word32 scratchSz = min(SEED_BLOCK_SZ, seedSz - SEED_BLOCK_SZ);

    while (seedIdx < seedSz - SEED_BLOCK_SZ) {
        if (ConstantCompare(seed + seedIdx,
                            seed + seedIdx + scratchSz,
                            scratchSz) == 0) {

            ret = DRBG_CONT_FAILURE;
        }
        seedIdx += SEED_BLOCK_SZ;
        scratchSz = min(SEED_BLOCK_SZ, (seedSz - seedIdx));
    }

    return ret;
}
#endif /* HAVE_HASHDRBG */
/* End NIST DRBG Code */


static int _InitRng(WC_RNG* rng, byte* nonce, word32 nonceSz,
                    void* heap, int devId)
{
    int ret = 0;
#ifdef HAVE_HASHDRBG
    word32 seedSz = SEED_SZ + SEED_BLOCK_SZ;
#endif

    (void)nonce;
    (void)nonceSz;

    if (rng == NULL)
        return BAD_FUNC_ARG;
    if (nonce == NULL && nonceSz != 0)
        return BAD_FUNC_ARG;

#ifdef WOLFSSL_HEAP_TEST
    rng->heap = (void*)WOLFSSL_HEAP_TEST;
    (void)heap;
#else
    rng->heap = heap;
#endif
    (void)devId;

#ifdef HAVE_HASHDRBG
    /* init the DBRG to known values */
    rng->drbg = NULL;
    rng->status = DRBG_NOT_INIT;
#endif

#ifdef CUSTOM_RAND_GENERATE_BLOCK
    ret = 0; /* success */
#else
#ifdef HAVE_HASHDRBG
    if (nonceSz == 0)
        seedSz = MAX_SEED_SZ;

    if (wc_RNG_HealthTestLocal(0) == 0) {
        byte seed[MAX_SEED_SZ];

#if !defined(WOLFSSL_NO_MALLOC) || defined(WOLFSSL_STATIC_MEMORY)
        rng->drbg =
                (struct DRBG*)XMALLOC(sizeof(DRBG_internal), rng->heap,
                                                          DYNAMIC_TYPE_RNG);
        if (rng->drbg == NULL) {
            ret = MEMORY_E;
            rng->status = DRBG_FAILED;
        }
#else
        rng->drbg = (struct DRBG*)&rng->drbg_data;
#endif
        if (ret == 0) {
            ret = wc_GenerateSeed(&rng->seed, seed, seedSz);
            if (ret == 0)
                ret = wc_RNG_TestSeed(seed, seedSz);
            else {
                ret = DRBG_FAILURE;
                rng->status = DRBG_FAILED;
            }

            if (ret == DRBG_SUCCESS)
                ret = Hash_DRBG_Instantiate((DRBG_internal *)rng->drbg,
                            seed + SEED_BLOCK_SZ, seedSz - SEED_BLOCK_SZ,
                            nonce, nonceSz, rng->heap, devId);

            if (ret != DRBG_SUCCESS) {
            #if !defined(WOLFSSL_NO_MALLOC) || defined(WOLFSSL_STATIC_MEMORY)
                XFREE(rng->drbg, rng->heap, DYNAMIC_TYPE_RNG);
            #endif
                rng->drbg = NULL;
            }
        }

        ForceZero(seed, seedSz);
    }
    else
        ret = DRBG_CONT_FAILURE;

    if (ret == DRBG_SUCCESS) {
        rng->status = DRBG_OK;
        ret = 0;
    }
    else if (ret == DRBG_CONT_FAILURE) {
        rng->status = DRBG_CONT_FAILED;
        ret = DRBG_CONT_FIPS_E;
    }
    else if (ret == DRBG_FAILURE) {
        rng->status = DRBG_FAILED;
        ret = RNG_FAILURE_E;
    }
    else {
        rng->status = DRBG_FAILED;
    }
#endif /* HAVE_HASHDRBG */
#endif /* CUSTOM_RAND_GENERATE_BLOCK */

    return ret;
}

#ifndef WOLFSSL_DO178_MAX_RNG
    #define WOLFSSL_DO178_MAX_RNG 4
#endif
static byte rng_buffer[WOLFSSL_DO178_MAX_RNG][sizeof(WC_RNG)];
static int rng_in_use[WOLFSSL_DO178_MAX_RNG] = {0};

WOLFSSL_ABI
WC_RNG* wc_rng_new(byte* nonce, word32 nonceSz, void* heap)
{
    WC_RNG* rng = NULL;
    int i;
#ifndef WOLFSSL_NO_MALLOC
    rng = (WC_RNG*)XMALLOC(sizeof(WC_RNG), heap, DYNAMIC_TYPE_RNG);
#else
    for (i = 0; i < WOLFSSL_DO178_MAX_RNG; i++) {
        if (rng_in_use[i] == 0) {
            rng_in_use[i]++;
            rng = (WC_RNG*)rng_buffer[i];
            break;
        }
    }
#endif
    if (rng) {
        int error = _InitRng(rng, nonce, nonceSz, heap, INVALID_DEVID) != 0;
        if (error) {
#ifndef WOLFSSL_NO_MALLOC
            XFREE(rng, heap, DYNAMIC_TYPE_RNG);
#else
            rng_in_use[i] = 0;
#endif
            rng = NULL;
        }
    }

    return rng;
}


WOLFSSL_ABI
void wc_rng_free(WC_RNG* rng)
{
    if (rng) {
        void* heap = rng->heap;

        wc_FreeRng(rng);
        ForceZero(rng, sizeof(WC_RNG));
#ifndef WOLFSSL_NO_MALLOC
        XFREE(rng, heap, DYNAMIC_TYPE_RNG);
#else
    for (int i = 0; i < WOLFSSL_DO178_MAX_RNG; i++) {
        if (rng == (WC_RNG*)rng_buffer[i]) {
            rng_in_use[i] = 0;
            return;
        }
    }
#endif
        (void)heap;
    }
}


int wc_InitRng(WC_RNG* rng)
{
    return _InitRng(rng, NULL, 0, NULL, INVALID_DEVID);
}


int wc_InitRng_ex(WC_RNG* rng, void* heap, int devId)
{
    return _InitRng(rng, NULL, 0, heap, devId);
}


int wc_InitRngNonce(WC_RNG* rng, byte* nonce, word32 nonceSz)
{
    return _InitRng(rng, nonce, nonceSz, NULL, INVALID_DEVID);
}


int wc_InitRngNonce_ex(WC_RNG* rng, byte* nonce, word32 nonceSz,
                       void* heap, int devId)
{
    return _InitRng(rng, nonce, nonceSz, heap, devId);
}


/* place a generated block in output */
WOLFSSL_ABI
int wc_RNG_GenerateBlock(WC_RNG* rng, byte* output, word32 sz)
{
    int ret;

    if (rng == NULL || output == NULL)
        return BAD_FUNC_ARG;

    if (sz == 0)
        return 0; 

#ifdef CUSTOM_RAND_GENERATE_BLOCK
    XMEMSET(output, 0, sz);
    ret = CUSTOM_RAND_GENERATE_BLOCK(output, sz);
#else

#ifdef HAVE_HASHDRBG
    if (sz > RNG_MAX_BLOCK_LEN)
        return BAD_FUNC_ARG;

    if (rng->status != DRBG_OK)
        return RNG_FAILURE_E;

    ret = Hash_DRBG_Generate((DRBG_internal *)rng->drbg, output, sz);
    if (ret == DRBG_NEED_RESEED) {
        if (wc_RNG_HealthTestLocal(1) == 0) {
            byte newSeed[SEED_SZ + SEED_BLOCK_SZ];

            ret = wc_GenerateSeed(&rng->seed, newSeed,
                                  SEED_SZ + SEED_BLOCK_SZ);
            if (ret != 0)
                ret = DRBG_FAILURE;
            else
                ret = wc_RNG_TestSeed(newSeed, SEED_SZ + SEED_BLOCK_SZ);

            if (ret == DRBG_SUCCESS)
	      ret = Hash_DRBG_Reseed((DRBG_internal *)rng->drbg, newSeed + SEED_BLOCK_SZ,
                                       SEED_SZ);
            if (ret == DRBG_SUCCESS)
	      ret = Hash_DRBG_Generate((DRBG_internal *)rng->drbg, output, sz);

            ForceZero(newSeed, sizeof(newSeed));
        }
        else
            ret = DRBG_CONT_FAILURE;
    }

    if (ret == DRBG_SUCCESS) {
        ret = 0;
    }
    else if (ret == DRBG_CONT_FAILURE) {
        ret = DRBG_CONT_FIPS_E;
        rng->status = DRBG_CONT_FAILED;
    }
    else {
        ret = RNG_FAILURE_E;
        rng->status = DRBG_FAILED;
    }
#else

    /* if we get here then there is an RNG configuration error */
    ret = RNG_FAILURE_E;

#endif /* HAVE_HASHDRBG */
#endif /* CUSTOM_RAND_GENERATE_BLOCK */

    return ret;
}


int wc_RNG_GenerateByte(WC_RNG* rng, byte* b)
{
    return wc_RNG_GenerateBlock(rng, b, 1);
}


int wc_FreeRng(WC_RNG* rng)
{
    int ret = 0;

    if (rng == NULL)
        return BAD_FUNC_ARG;

#ifdef HAVE_HASHDRBG
    if (rng->drbg != NULL) {
      if (Hash_DRBG_Uninstantiate((DRBG_internal *)rng->drbg) != DRBG_SUCCESS)
            ret = RNG_FAILURE_E;

    #if !defined(WOLFSSL_NO_MALLOC) || defined(WOLFSSL_STATIC_MEMORY)
        XFREE(rng->drbg, rng->heap, DYNAMIC_TYPE_RNG);
    #endif
        rng->drbg = NULL;
    }

    rng->status = DRBG_NOT_INIT;
#endif /* HAVE_HASHDRBG */

    return ret;
}

#ifdef HAVE_HASHDRBG
int wc_RNG_HealthTest(int reseed, const byte* seedA, word32 seedASz,
                                  const byte* seedB, word32 seedBSz,
                                  byte* output, word32 outputSz)
{
    return wc_RNG_HealthTest_ex(reseed, NULL, 0,
                                seedA, seedASz, seedB, seedBSz,
                                output, outputSz,
                                NULL, INVALID_DEVID);
}


int wc_RNG_HealthTest_ex(int reseed, const byte* nonce, word32 nonceSz,
                                  const byte* seedA, word32 seedASz,
                                  const byte* seedB, word32 seedBSz,
                                  byte* output, word32 outputSz,
                                  void* heap, int devId)
{
    int ret = -1;
    DRBG_internal* drbg;
#ifndef WOLFSSL_SMALL_STACK
    DRBG_internal  drbg_var;
#endif

    if (seedA == NULL || output == NULL) {
        return BAD_FUNC_ARG;
    }

    if (reseed != 0 && seedB == NULL) {
        return BAD_FUNC_ARG;
    }

    if (outputSz != RNG_HEALTH_TEST_CHECK_SIZE) {
        return ret;
    }

#ifdef WOLFSSL_SMALL_STACK
#else
    drbg = &drbg_var;
#endif

    if (Hash_DRBG_Instantiate(drbg, seedA, seedASz, nonce, nonceSz,
                              heap, devId) != 0) {
        goto exit_rng_ht;
    }

    if (reseed) {
        if (Hash_DRBG_Reseed(drbg, seedB, seedBSz) != 0) {
            goto exit_rng_ht;
        }
    }

    /* This call to generate is prescribed by the NIST DRBGVS
     * procedure. The results are thrown away. The known
     * answer test checks the second block of DRBG out of
     * the generator to ensure the internal state is updated
     * as expected. */
    if (Hash_DRBG_Generate(drbg, output, outputSz) != 0) {
        goto exit_rng_ht;
    }

    if (Hash_DRBG_Generate(drbg, output, outputSz) != 0) {
        goto exit_rng_ht;
    }

    /* Mark success */
    ret = 0;

exit_rng_ht:

    /* This is safe to call even if Hash_DRBG_Instantiate fails */
    if (Hash_DRBG_Uninstantiate(drbg) != 0) {
        ret = -1;
    }

#ifdef WOLFSSL_SMALL_STACK
    XFREE(drbg, NULL, DYNAMIC_TYPE_RNG);
#endif

    return ret;
}


const FLASH_QUALIFIER byte seedA_data[] = {
    0x63, 0x36, 0x33, 0x77, 0xe4, 0x1e, 0x86, 0x46, 0x8d, 0xeb, 0x0a, 0xb4,
    0xa8, 0xed, 0x68, 0x3f, 0x6a, 0x13, 0x4e, 0x47, 0xe0, 0x14, 0xc7, 0x00,
    0x45, 0x4e, 0x81, 0xe9, 0x53, 0x58, 0xa5, 0x69, 0x80, 0x8a, 0xa3, 0x8f,
    0x2a, 0x72, 0xa6, 0x23, 0x59, 0x91, 0x5a, 0x9f, 0x8a, 0x04, 0xca, 0x68
};

const FLASH_QUALIFIER byte reseedSeedA_data[] = {
    0xe6, 0x2b, 0x8a, 0x8e, 0xe8, 0xf1, 0x41, 0xb6, 0x98, 0x05, 0x66, 0xe3,
    0xbf, 0xe3, 0xc0, 0x49, 0x03, 0xda, 0xd4, 0xac, 0x2c, 0xdf, 0x9f, 0x22,
    0x80, 0x01, 0x0a, 0x67, 0x39, 0xbc, 0x83, 0xd3
};

const FLASH_QUALIFIER byte outputA_data[] = {
    0x04, 0xee, 0xc6, 0x3b, 0xb2, 0x31, 0xdf, 0x2c, 0x63, 0x0a, 0x1a, 0xfb,
    0xe7, 0x24, 0x94, 0x9d, 0x00, 0x5a, 0x58, 0x78, 0x51, 0xe1, 0xaa, 0x79,
    0x5e, 0x47, 0x73, 0x47, 0xc8, 0xb0, 0x56, 0x62, 0x1c, 0x18, 0xbd, 0xdc,
    0xdd, 0x8d, 0x99, 0xfc, 0x5f, 0xc2, 0xb9, 0x20, 0x53, 0xd8, 0xcf, 0xac,
    0xfb, 0x0b, 0xb8, 0x83, 0x12, 0x05, 0xfa, 0xd1, 0xdd, 0xd6, 0xc0, 0x71,
    0x31, 0x8a, 0x60, 0x18, 0xf0, 0x3b, 0x73, 0xf5, 0xed, 0xe4, 0xd4, 0xd0,
    0x71, 0xf9, 0xde, 0x03, 0xfd, 0x7a, 0xea, 0x10, 0x5d, 0x92, 0x99, 0xb8,
    0xaf, 0x99, 0xaa, 0x07, 0x5b, 0xdb, 0x4d, 0xb9, 0xaa, 0x28, 0xc1, 0x8d,
    0x17, 0x4b, 0x56, 0xee, 0x2a, 0x01, 0x4d, 0x09, 0x88, 0x96, 0xff, 0x22,
    0x82, 0xc9, 0x55, 0xa8, 0x19, 0x69, 0xe0, 0x69, 0xfa, 0x8c, 0xe0, 0x07,
    0xa1, 0x80, 0x18, 0x3a, 0x07, 0xdf, 0xae, 0x17
};

const FLASH_QUALIFIER byte seedB_data[] = {
    0xa6, 0x5a, 0xd0, 0xf3, 0x45, 0xdb, 0x4e, 0x0e, 0xff, 0xe8, 0x75, 0xc3,
    0xa2, 0xe7, 0x1f, 0x42, 0xc7, 0x12, 0x9d, 0x62, 0x0f, 0xf5, 0xc1, 0x19,
    0xa9, 0xef, 0x55, 0xf0, 0x51, 0x85, 0xe0, 0xfb, /* nonce next */
    0x85, 0x81, 0xf9, 0x31, 0x75, 0x17, 0x27, 0x6e, 0x06, 0xe9, 0x60, 0x7d,
    0xdb, 0xcb, 0xcc, 0x2e
};

const FLASH_QUALIFIER byte outputB_data[] = {
    0xd3, 0xe1, 0x60, 0xc3, 0x5b, 0x99, 0xf3, 0x40, 0xb2, 0x62, 0x82, 0x64,
    0xd1, 0x75, 0x10, 0x60, 0xe0, 0x04, 0x5d, 0xa3, 0x83, 0xff, 0x57, 0xa5,
    0x7d, 0x73, 0xa6, 0x73, 0xd2, 0xb8, 0xd8, 0x0d, 0xaa, 0xf6, 0xa6, 0xc3,
    0x5a, 0x91, 0xbb, 0x45, 0x79, 0xd7, 0x3f, 0xd0, 0xc8, 0xfe, 0xd1, 0x11,
    0xb0, 0x39, 0x13, 0x06, 0x82, 0x8a, 0xdf, 0xed, 0x52, 0x8f, 0x01, 0x81,
    0x21, 0xb3, 0xfe, 0xbd, 0xc3, 0x43, 0xe7, 0x97, 0xb8, 0x7d, 0xbb, 0x63,
    0xdb, 0x13, 0x33, 0xde, 0xd9, 0xd1, 0xec, 0xe1, 0x77, 0xcf, 0xa6, 0xb7,
    0x1f, 0xe8, 0xab, 0x1d, 0xa4, 0x66, 0x24, 0xed, 0x64, 0x15, 0xe5, 0x1c,
    0xcd, 0xe2, 0xc7, 0xca, 0x86, 0xe2, 0x83, 0x99, 0x0e, 0xea, 0xeb, 0x91,
    0x12, 0x04, 0x15, 0x52, 0x8b, 0x22, 0x95, 0x91, 0x02, 0x81, 0xb0, 0x2d,
    0xd4, 0x31, 0xf4, 0xc9, 0xf7, 0x04, 0x27, 0xdf
};


static int wc_RNG_HealthTestLocal(int reseed)
{
    int ret = 0;
#ifdef WOLFSSL_SMALL_STACK
    byte* check;
#else
    byte  check[RNG_HEALTH_TEST_CHECK_SIZE];
#endif


    if (reseed) {
#ifdef WOLFSSL_USE_FLASHMEM
#else
        const byte* seedA = seedA_data;
        const byte* reseedSeedA = reseedSeedA_data;
        const byte* outputA = outputA_data;
#endif
        ret = wc_RNG_HealthTest(1, seedA, sizeof(seedA_data),
                                reseedSeedA, sizeof(reseedSeedA_data),
                                check, RNG_HEALTH_TEST_CHECK_SIZE);
        if (ret == 0) {
            if (ConstantCompare(check, outputA,
                                RNG_HEALTH_TEST_CHECK_SIZE) != 0)
                ret = -1;
        }

#ifdef WOLFSSL_USE_FLASHMEM
#endif
    }
    else {
#ifdef WOLFSSL_USE_FLASHMEM
#else
        const byte* seedB = seedB_data;
        const byte* outputB = outputB_data;
#endif
        ret = wc_RNG_HealthTest(0, seedB, sizeof(seedB_data),
                                NULL, 0,
                                check, RNG_HEALTH_TEST_CHECK_SIZE);
        if (ret == 0) {
            if (ConstantCompare(check, outputB,
                                RNG_HEALTH_TEST_CHECK_SIZE) != 0)
                ret = -1;
        }

        /* The previous test cases use a large seed instead of a seed and nonce.
         * seedB is actually from a test case with a seed and nonce, and
         * just concatenates them. The pivot point between seed and nonce is
         * byte 32, feed them into the health test separately. */
        if (ret == 0) {
            ret = wc_RNG_HealthTest_ex(0,
                                    seedB + 32, sizeof(seedB_data) - 32,
                                    seedB, 32,
                                    NULL, 0,
                                    check, RNG_HEALTH_TEST_CHECK_SIZE,
                                    NULL, INVALID_DEVID);
            if (ret == 0) {
                if (ConstantCompare(check, outputB, sizeof(outputB_data)) != 0)
                    ret = -1;
            }
        }
    }

    return ret;
}

#endif /* HAVE_HASHDRBG */

/* Begin wc_GenerateSeed Implementations */
#if defined(CUSTOM_RAND_GENERATE_SEED)

    /* Implement your own random generation function
     * Return 0 to indicate success
     * int rand_gen_seed(byte* output, word32 sz);
     * #define CUSTOM_RAND_GENERATE_SEED  rand_gen_seed */

    int wc_GenerateSeed(OS_Seed* os, byte* output, word32 sz)
    {
        (void)os; /* Suppress unused arg warning */
        return CUSTOM_RAND_GENERATE_SEED(output, sz);
    }

#elif defined(CUSTOM_RAND_GENERATE_SEED_OS)

    /* Implement your own random generation function,
     *  which includes OS_Seed.
     * Return 0 to indicate success
     * int rand_gen_seed(OS_Seed* os, byte* output, word32 sz);
     * #define CUSTOM_RAND_GENERATE_SEED_OS  rand_gen_seed */

    int wc_GenerateSeed(OS_Seed* os, byte* output, word32 sz)
    {
        return CUSTOM_RAND_GENERATE_SEED_OS(os, output, sz);
    }

#elif defined(CUSTOM_RAND_GENERATE)

   /* Implement your own random generation function
    * word32 rand_gen(void);
    * #define CUSTOM_RAND_GENERATE  rand_gen  */

    int wc_GenerateSeed(OS_Seed* os, byte* output, word32 sz)
    {
        word32 i = 0;

        (void)os;

        while (i < sz)
        {
            /* If not aligned or there is odd/remainder */
            if( (i + sizeof(CUSTOM_RAND_TYPE)) > sz ||
                ((wolfssl_word)&output[i] % sizeof(CUSTOM_RAND_TYPE)) != 0
            ) {
                /* Single byte at a time */
                output[i++] = (byte)CUSTOM_RAND_GENERATE();
            }
            else {
                /* Use native 8, 16, 32 or 64 copy instruction */
                *((CUSTOM_RAND_TYPE*)&output[i]) = CUSTOM_RAND_GENERATE();
                i += sizeof(CUSTOM_RAND_TYPE);
            }
        }

        return 0;
    }

#elif defined(WOLFSSL_SGX)

#elif defined(CUSTOM_RAND_GENERATE_BLOCK)
    /* #define CUSTOM_RAND_GENERATE_BLOCK myRngFunc
     * extern int myRngFunc(byte* output, word32 sz);
     */

#elif defined(WOLFSSL_SAFERTOS) || defined(WOLFSSL_LEANPSK) || \
      defined(WOLFSSL_IAR_ARM)  || defined(WOLFSSL_MDK_ARM) || \
      defined(WOLFSSL_uITRON4)  || defined(WOLFSSL_uTKERNEL2) || \
      defined(WOLFSSL_LPC43xx)  || defined(WOLFSSL_STM32F2xx) || \
      defined(MBED)             || defined(WOLFSSL_EMBOS) || \
      defined(WOLFSSL_GENSEED_FORTEST) || defined(WOLFSSL_CHIBIOS) || \
      defined(WOLFSSL_CONTIKI)  || defined(WOLFSSL_AZSPHERE)

    /* these platforms do not have a default random seed and
       you'll need to implement your own wc_GenerateSeed or define via
       CUSTOM_RAND_GENERATE_BLOCK */

    #define USE_TEST_GENSEED

#elif defined(NO_DEV_RANDOM)

    #error "you need to write an os specific wc_GenerateSeed() here"

    /*
    int wc_GenerateSeed(OS_Seed* os, byte* output, word32 sz)
    {
        return 0;
    }
    */

#else

    /* may block */
    int wc_GenerateSeed(OS_Seed* os, byte* output, word32 sz)
    {
        int ret = 0;

        if (os == NULL) {
            return BAD_FUNC_ARG;
        }

    #ifndef NO_DEV_URANDOM /* way to disable use of /dev/urandom */
        os->fd = open("/dev/urandom", O_RDONLY);
        if (os->fd == -1)
    #endif
        {
            /* may still have /dev/random */
            os->fd = open("/dev/random", O_RDONLY);
            if (os->fd == -1)
                return OPEN_RAN_E;
        }

        while (sz) {
            int len = (int)read(os->fd, output, sz);
            if (len == -1) {
                ret = READ_RAN_E;
                break;
            }

            sz     -= len;
            output += len;

            if (sz) {
    #if defined(BLOCKING) || defined(WC_RNG_BLOCKING)
                sleep(0);             /* context switch */
    #else
                ret = RAN_BLOCK_E;
                break;
    #endif
            }
        }
        close(os->fd);

        return ret;
    }

#endif

#ifdef USE_TEST_GENSEED

    int wc_GenerateSeed(OS_Seed* os, byte* output, word32 sz)
    {
        word32 i;
        for (i = 0; i < sz; i++ )
            output[i] = i;

        (void)os;

        return 0;
    }
#endif


/* End wc_GenerateSeed */
#endif /* WC_NO_RNG */
