/* user_settings.h
 *
 * Copyright (C) 2006-2021 wolfSSL Inc.  All rights reserved.
 *
 * This file is part of wolfSSL.
 *
 * Contact licensing@wolfssl.com with any questions or comments.
 *
 * https://www.wolfssl.com
 */


#ifndef WOLFSSL_SETTINGS_H
#define WOLFSSL_SETTINGS_H

#ifdef __cplusplus
extern "C" {
#endif

/*
DO-178C wolfCrypt Algorithms:

AES-GCM
    IV Generation: external
    Key Length: 256

*/
/* ------------------------------------------------------------------------- */
/* From Makefile flags */
/* ------------------------------------------------------------------------- */
#ifndef WOLFSSL_USER_SETTINGS
    #define WOLFSSL_USER_SETTINGS
#endif

#ifndef WOLFSSL_ARMARCH
    #define WOLFSSL_ARMARCH 7
#endif

#ifndef WOLFSSL_ARMASM_INLINE
    #define WOLFSSL_ARMASM_INLINE
#endif

#ifndef WOLFSSL_ARMASM_NO_HW_CRYPTO
    #define WOLFSSL_ARMASM_NO_HW_CRYPTO
#endif

#ifndef GCM_TABLE_4BIT
    #define GCM_TABLE_4BIT
#endif

/* Optional compat: some code uses WOLFSSL_ARM_ARCH instead of WOLFSSL_ARMARCH */
#if !defined(WOLFSSL_ARM_ARCH) && defined(WOLFSSL_ARMARCH)
    #define WOLFSSL_ARM_ARCH WOLFSSL_ARMARCH
#endif

/* ------------------------------------------------------------------------- */
/* Platform */
/* ------------------------------------------------------------------------- */
/* Enable DO-178C Version of code _cert.c files */
#ifndef HAVE_DO178
    #define HAVE_DO178
#endif

#ifndef WOLFSSL_ARMASM
    #define WOLFSSL_ARMASM
#endif

/* Target is big endian unless otherwise detected */
#if defined(__ppc) || defined(__powerpc__) || defined(__PPC__)
    #ifndef BIG_ENDIAN_ORDER
        #define BIG_ENDIAN_ORDER
    #endif
#else
    #ifndef LITTLE_ENDIAN_ORDER
        #define LITTLE_ENDIAN_ORDER
    #endif
#endif

/* Standard integer types — leave commented out unless needed */
/*
typedef signed int int32_t;
typedef unsigned int uint32_t;
typedef long long int64_t;
typedef unsigned long long uint64_t;
*/

#ifndef SINGLE_THREADED
    #define SINGLE_THREADED
#endif

#ifndef WOLFSSL_GENERAL_ALIGNMENT
    #define WOLFSSL_GENERAL_ALIGNMENT 4
#endif

#ifndef SIZEOF_LONG_LONG
    #define SIZEOF_LONG_LONG 8
#endif

#ifndef WOLFSSL_IGNORE_FILE_WARN
    #define WOLFSSL_IGNORE_FILE_WARN
#endif

/* In-lining of misc.c functions */
#ifndef WC_INLINE
    #define WC_INLINE __inline__
#endif

/* ------------------------------------------------------------------------- */
/* Custom Standard Lib */
/* ------------------------------------------------------------------------- */
#ifndef BUILD_LOCAL_TEST
    #ifndef STRING_USER
        #define STRING_USER /* enable custom stdlib */
    #endif

    /* no printf - wolfCrypt test only */
    /* #define XPRINTF(f, ...) */

    #ifndef _SIZE_T
        /* typedef unsigned int size_t; */
    #endif
    #ifndef NULL
        #define NULL ((void*)0)
    #endif
#endif

/* Override of all standard library functions */
#include "wolf_string.h"

#ifndef XMEMCPY
    #define XMEMCPY(d,s,l)    memcpy((d),(s),(l))
#endif
#ifndef XMEMSET
    #define XMEMSET(b,c,l)    memset((b),(c),(l))
#endif
#ifndef XMEMCMP
    #define XMEMCMP(s1,s2,n)  memcmp((s1),(s2),(n))
#endif
#ifndef XMEMMOVE
    #define XMEMMOVE(d,s,l)   memmove((d),(s),(l))
#endif

#ifndef XSTRLEN
    #define XSTRLEN(s1)       strlen((s1))
#endif
#ifndef XSTRNCPY
    #define XSTRNCPY(s1,s2,n) strncpy((s1),(s2),(n))
#endif
#ifndef XSTRNCMP
    #define XSTRNCMP(s1,s2,n) strncmp((s1),(s2),(n))
#endif

/* ------------------------------------------------------------------------- */
/* Crypto */
/* ------------------------------------------------------------------------- */
/* RSA */
#ifndef NO_RSA
    #define NO_RSA
#endif
#ifndef NO_ASN
    #define NO_ASN
#endif
#ifndef NO_SHA256
    #define NO_SHA256
#endif
#ifndef WC_NO_RNG
    #define WC_NO_RNG
#endif
#ifndef CUSTOM_RAND_GENERATE_BLOCK
    #define CUSTOM_RAND_GENERATE_BLOCK
#endif

#ifndef HAVE_AESGCM
    #define HAVE_AESGCM
#endif

/* AES */
#ifndef NO_AES_128
    #define NO_AES_128
#endif
#ifndef NO_AES_192
    #define NO_AES_192
#endif

/* ------------------------------------------------------------------------- */
/* Benchmark / Test */
/* ------------------------------------------------------------------------- */
#ifndef BENCH_EMBEDDED
    #define BENCH_EMBEDDED /* Use reduced benchmark / test sizes */
#endif
#ifndef USE_CERT_BUFFERS_3072
    #define USE_CERT_BUFFERS_3072 /* uncomment 3072 to use it for benchmark */
#endif

/* ------------------------------------------------------------------------- */
/* Debugging */
/* ------------------------------------------------------------------------- */
#undef DEBUG_WOLFSSL
#ifndef NO_ERROR_STRINGS
    #define NO_ERROR_STRINGS
#endif

/* ------------------------------------------------------------------------- */
/* Memory */
/* ------------------------------------------------------------------------- */
#ifndef NO_WOLFSSL_MEMORY
    #define NO_WOLFSSL_MEMORY
#endif
#ifndef WOLFSSL_NO_MALLOC
    #define WOLFSSL_NO_MALLOC /* Disable fallback malloc/free */
#endif

/* ------------------------------------------------------------------------- */
/* Port */
/* ------------------------------------------------------------------------- */
#ifndef WOLFSSL_USER_CURRTIME
    #define WOLFSSL_USER_CURRTIME
#endif

/* ------------------------------------------------------------------------- */
/* RNG */
/* ------------------------------------------------------------------------- */
/* Seed Source */
/* Size of returned HW RNG value */
#ifndef CUSTOM_RAND_TYPE
    #define CUSTOM_RAND_TYPE      unsigned int
#endif
#ifndef CUSTOM_RAND_GENERATE
    extern unsigned int myRandGen(void);
    #define CUSTOM_RAND_GENERATE  myRandGen
#endif

/* Choose RNG method */
#ifndef HAVE_HASHDRBG
    #define HAVE_HASHDRBG
#endif

/* ------------------------------------------------------------------------- */
/* Disable Features */
/* ------------------------------------------------------------------------- */
#ifndef NO_WOLFSSL_SERVER
    #define NO_WOLFSSL_SERVER
#endif
#ifndef NO_WOLFSSL_CLIENT
    #define NO_WOLFSSL_CLIENT
#endif
#ifndef BUILD_LOCAL_TEST
    #ifndef NO_CRYPT_TEST
        #define NO_CRYPT_TEST
    #endif
#endif
#ifndef NO_CRYPT_BENCHMARK
    #define NO_CRYPT_BENCHMARK
#endif
#ifndef WOLFCRYPT_ONLY
    #define WOLFCRYPT_ONLY
#endif
#ifndef NO_FILESYSTEM
    #define NO_FILESYSTEM
#endif
#ifndef NO_WOLFSSL_DIR
    #define NO_WOLFSSL_DIR
#endif
#ifndef NO_WRITEV
    #define NO_WRITEV
#endif
#ifndef WOLFSSL_NO_SOCK
    #define WOLFSSL_NO_SOCK
#endif
#ifndef NO_DSA
    #define NO_DSA
#endif
#ifndef NO_RC4
    #define NO_RC4
#endif
#ifndef NO_OLD_TLS
    #define NO_OLD_TLS
#endif
#ifndef NO_HC128
    #define NO_HC128
#endif
#ifndef NO_RABBIT
    #define NO_RABBIT
#endif
#ifndef NO_PSK
    #define NO_PSK
#endif
#ifndef NO_MD4
    #define NO_MD4
#endif
#ifndef NO_DH
    #define NO_DH
#endif
#ifndef NO_DES3
    #define NO_DES3
#endif
#ifndef NO_MD5
    #define NO_MD5
#endif
#ifndef NO_SHA
    #define NO_SHA
#endif
#ifndef NO_SIG_WRAPPER
    #define NO_SIG_WRAPPER
#endif
#ifndef NO_CODING
    #define NO_CODING
#endif
#ifndef NO_PWDBASED
    #define NO_PWDBASED
#endif
#ifndef NO_ASN_TIME
    #define NO_ASN_TIME
#endif
#ifndef NO_ASN_CRYPT
    #define NO_ASN_CRYPT
#endif
#ifndef NO_CERTS
    #define NO_CERTS
#endif
#ifndef WOLFSSL_NO_PEM
    #define WOLFSSL_NO_PEM
#endif
#ifndef NO_PKCS12
    #define NO_PKCS12
#endif
#ifndef NO_PKCS8
    #define NO_PKCS8
#endif
#ifndef NO_PBKDF1
    #define NO_PBKDF1
#endif

#ifdef __cplusplus
}
#endif

#endif /* WOLFSSL_SETTINGS_H */
