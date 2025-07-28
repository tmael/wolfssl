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
/* Platform */
/* ------------------------------------------------------------------------- */
/* Enable DO-178C Version of code _cert.c files */
#define HAVE_DO178
#define WOLFSSL_ARMASM
/* Target is big endian */
#if defined(__ppc) || defined(__powerpc__) || defined(__PPC__)
#define BIG_ENDIAN_ORDER
#else
    #ifndef LITTLE_ENDIAN_ORDER
        #define LITTLE_ENDIAN_ORDER  
    #endif   
#endif

/* Define standard integer types */

/*
typedef signed int int32_t;
typedef unsigned int uint32_t;
typedef long long int64_t;
typedef unsigned long long uint64_t;

*/

#define SINGLE_THREADED
#define WOLFSSL_GENERAL_ALIGNMENT   4
#define SIZEOF_LONG_LONG 8
#define WOLFSSL_IGNORE_FILE_WARN

/* In-lining of misc.c functions */
/* If defined, must include wolfcrypt/src/misc.c in build */
/* Slower, but about 1k smaller */
#define WC_INLINE __inline__


/* ------------------------------------------------------------------------- */
/* Custom Standard Lib */
/* ------------------------------------------------------------------------- */
#ifndef BUILD_LOCAL_TEST
    #define STRING_USER /* enable custom stdlib */

    /* no printf - wolfCrypt test only */
    //#define XPRINTF(f, ...)

    #ifndef _SIZE_T
        //typedef unsigned int size_t;
    #endif
    #ifndef NULL
        #define NULL ((void*)0)
    #endif
#endif

/* override of all standard library functions */
#include "wolf_string.h"

#define XMEMCPY(d,s,l)    memcpy((d),(s),(l))
#define XMEMSET(b,c,l)    memset((b),(c),(l))
#define XMEMCMP(s1,s2,n)  memcmp((s1),(s2),(n))
#define XMEMMOVE(d,s,l)   memmove((d),(s),(l))

#define XSTRLEN(s1)       strlen((s1))
#define XSTRNCPY(s1,s2,n) strncpy((s1),(s2),(n))
#define XSTRNCMP(s1,s2,n) strncmp((s1),(s2),(n))


/* ------------------------------------------------------------------------- */
/* Crypto */
/* ------------------------------------------------------------------------- */
/* RSA */
#define NO_RSA
#define NO_ASN
#define NO_SHA256
#define WC_NO_RNG
#define CUSTOM_RAND_GENERATE_BLOCK

#define HAVE_AESGCM

/* AES */
#define NO_AES_128
#define NO_AES_192

/* Sha256 */
/* On by default */

/* ------------------------------------------------------------------------- */
/* Benchmark / Test */
/* ------------------------------------------------------------------------- */
#define BENCH_EMBEDDED /* Use reduced benchmark / test sizes */
#define USE_CERT_BUFFERS_3072 /* uncomment 3072 to use it for benchmark */


/* ------------------------------------------------------------------------- */
/* Debugging */
/* ------------------------------------------------------------------------- */
#undef DEBUG_WOLFSSL
#define NO_ERROR_STRINGS


/* ------------------------------------------------------------------------- */
/* Memory */
/* ------------------------------------------------------------------------- */

#define NO_WOLFSSL_MEMORY
#define WOLFSSL_NO_MALLOC /* Disable fallback malloc/free */


/* ------------------------------------------------------------------------- */
/* Port */
/* ------------------------------------------------------------------------- */

/* User supplied benchmark time function "custom_time()" */
#define WOLFSSL_USER_CURRTIME


/* ------------------------------------------------------------------------- */
/* RNG */
/* ------------------------------------------------------------------------- */
/* Seed Source */
/* Size of returned HW RNG value */
#define CUSTOM_RAND_TYPE      unsigned int
extern unsigned int myRandGen(void);
#define CUSTOM_RAND_GENERATE  myRandGen

/* Choose RNG method */
/* Use built-in P-RNG (SHA256 based) with HW RNG */
/* P-RNG + HW RNG (P-RNG is ~8K) */
#define HAVE_HASHDRBG


/* ------------------------------------------------------------------------- */
/* Disable Features */
/* ------------------------------------------------------------------------- */
#define NO_WOLFSSL_SERVER
#define NO_WOLFSSL_CLIENT
#ifndef BUILD_LOCAL_TEST
    #define NO_CRYPT_TEST
#endif
#define NO_CRYPT_BENCHMARK
#define WOLFCRYPT_ONLY
#define NO_FILESYSTEM
#define NO_WOLFSSL_DIR
#define NO_WRITEV
#define WOLFSSL_NO_SOCK
#define NO_DSA
#define NO_RC4
#define NO_OLD_TLS
#define NO_HC128
#define NO_RABBIT
#define NO_PSK
#define NO_MD4
#define NO_DH
#define NO_DES3
#define NO_MD5
#define NO_SHA
#define NO_SIG_WRAPPER
#define NO_CODING
#define NO_PWDBASED
#define NO_ASN_TIME
#define NO_ASN_CRYPT
#define NO_CERTS
#define WOLFSSL_NO_PEM
#define NO_PKCS12
#define NO_PKCS8
#define NO_PBKDF1


#ifdef __cplusplus
}
#endif

#endif /* WOLFSSL_SETTINGS_H */
