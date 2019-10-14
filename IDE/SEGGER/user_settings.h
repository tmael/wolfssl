/* user_settings.h
 *
 * Copyright (C) 2019 wolfSSL Inc.
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

DO-178C wolfCrypt Algorithms:

SHA256

RSA Sign and Verify
    Signature Type: PKCS 1.5, PKCSPSS, OAEP
    Modulo: 2048, 3072
    Hash Algorithm: SHA2-256

AES-GCM and AES-CBC Decrypt and Encrypt
    IV Generation: Internal and external
    Key Length: 128, 192, 256

ChaCha20
Poly1305
ChaCha20 and Poly1305
*/

#ifndef WOLFSSL_SETTINGS_H
#define WOLFSSL_SETTINGS_H

#ifdef __cplusplus
extern "C" {
#endif

/*
Internal comment:
To configure and run test application in Linux:
$ cd ~/wolfssl;
$ ./configure --disable-shared --enable-do178 CFLAGS="-I./IDE/SEGGER  -DWOLFSSL_USER_SETTINGS" && sudo make clean; make && wolfcrypt/test/testwolfcrypt

Output of the test application:
SHA-256  test passed!
Chacha   test passed!
POLY1305 test passed!
ChaCha20-Poly1305 AEAD test passed!
AES      test passed!
AES192   test passed!
AES256   test passed!
AES-GCM  test passed!
RSA NOPAD test passed!
RSA      test passed!
Test complete
*/

#ifndef HAVE_DO178
    #define HAVE_DO178
#endif

#define WOLFCRYPT_ONLY
#undef  SINGLE_THREADED
#define SINGLE_THREADED

/* ------------------------------------------------------------------------- */
/* SHA-256 is on by default. define NO_SHA256 to turn it off */
/* ------------------------------------------------------------------------- */
#undef NO_SHA256

/* ------------------------------------------------------------------------- */
/* AES */
/* ------------------------------------------------------------------------- */

#undef  HAVE_AESGCM
#define HAVE_AESGCM

/* Select one of the AES GCM option */
#define GCM_WORD32

#undef  HAVE_AES_CBC
#define HAVE_AES_CBC

/* ------------------------------------------------------------------------- */
/* POLY1305 */
/* ------------------------------------------------------------------------- */

#undef  HAVE_POLY1305
#define HAVE_POLY1305

/* ------------------------------------------------------------------------- */
/* Chacha */
/* ------------------------------------------------------------------------- */

#undef  HAVE_CHACHA
#define HAVE_CHACHA

/* ------------------------------------------------------------------------- */
/* RSA */
/* ------------------------------------------------------------------------- */

#undef  WOLFSSL_HAVE_SP_RSA
#define WOLFSSL_HAVE_SP_RSA

#undef  TFM_TIMING_RESISTANT
#define TFM_TIMING_RESISTANT

#undef  WC_RSA_BLINDING
#define WC_RSA_BLINDING

#define WOLFSSL_SP_MATH

/* includes sp_c32.c instead of the default sp_c64.c, see sp_int.h */
#define SP_WORD_SIZE 32
/* RSA specific code used in one place */
#define WOLFSSL_SP_RSA

/* Use inline to not use heap memory */
#define WOLFSSL_RSA_VERIFY_INLINE

#if 0
/*  Optional settings */
    #define NO_RSA_BOUNDS_CHECK
#endif

/* padding options*/
#if 0
/* PKCSV15 and OAEP is included in the default build
   The public RSA wc_* functions uses WC_RSA_PKCSV15_PAD as default  */
#define WC_NO_RSA_OAEP       /* Disable RSA OAEP padding */
#define WC_RSA_PSS           /* Adds RSA padding to the build */
#define WC_RSA_NO_PADDING    /* Adds RSA no padding to the build */
#endif

/* ------------------------------------------------------------------------- */
/* RNG */
/* ------------------------------------------------------------------------- */
#define WOLFSSL_GENSEED_FORTEST
#undef WC_NO_RNG

/* RSA and AES GCM require RNG, HAVE_HASHDRBG */
#undef  HAVE_HASHDRBG
#define HAVE_HASHDRBG

/* ------------------------------------------------------------------------- */
/* Memory, no malloc() and free() */
/* ------------------------------------------------------------------------- */
#define NO_WOLFSSL_MEMORY
#define WOLFSSL_NO_MALLOC

/* ------------------------------------------------------------------------- */
/* Test (test.c) application, non-cert */
/* ------------------------------------------------------------------------- */
#if 1
    /* define for test.c application */
    #define WOLFSSL_PUBLIC_MP
    /* test PSS and no padding */
    #define WC_RSA_PSS           /* Adds RSA padding to the build */
    #define WC_RSA_NO_PADDING    /* Adds RSA no padding to the build */
    /* Must include logging.c to use verbose debugging functionality */
#endif

/* ------------------------------------------------------------------------- */
/* Disable features */
/* ------------------------------------------------------------------------- */

#define NO_INLINE

#define NO_SIG_WRAPPER

#undef  WOLFSSL_SHA224
/* remove SHA512*/
#undef  WOLFSSL_SHA3
#undef  WOLFSSL_SHA512

#define NO_CODING
#define NO_ERROR_STRINGS
#define WOLFSSL_OPTIONS_IGNORE_SYS

#undef  NO_FILESYSTEM
#define NO_FILESYSTEM

#undef  NO_DSA
#define NO_DSA

#undef  HAVE_ECC
#undef  TFM_ECC256
#undef  ECC_SHAMIR
#undef  WOLFSSL_HAVE_SP_ECC

#undef  NO_RC4
#define NO_RC4

#undef  NO_HC128
#define NO_HC128

#undef  NO_RABBIT
#define NO_RABBIT

#undef  NO_PSK
#define NO_PSK

#undef  NO_MD4
#define NO_MD4

#undef  NO_MD5
#define NO_MD5

#undef  NO_SHA
#define NO_SHA

#undef  NO_PWDBASED
#define NO_PWDBASED

#undef  WC_NO_ASYNC_THREADING
#define WC_NO_ASYNC_THREADING

#undef  NO_DES3
#define NO_DES3

#undef  WOLFSSL_HAVE_SP_DH
#define NO_DH

#undef  USE_FAST_MATH

#ifdef __cplusplus
}
#endif

#endif /* WOLFSSL_SETTINGS_H */
