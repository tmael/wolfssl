/* ecc.c
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

#ifdef HAVE_DO178
/* in case user set HAVE_ECC there */
#include <wolfssl/wolfcrypt/settings.h>

/* public ASN interface */
#include <wolfssl/wolfcrypt/asn_public.h>

/*
Possible ECC enable options:
 * HAVE_ECC:            Overall control of ECC                  default: on
 * HAVE_ECC_ENCRYPT:    ECC encrypt/decrypt w/AES and HKDF      default: off
 * HAVE_ECC_SIGN:       ECC sign                                default: on
 * HAVE_ECC_VERIFY:     ECC verify                              default: on
 * HAVE_ECC_DHE:        ECC build shared secret                 default: on
 * HAVE_ECC_CDH:        ECC cofactor DH shared secret           default: off
 * HAVE_ECC_KEY_IMPORT: ECC Key import                          default: on
 * HAVE_ECC_KEY_EXPORT: ECC Key export                          default: on
 * ECC_SHAMIR:          Enables Shamir calc method              default: on
 * HAVE_COMP_KEY:       Enables compressed key                  default: off
 * WOLFSSL_VALIDATE_ECC_IMPORT: Validate ECC key on import      default: off
 * WOLFSSL_VALIDATE_ECC_KEYGEN: Validate ECC key gen            default: off
 * WOLFSSL_CUSTOM_CURVES: Allow non-standard curves.            default: off
 *                        Includes the curve "a" variable in calculation
 * ECC_DUMP_OID:        Enables dump of OID encoding and sum    default: off
 * ECC_CACHE_CURVE:     Enables cache of curve info to improve perofrmance
                                                                default: off
 * FP_ECC:              ECC Fixed Point Cache                   default: off
 * USE_ECC_B_PARAM:     Enable ECC curve B param                default: off
                         (on for HAVE_COMP_KEY)
 */

/*
ECC Curve Types:
 * NO_ECC_SECP          Disables SECP curves                    default: off (not defined)
 * HAVE_ECC_SECPR2      Enables SECP R2 curves                  default: off
 * HAVE_ECC_SECPR3      Enables SECP R3 curves                  default: off
 * HAVE_ECC_BRAINPOOL   Enables Brainpool curves                default: off
 * HAVE_ECC_KOBLITZ     Enables Koblitz curves                  default: off
 */

/*
ECC Curve Sizes:
 * ECC_USER_CURVES: Allows custom combination of key sizes below
 * HAVE_ALL_CURVES: Enable all key sizes (on unless ECC_USER_CURVES is defined)
 * HAVE_ECC112: 112 bit key
 * HAVE_ECC128: 128 bit key
 * HAVE_ECC160: 160 bit key
 * HAVE_ECC192: 192 bit key
 * HAVE_ECC224: 224 bit key
 * HAVE_ECC239: 239 bit key
 * NO_ECC256: Disables 256 bit key (on by default)
 * HAVE_ECC320: 320 bit key
 * HAVE_ECC384: 384 bit key
 * HAVE_ECC512: 512 bit key
 * HAVE_ECC521: 521 bit key
 */


#ifdef HAVE_ECC

/* Make sure custom curves is enabled for Brainpool or Koblitz curve types */
#if (defined(HAVE_ECC_BRAINPOOL) || defined(HAVE_ECC_KOBLITZ)) &&\
    !defined(WOLFSSL_CUSTOM_CURVES)
    #error Brainpool and Koblitz curves requires WOLFSSL_CUSTOM_CURVES
#endif

#if defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION >= 2)
    /* set NO_WRAPPERS before headers, use direct internal f()s not wrappers */
    #define FIPS_NO_WRAPPERS

	#ifdef USE_WINDOWS_API
		#pragma code_seg(".fipsA$f")
		#pragma const_seg(".fipsB$f")
	#endif
#endif

#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/types.h>

#ifdef WOLFSSL_HAVE_SP_ECC
#include <wolfssl/wolfcrypt/sp.h>
#endif

#ifdef HAVE_ECC_ENCRYPT
    #include <wolfssl/wolfcrypt/hmac.h>
    #include <wolfssl/wolfcrypt/aes.h>
#endif

#ifdef HAVE_X963_KDF
    #include <wolfssl/wolfcrypt/hash.h>
#endif

#ifdef WOLF_CRYPTO_CB
    #include <wolfssl/wolfcrypt/cryptocb.h>
#endif

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#if defined(FREESCALE_LTC_ECC)
    #include <wolfssl/wolfcrypt/port/nxp/ksdk_port.h>
#endif

#ifdef WOLFSSL_SP_MATH
    #define GEN_MEM_ERR MP_MEM
#elif defined(USE_FAST_MATH)
    #define GEN_MEM_ERR FP_MEM
#else
    #define GEN_MEM_ERR MP_MEM
#endif


/* internal ECC states */
enum {
    ECC_STATE_NONE = 0,

    ECC_STATE_SHARED_SEC_GEN,
    ECC_STATE_SHARED_SEC_RES,

    ECC_STATE_SIGN_DO,
    ECC_STATE_SIGN_ENCODE,

    ECC_STATE_VERIFY_DECODE,
    ECC_STATE_VERIFY_DO,
    ECC_STATE_VERIFY_RES,
};


/* map
   ptmul -> mulmod
*/

/* 256-bit curve on by default whether user curves or not */
#if !defined(NO_ECC256)  || defined(HAVE_ALL_CURVES)
    #define ECC256
#endif

/* The encoded OID's for ECC curves */
#ifdef ECC256
    #ifndef NO_ECC_SECP
        #ifdef HAVE_OID_ENCODING
            #define CODED_SECP256R1    {1,2,840,10045,3,1,7}
            #define CODED_SECP256R1_SZ 7
        #else
            #define CODED_SECP256R1    {0x2A,0x86,0x48,0xCE,0x3D,0x03,0x01,0x07}
            #define CODED_SECP256R1_SZ 8
        #endif
        #ifndef USE_WINDOWS_API
            static const ecc_oid_t ecc_oid_secp256r1[] = CODED_SECP256R1;
        #else
            #define ecc_oid_secp256r1 CODED_SECP256R1
        #endif
        #define ecc_oid_secp256r1_sz CODED_SECP256R1_SZ
    #endif /* !NO_ECC_SECP */
    #ifdef HAVE_ECC_KOBLITZ
        #ifdef HAVE_OID_ENCODING
            #define CODED_SECP256K1    {1,3,132,0,10}
            #define CODED_SECP256K1_SZ 5
        #else
            #define CODED_SECP256K1    {0x2B,0x81,0x04,0x00,0x0A}
            #define CODED_SECP256K1_SZ 5
        #endif
        #ifndef USE_WINDOWS_API
            static const ecc_oid_t ecc_oid_secp256k1[] = CODED_SECP256K1;
        #else
            #define ecc_oid_secp256k1 CODED_SECP256K1
        #endif
        #define ecc_oid_secp256k1_sz CODED_SECP256K1_SZ
    #endif /* HAVE_ECC_KOBLITZ */
    #ifdef HAVE_ECC_BRAINPOOL
        #ifdef HAVE_OID_ENCODING
            #define CODED_BRAINPOOLP256R1    {1,3,36,3,3,2,8,1,1,7}
            #define CODED_BRAINPOOLP256R1_SZ 10
        #else
            #define CODED_BRAINPOOLP256R1    {0x2B,0x24,0x03,0x03,0x02,0x08,0x01,0x01,0x07}
            #define CODED_BRAINPOOLP256R1_SZ 9
        #endif
        #ifndef USE_WINDOWS_API
            static const ecc_oid_t ecc_oid_brainpoolp256r1[] = CODED_BRAINPOOLP256R1;
        #else
            #define ecc_oid_brainpoolp256r1 CODED_BRAINPOOLP256R1
        #endif
        #define ecc_oid_brainpoolp256r1_sz CODED_BRAINPOOLP256R1_SZ
    #endif /* HAVE_ECC_BRAINPOOL */
#endif /* ECC256 */

/* This holds the key settings.
   ***MUST*** be organized by size from smallest to largest. */

const ecc_set_type ecc_sets[] = {
#ifdef ECC256
    #ifndef NO_ECC_SECP
    {
        32,                                                                 /* size/bytes */
        ECC_SECP256R1,                                                      /* ID         */
        "SECP256R1",                                                        /* curve name */
        "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", /* prime      */
        "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC", /* A          */
        "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", /* B          */
        "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", /* order      */
        "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296", /* Gx         */
        "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5", /* Gy         */
		ecc_oid_secp256r1,                                                  /* oid/oidSz  */
        ecc_oid_secp256r1_sz,
        ECC_SECP256R1_OID,                                                  /* oid sum    */
        1,                                                                  /* cofactor   */
    },
    #endif /* !NO_ECC_SECP */
    #ifdef HAVE_ECC_KOBLITZ
    {
        32,                                                                 /* size/bytes */
        ECC_SECP256K1,                                                      /* ID         */
        "SECP256K1",                                                        /* curve name */
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", /* prime      */
        "0000000000000000000000000000000000000000000000000000000000000000", /* A          */
        "0000000000000000000000000000000000000000000000000000000000000007", /* B          */
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", /* order      */
        "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", /* Gx         */
        "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", /* Gy         */
        ecc_oid_secp256k1,                                                  /* oid/oidSz  */
        ecc_oid_secp256k1_sz,
        ECC_SECP256K1_OID,                                                  /* oid sum    */
        1,                                                                  /* cofactor   */
    },
    #endif /* HAVE_ECC_KOBLITZ */
    #ifdef HAVE_ECC_BRAINPOOL
    {
        32,                                                                 /* size/bytes */
        ECC_BRAINPOOLP256R1,                                                /* ID         */
        "BRAINPOOLP256R1",                                                  /* curve name */
        "A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377", /* prime      */
        "7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9", /* A          */
        "26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6", /* B          */
        "A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7", /* order      */
        "8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262", /* Gx         */
        "547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997", /* Gy         */
        ecc_oid_brainpoolp256r1,                                            /* oid/oidSz  */
        ecc_oid_brainpoolp256r1_sz,
        ECC_BRAINPOOLP256R1_OID,                                            /* oid sum    */
        1,                                                                  /* cofactor   */
    },
    #endif /* HAVE_ECC_BRAINPOOL */
#endif /* ECC256 */
#if defined(WOLFSSL_CUSTOM_CURVES) && defined(ECC_CACHE_CURVE)
    /* place holder for custom curve index for cache */
    {
        1, /* non-zero */
        ECC_CURVE_CUSTOM,
        #ifndef USE_WINDOWS_API
            NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
        #else
            {0},{0},{0},{0},{0},{0},{0},{0},
        #endif
        0, 0, 0
    },
#endif
    {
        0,
        ECC_CURVE_INVALID,
        #ifndef USE_WINDOWS_API
            NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
        #else
            {0},{0},{0},{0},{0},{0},{0},{0},
        #endif
        0, 0, 0
    }
};
#define ECC_SET_COUNT   (sizeof(ecc_sets)/sizeof(ecc_set_type))


#ifdef HAVE_OID_ENCODING
    /* encoded OID cache */
    typedef struct {
        word32 oidSz;
        byte oid[ECC_MAX_OID_LEN];
    } oid_cache_t;
    static oid_cache_t ecc_oid_cache[ECC_SET_COUNT];
#endif

int mp_jacobi(mp_int* a, mp_int* n, int* c);
int mp_sqrtmod_prime(mp_int* n, mp_int* prime, mp_int* ret);


/* Curve Specs */
typedef struct ecc_curve_spec {
    const ecc_set_type* dp;

    mp_int* prime;
    mp_int* Af;
    #ifdef USE_ECC_B_PARAM
        mp_int* Bf;
    #endif
    mp_int* order;
    mp_int* Gx;
    mp_int* Gy;

#ifdef ECC_CACHE_CURVE
    mp_int prime_lcl;
    mp_int Af_lcl;
    #ifdef USE_ECC_B_PARAM
        mp_int Bf_lcl;
    #endif
    mp_int order_lcl;
    mp_int Gx_lcl;
    mp_int Gy_lcl;
#else
    mp_int* spec_ints;
    word32 spec_count;
    word32 spec_use;
#endif

    byte load_mask;
} ecc_curve_spec;

enum ecc_curve_load_mask {
    ECC_CURVE_FIELD_NONE    = 0x00,
    ECC_CURVE_FIELD_PRIME   = 0x01,
    ECC_CURVE_FIELD_AF      = 0x02,
#ifdef USE_ECC_B_PARAM
    ECC_CURVE_FIELD_BF      = 0x04,
#endif
    ECC_CURVE_FIELD_ORDER   = 0x08,
    ECC_CURVE_FIELD_GX      = 0x10,
    ECC_CURVE_FIELD_GY      = 0x20,
#ifdef USE_ECC_B_PARAM
    ECC_CURVE_FIELD_ALL     = 0x3F,
    ECC_CURVE_FIELD_COUNT   = 6,
#else
    ECC_CURVE_FIELD_ALL     = 0x3B,
    ECC_CURVE_FIELD_COUNT   = 5,
#endif
};

#ifdef ECC_CACHE_CURVE
    /* cache (mp_int) of the curve parameters */
    static ecc_curve_spec* ecc_curve_spec_cache[ECC_SET_COUNT];
    #ifndef SINGLE_THREADED
        static wolfSSL_Mutex ecc_curve_cache_mutex;
    #endif

    #define DECLARE_CURVE_SPECS(curve, intcount) ecc_curve_spec* curve = NULL
    #define ALLOC_CURVE_SPECS(intcount)
    #define FREE_CURVE_SPECS()
#elif defined(WOLFSSL_SMALL_STACK)
#else
    #define DECLARE_CURVE_SPECS(curve, intcount) \
        mp_int spec_ints[(intcount)]; \
        ecc_curve_spec curve_lcl; \
        ecc_curve_spec* curve = &curve_lcl; \
        XMEMSET(curve, 0, sizeof(ecc_curve_spec)); \
        curve->spec_ints = spec_ints; \
        curve->spec_count = intcount
    #define ALLOC_CURVE_SPECS(intcount)
    #define FREE_CURVE_SPECS()
#endif /* ECC_CACHE_CURVE */

static void _wc_ecc_curve_free(ecc_curve_spec* curve)
{
    if (curve == NULL) {
        return;
    }

    if (curve->load_mask & ECC_CURVE_FIELD_PRIME)
        mp_clear(curve->prime);
    if (curve->load_mask & ECC_CURVE_FIELD_AF)
        mp_clear(curve->Af);
#ifdef USE_ECC_B_PARAM
    if (curve->load_mask & ECC_CURVE_FIELD_BF)
        mp_clear(curve->Bf);
#endif
    if (curve->load_mask & ECC_CURVE_FIELD_ORDER)
        mp_clear(curve->order);
    if (curve->load_mask & ECC_CURVE_FIELD_GX)
        mp_clear(curve->Gx);
    if (curve->load_mask & ECC_CURVE_FIELD_GY)
        mp_clear(curve->Gy);

    curve->load_mask = 0;
}

static void wc_ecc_curve_free(ecc_curve_spec* curve)
{
    /* don't free cached curves */
#ifndef ECC_CACHE_CURVE
    _wc_ecc_curve_free(curve);
#endif
    (void)curve;
}

static int wc_ecc_curve_load_item(const char* src, mp_int** dst,
    ecc_curve_spec* curve, byte mask)
{
    int err;

#ifndef ECC_CACHE_CURVE
    /* get mp_int from temp */
    if (curve->spec_use >= curve->spec_count) {
        WOLFSSL_MSG("Invalid DECLARE_CURVE_SPECS count");
        return ECC_BAD_ARG_E;
    }
    *dst = &curve->spec_ints[curve->spec_use++];
#endif

    err = mp_init(*dst);
    if (err == MP_OKAY) {
        curve->load_mask |= mask;

        err = mp_read_radix(*dst, src, MP_RADIX_HEX);

    #ifdef HAVE_WOLF_BIGINT
        if (err == MP_OKAY)
            err = wc_mp_to_bigint(*dst, &(*dst)->raw);
    #endif
    }
    return err;
}

static int wc_ecc_curve_load(const ecc_set_type* dp, ecc_curve_spec** pCurve,
    byte load_mask)
{
    int ret = 0, x;
    ecc_curve_spec* curve;
    byte load_items = 0; /* mask of items to load */

    if (dp == NULL || pCurve == NULL)
        return BAD_FUNC_ARG;

#ifdef ECC_CACHE_CURVE
    x = wc_ecc_get_curve_idx(dp->id);
    if (x == ECC_CURVE_INVALID)
        return ECC_BAD_ARG_E;

#if !defined(SINGLE_THREADED)
    ret = wc_LockMutex(&ecc_curve_cache_mutex);
    if (ret != 0) {
        return ret;
    }
#endif

    /* make sure cache has been allocated */
    if (ecc_curve_spec_cache[x] == NULL) {
        ecc_curve_spec_cache[x] = (ecc_curve_spec*)XMALLOC(
            sizeof(ecc_curve_spec), NULL, DYNAMIC_TYPE_ECC);
        if (ecc_curve_spec_cache[x] == NULL) {
        #if defined(ECC_CACHE_CURVE) && !defined(SINGLE_THREADED)
            wc_UnLockMutex(&ecc_curve_cache_mutex);
        #endif
            return MEMORY_E;
        }
        XMEMSET(ecc_curve_spec_cache[x], 0, sizeof(ecc_curve_spec));
    }

    /* set curve pointer to cache */
    *pCurve = ecc_curve_spec_cache[x];

#endif /* ECC_CACHE_CURVE */
    curve = *pCurve;

    /* make sure the curve is initialized */
    if (curve->dp != dp) {
        curve->load_mask = 0;

    #ifdef ECC_CACHE_CURVE
        curve->prime = &curve->prime_lcl;
        curve->Af = &curve->Af_lcl;
        #ifdef USE_ECC_B_PARAM
            curve->Bf = &curve->Bf_lcl;
        #endif
        curve->order = &curve->order_lcl;
        curve->Gx = &curve->Gx_lcl;
        curve->Gy = &curve->Gy_lcl;
    #endif
    }
    curve->dp = dp; /* set dp info */

    /* determine items to load */
    load_items = (((byte)~(word32)curve->load_mask) & load_mask);
    curve->load_mask |= load_items;

    /* load items */
    x = 0;
    if (load_items & ECC_CURVE_FIELD_PRIME)
        x += wc_ecc_curve_load_item(dp->prime, &curve->prime, curve,
            ECC_CURVE_FIELD_PRIME);
    if (load_items & ECC_CURVE_FIELD_AF)
        x += wc_ecc_curve_load_item(dp->Af, &curve->Af, curve,
            ECC_CURVE_FIELD_AF);
#ifdef USE_ECC_B_PARAM
    if (load_items & ECC_CURVE_FIELD_BF)
        x += wc_ecc_curve_load_item(dp->Bf, &curve->Bf, curve,
            ECC_CURVE_FIELD_BF);
#endif
    if (load_items & ECC_CURVE_FIELD_ORDER)
        x += wc_ecc_curve_load_item(dp->order, &curve->order, curve,
            ECC_CURVE_FIELD_ORDER);
    if (load_items & ECC_CURVE_FIELD_GX)
        x += wc_ecc_curve_load_item(dp->Gx, &curve->Gx, curve,
            ECC_CURVE_FIELD_GX);
    if (load_items & ECC_CURVE_FIELD_GY)
        x += wc_ecc_curve_load_item(dp->Gy, &curve->Gy, curve,
            ECC_CURVE_FIELD_GY);

    /* check for error */
    if (x != 0) {
        wc_ecc_curve_free(curve);
        ret = MP_READ_E;
    }

#if defined(ECC_CACHE_CURVE) && !defined(SINGLE_THREADED)
    wc_UnLockMutex(&ecc_curve_cache_mutex);
#endif

    return ret;
}

/* Retrieve the curve name for the ECC curve id.
 *
 * curve_id  The id of the curve.
 * returns the name stored from the curve if available, otherwise NULL.
 */
const char* wc_ecc_get_name(int curve_id)
{
    int curve_idx = wc_ecc_get_curve_idx(curve_id);
    if (curve_idx == ECC_CURVE_INVALID)
        return NULL;
    return ecc_sets[curve_idx].name;
}

int wc_ecc_set_curve(ecc_key* key, int keysize, int curve_id)
{
    if (keysize <= 0 && curve_id < 0) {
        return BAD_FUNC_ARG;
    }

    if (keysize > ECC_MAXSIZE) {
        return ECC_BAD_ARG_E;
    }

    /* handle custom case */
    if (key->idx != ECC_CUSTOM_IDX) {
        int x;

        /* default values */
        key->idx = 0;
        key->dp = NULL;

        /* find ecc_set based on curve_id or key size */
        for (x = 0; ecc_sets[x].size != 0; x++) {
            if (curve_id > ECC_CURVE_DEF) {
                if (curve_id == ecc_sets[x].id)
                  break;
            }
            else if (keysize <= ecc_sets[x].size) {
                break;
            }
        }
        if (ecc_sets[x].size == 0) {
            WOLFSSL_MSG("ECC Curve not found");
            return ECC_CURVE_OID_E;
        }

        key->idx = x;
        key->dp  = &ecc_sets[x];
    }

    return 0;
}


#ifdef ALT_ECC_SIZE
static void alt_fp_init(mp_int* a)
{
    a->size = FP_SIZE_ECC;
    mp_zero(a);
}
#endif /* ALT_ECC_SIZE */

#ifndef WOLFSSL_ATECC508A

#if !defined(FREESCALE_LTC_ECC)

#if !defined(FP_ECC) || !defined(WOLFSSL_SP_MATH)
/**
   Perform a point multiplication
   k    The scalar to multiply by
   G    The base point
   R    [out] Destination for kG
   a    ECC curve parameter a
   modulus  The modulus of the field the ECC curve is in
   map      Boolean whether to map back to affine or not
                (1==map, 0 == leave in projective)
   return MP_OKAY on success
*/
#ifdef FP_ECC
static int normal_ecc_mulmod(mp_int* k, ecc_point *G, ecc_point *R,
                  mp_int* a, mp_int* modulus, int map,
                  void* heap)
#else
int wc_ecc_mulmod_ex(mp_int* k, ecc_point *G, ecc_point *R,
                  mp_int* a, mp_int* modulus, int map,
                  void* heap)
#endif
{
#ifndef WOLFSSL_SP_MATH

#else
   if (k == NULL || G == NULL || R == NULL || modulus == NULL) {
       return ECC_BAD_ARG_E;
   }

   (void)a;

   return sp_ecc_mulmod_256(k, G, R, map, heap);
#endif
}

#endif /* !FP_ECC || !WOLFSSL_SP_MATH */

#endif /* !FREESCALE_LTC_ECC */

/** ECC Fixed Point mulmod global
    k        The multiplicand
    G        Base point to multiply
    R        [out] Destination of product
    a        ECC curve parameter a
    modulus  The modulus for the curve
    map      [boolean] If non-zero maps the point back to affine co-ordinates,
             otherwise it's left in jacobian-montgomery form
    return MP_OKAY if successful
*/
int wc_ecc_mulmod(mp_int* k, ecc_point *G, ecc_point *R, mp_int* a,
                  mp_int* modulus, int map)
{
    return wc_ecc_mulmod_ex(k, G, R, a, modulus, map, NULL);
}

#endif /* !WOLFSSL_ATECC508A */

ecc_point ecc_pointGlobal[64]; 
int ecc_pointGlobalInx = 0; 

/**
 * use a heap hint when creating new ecc_point
 * return an allocated point on success or NULL on failure
 */
ecc_point* wc_ecc_new_point_h(void* heap)
{
#ifdef WOLFSSL_SMALL_STACK
#else
  ecc_point* p = &ecc_pointGlobal[ecc_pointGlobalInx++ % 64];
#endif
   (void)heap;

   XMEMSET(p, 0, sizeof(ecc_point));

#ifndef ALT_ECC_SIZE
   if (mp_init_multi(p->x, p->y, p->z, NULL, NULL, NULL) != MP_OKAY) {
#ifdef WOLFSSL_SMALL_STACK
      XFREE(p, heap, DYNAMIC_TYPE_ECC);
#endif
      return NULL;

   }
#else
   p->x = (mp_int*)&p->xyz[0];
   p->y = (mp_int*)&p->xyz[1];
   p->z = (mp_int*)&p->xyz[2];
   alt_fp_init(p->x);
   alt_fp_init(p->y);
   alt_fp_init(p->z);
#endif

   return p;
}


/**
   Allocate a new ECC point
   return A newly allocated point or NULL on error
*/
ecc_point* wc_ecc_new_point(void)
{
  return wc_ecc_new_point_h(NULL);
}


void wc_ecc_del_point_h(ecc_point* p, void* heap)
{
   /* prevents free'ing null arguments */
   if (p != NULL) {
      mp_clear(p->x);
      mp_clear(p->y);
      mp_clear(p->z);
      XFREE(p, heap, DYNAMIC_TYPE_ECC);
   }
   (void)heap;
}


/** Free an ECC point from memory
  p   The point to free
*/
void wc_ecc_del_point(ecc_point* p)
{
    wc_ecc_del_point_h(p, NULL);
}


/** Copy the value of a point to an other one
  p    The point to copy
  r    The created point
*/
int wc_ecc_copy_point(ecc_point* p, ecc_point *r)
{
    int ret;

    /* prevents null arguments */
    if (p == NULL || r == NULL)
        return ECC_BAD_ARG_E;

    ret = mp_copy(p->x, r->x);
    if (ret != MP_OKAY)
        return ret;
    ret = mp_copy(p->y, r->y);
    if (ret != MP_OKAY)
        return ret;
    ret = mp_copy(p->z, r->z);
    if (ret != MP_OKAY)
        return ret;

    return MP_OKAY;
}

/** Compare the value of a point with an other one
 a    The point to compare
 b    The other point to compare

 return MP_EQ if equal, MP_LT/MP_GT if not, < 0 in case of error
 */
int wc_ecc_cmp_point(ecc_point* a, ecc_point *b)
{
    int ret;

    /* prevents null arguments */
    if (a == NULL || b == NULL)
        return BAD_FUNC_ARG;

    ret = mp_cmp(a->x, b->x);
    if (ret != MP_EQ)
        return ret;
    ret = mp_cmp(a->y, b->y);
    if (ret != MP_EQ)
        return ret;
    ret = mp_cmp(a->z, b->z);
    if (ret != MP_EQ)
        return ret;

    return MP_EQ;
}


/** Returns whether an ECC idx is valid or not
  n      The idx number to check
  return 1 if valid, 0 if not
*/
int wc_ecc_is_valid_idx(int n)
{
   int x;

   for (x = 0; ecc_sets[x].size != 0; x++)
       ;
   /* -1 is a valid index --- indicating that the domain params
      were supplied by the user */
   if ((n >= ECC_CUSTOM_IDX) && (n < x)) {
      return 1;
   }

   return 0;
}

int wc_ecc_get_curve_idx(int curve_id)
{
    int curve_idx;
    for (curve_idx = 0; ecc_sets[curve_idx].size != 0; curve_idx++) {
        if (curve_id == ecc_sets[curve_idx].id)
            break;
    }
    if (ecc_sets[curve_idx].size == 0) {
        return ECC_CURVE_INVALID;
    }
    return curve_idx;
}

int wc_ecc_get_curve_id(int curve_idx)
{
    if (wc_ecc_is_valid_idx(curve_idx)) {
        return ecc_sets[curve_idx].id;
    }
    return ECC_CURVE_INVALID;
}

/* Returns the curve size that corresponds to a given ecc_curve_id identifier
 *
 * id      curve id, from ecc_curve_id enum in ecc.h
 * return  curve size, from ecc_sets[] on success, negative on error
 */
int wc_ecc_get_curve_size_from_id(int curve_id)
{
    int curve_idx = wc_ecc_get_curve_idx(curve_id);
    if (curve_idx == ECC_CURVE_INVALID)
        return ECC_BAD_ARG_E;
    return ecc_sets[curve_idx].size;
}

/* Returns the curve index that corresponds to a given curve name in
 * ecc_sets[] of ecc.c
 *
 * name    curve name, from ecc_sets[].name in ecc.c
 * return  curve index in ecc_sets[] on success, negative on error
 */
int wc_ecc_get_curve_idx_from_name(const char* curveName)
{
    int curve_idx;
    word32 len;

    if (curveName == NULL)
        return BAD_FUNC_ARG;

    len = (word32)XSTRLEN(curveName);

    for (curve_idx = 0; ecc_sets[curve_idx].size != 0; curve_idx++) {
        if (ecc_sets[curve_idx].name &&
                XSTRNCASECMP(ecc_sets[curve_idx].name, curveName, len) == 0) {
            break;
        }
    }
    if (ecc_sets[curve_idx].size == 0) {
        WOLFSSL_MSG("ecc_set curve name not found");
        return ECC_CURVE_INVALID;
    }
    return curve_idx;
}

/* Returns the curve size that corresponds to a given curve name,
 * as listed in ecc_sets[] of ecc.c.
 *
 * name    curve name, from ecc_sets[].name in ecc.c
 * return  curve size, from ecc_sets[] on success, negative on error
 */
int wc_ecc_get_curve_size_from_name(const char* curveName)
{
    int curve_idx;

    if (curveName == NULL)
        return BAD_FUNC_ARG;

    curve_idx = wc_ecc_get_curve_idx_from_name(curveName);
    if (curve_idx < 0)
        return curve_idx;

    return ecc_sets[curve_idx].size;
}

/* Returns the curve id that corresponds to a given curve name,
 * as listed in ecc_sets[] of ecc.c.
 *
 * name   curve name, from ecc_sets[].name in ecc.c
 * return curve id, from ecc_sets[] on success, negative on error
 */
int wc_ecc_get_curve_id_from_name(const char* curveName)
{
    int curve_idx;

    if (curveName == NULL)
        return BAD_FUNC_ARG;

    curve_idx = wc_ecc_get_curve_idx_from_name(curveName);
    if (curve_idx < 0)
        return curve_idx;

    return ecc_sets[curve_idx].id;
}

/* Compares a curve parameter (hex, from ecc_sets[]) to given input
 * parameter for equality.
 * encType is WC_TYPE_UNSIGNED_BIN or WC_TYPE_HEX_STR
 * Returns MP_EQ on success, negative on error */
static int wc_ecc_cmp_param(const char* curveParam,
                            const byte* param, word32 paramSz, int encType)
{
    int err = MP_OKAY;
#ifdef WOLFSSL_SMALL_STACK
#else
    mp_int  a[1], b[1];
#endif

    if (param == NULL || curveParam == NULL)
        return BAD_FUNC_ARG;

    if (encType == WC_TYPE_HEX_STR)
        return XSTRNCMP(curveParam, (char*) param, paramSz);

    if ((err = mp_init_multi(a, b, NULL, NULL, NULL, NULL)) != MP_OKAY) {
        return err;
    }

    if (err == MP_OKAY) {
        err = mp_read_unsigned_bin(a, param, paramSz);
    }
    if (err == MP_OKAY)
        err = mp_read_radix(b, curveParam, MP_RADIX_HEX);

    if (err == MP_OKAY) {
        if (mp_cmp(a, b) != MP_EQ) {
            err = -1;
        } else {
            err = MP_EQ;
        }
    }

    mp_clear(a);
    mp_clear(b);

    return err;
}

/* Returns the curve id in ecc_sets[] that corresponds to a given set of
 * curve parameters.
 *
 * fieldSize  the field size in bits
 * prime      prime of the finite field
 * primeSz    size of prime in octets
 * Af         first coefficient a of the curve
 * AfSz       size of Af in octets
 * Bf         second coefficient b of the curve
 * BfSz       size of Bf in octets
 * order      curve order
 * orderSz    size of curve in octets
 * Gx         affine x coordinate of base point
 * GxSz       size of Gx in octets
 * Gy         affine y coordinate of base point
 * GySz       size of Gy in octets
 * cofactor   curve cofactor
 *
 * return curve id, from ecc_sets[] on success, negative on error
 */
int wc_ecc_get_curve_id_from_params(int fieldSize,
        const byte* prime, word32 primeSz, const byte* Af, word32 AfSz,
        const byte* Bf, word32 BfSz, const byte* order, word32 orderSz,
        const byte* Gx, word32 GxSz, const byte* Gy, word32 GySz, int cofactor)
{
    int idx;
    int curveSz;

    if (prime == NULL || Af == NULL || Bf == NULL || order == NULL ||
        Gx == NULL || Gy == NULL)
        return BAD_FUNC_ARG;

    curveSz = (fieldSize + 1) / 8;    /* round up */

    for (idx = 0; ecc_sets[idx].size != 0; idx++) {
        if (curveSz == ecc_sets[idx].size) {
            if ((wc_ecc_cmp_param(ecc_sets[idx].prime, prime,
                            primeSz, WC_TYPE_UNSIGNED_BIN) == MP_EQ) &&
                (wc_ecc_cmp_param(ecc_sets[idx].Af, Af, AfSz,
                                  WC_TYPE_UNSIGNED_BIN) == MP_EQ) &&
                (wc_ecc_cmp_param(ecc_sets[idx].Bf, Bf, BfSz,
                                  WC_TYPE_UNSIGNED_BIN) == MP_EQ) &&
                (wc_ecc_cmp_param(ecc_sets[idx].order, order,
                                  orderSz, WC_TYPE_UNSIGNED_BIN) == MP_EQ) &&
                (wc_ecc_cmp_param(ecc_sets[idx].Gx, Gx, GxSz,
                                  WC_TYPE_UNSIGNED_BIN) == MP_EQ) &&
                (wc_ecc_cmp_param(ecc_sets[idx].Gy, Gy, GySz,
                                  WC_TYPE_UNSIGNED_BIN) == MP_EQ) &&
                (cofactor == ecc_sets[idx].cofactor)) {
                    break;
            }
        }
    }

    if (ecc_sets[idx].size == 0)
        return ECC_CURVE_INVALID;

    return ecc_sets[idx].id;
}

/* Returns the curve id in ecc_sets[] that corresponds
 * to a given domain parameters pointer.
 *
 * dp   domain parameters pointer
 *
 * return curve id, from ecc_sets[] on success, negative on error
 */
int wc_ecc_get_curve_id_from_dp_params(const ecc_set_type* dp)
{
    int idx;

    if (dp == NULL || dp->prime == NULL ||  dp->Af == NULL ||
        dp->Bf == NULL || dp->order == NULL || dp->Gx == NULL || dp->Gy == NULL)
        return BAD_FUNC_ARG;

    for (idx = 0; ecc_sets[idx].size != 0; idx++) {
        if (dp->size == ecc_sets[idx].size) {
            if ((wc_ecc_cmp_param(ecc_sets[idx].prime, (const byte*)dp->prime,
                    (word32)XSTRLEN(dp->prime), WC_TYPE_HEX_STR) == MP_EQ) &&
                (wc_ecc_cmp_param(ecc_sets[idx].Af, (const byte*)dp->Af,
                    (word32)XSTRLEN(dp->Af),WC_TYPE_HEX_STR) == MP_EQ) &&
                (wc_ecc_cmp_param(ecc_sets[idx].Bf, (const byte*)dp->Bf,
                    (word32)XSTRLEN(dp->Bf),WC_TYPE_HEX_STR) == MP_EQ) &&
                (wc_ecc_cmp_param(ecc_sets[idx].order, (const byte*)dp->order,
                    (word32)XSTRLEN(dp->order),WC_TYPE_HEX_STR) == MP_EQ) &&
                (wc_ecc_cmp_param(ecc_sets[idx].Gx, (const byte*)dp->Gx,
                    (word32)XSTRLEN(dp->Gx),WC_TYPE_HEX_STR) == MP_EQ) &&
                (wc_ecc_cmp_param(ecc_sets[idx].Gy, (const byte*)dp->Gy,
                    (word32)XSTRLEN(dp->Gy),WC_TYPE_HEX_STR) == MP_EQ) &&
                (dp->cofactor == ecc_sets[idx].cofactor)) {
                    break;
            }
        }
    }

    if (ecc_sets[idx].size == 0)
        return ECC_CURVE_INVALID;

    return ecc_sets[idx].id;
}

/* Returns the curve id that corresponds to a given OID,
 * as listed in ecc_sets[] of ecc.c.
 *
 * oid   OID, from ecc_sets[].name in ecc.c
 * len   OID len, from ecc_sets[].name in ecc.c
 * return curve id, from ecc_sets[] on success, negative on error
 */
int wc_ecc_get_curve_id_from_oid(const byte* oid, word32 len)
{
    int curve_idx;

    if (oid == NULL)
        return BAD_FUNC_ARG;

    for (curve_idx = 0; ecc_sets[curve_idx].size != 0; curve_idx++) {
        if (ecc_sets[curve_idx].oid && ecc_sets[curve_idx].oidSz == len &&
                              XMEMCMP(ecc_sets[curve_idx].oid, oid, len) == 0) {
            break;
        }
    }
    if (ecc_sets[curve_idx].size == 0) {
        WOLFSSL_MSG("ecc_set curve name not found");
        return ECC_CURVE_INVALID;
    }

    return ecc_sets[curve_idx].id;
}

/* Get curve parameters using curve index */
const ecc_set_type* wc_ecc_get_curve_params(int curve_idx)
{
    const ecc_set_type* ecc_set = NULL;

    if (curve_idx >= 0 && curve_idx < (int)ECC_SET_COUNT) {
        ecc_set = &ecc_sets[curve_idx];
    }
    return ecc_set;
}

#ifdef HAVE_ECC_DHE
/**
  Create an ECC shared secret between two keys
  private_key      The private ECC key (heap hint based off of private key)
  public_key       The public key
  out              [out] Destination of the shared secret
                         Conforms to EC-DH from ANSI X9.63
  outlen           [in/out] The max size and resulting size of the shared secret
  return           MP_OKAY if successful
*/
int wc_ecc_shared_secret(ecc_key* private_key, ecc_key* public_key, byte* out,
                      word32* outlen)
{
   int err;
#if defined(WOLFSSL_CRYPTOCELL)
   CRYS_ECDH_TempData_t tempBuff;
#endif
   if (private_key == NULL || public_key == NULL || out == NULL ||
                                                            outlen == NULL) {
       return BAD_FUNC_ARG;
   }

#ifdef WOLF_CRYPTO_CB
    if (private_key->devId != INVALID_DEVID) {
        err = wc_CryptoCb_Ecdh(private_key, public_key, out, outlen);
        if (err != CRYPTOCB_UNAVAILABLE)
            return err;
        /* fall-through when unavailable */
    }
#endif

   /* type valid? */
   if (private_key->type != ECC_PRIVATEKEY &&
           private_key->type != ECC_PRIVATEKEY_ONLY) {
      return ECC_BAD_ARG_E;
   }

   /* Verify domain params supplied */
   if (wc_ecc_is_valid_idx(private_key->idx) == 0 ||
       wc_ecc_is_valid_idx(public_key->idx)  == 0) {
      return ECC_BAD_ARG_E;
   }

   /* Verify curve id matches */
   if (private_key->dp->id != public_key->dp->id) {
      return ECC_BAD_ARG_E;
   }

#ifdef WOLFSSL_ATECC508A
#elif defined(WOLFSSL_CRYPTOCELL)
#else
   err = wc_ecc_shared_secret_ex(private_key, &public_key->pubkey, out, outlen);
#endif /* WOLFSSL_ATECC508A */

   return err;
}

#if !defined(WOLFSSL_ATECC508A) && !defined(WOLFSSL_CRYPTOCELL)

static int wc_ecc_shared_secret_gen_sync(ecc_key* private_key, ecc_point* point,
                               byte* out, word32* outlen, ecc_curve_spec* curve)
{
    int err;
#ifndef WOLFSSL_SP_MATH
    ecc_point* result = NULL;
    word32 x = 0;
#endif
    mp_int* k = &private_key->k;
#ifdef HAVE_ECC_CDH
    mp_int k_lcl;

    /* if cofactor flag has been set */
    if (private_key->flags & WC_ECC_FLAG_COFACTOR) {
        mp_digit cofactor = (mp_digit)private_key->dp->cofactor;
        /* only perform cofactor calc if not equal to 1 */
        if (cofactor != 1) {
            k = &k_lcl;
            if (mp_init(k) != MP_OKAY)
                return MEMORY_E;
            /* multiply cofactor times private key "k" */
            err = mp_mul_d(&private_key->k, cofactor, k);
            if (err != MP_OKAY) {
                mp_clear(k);
                return err;
            }
        }
    }
#endif

#ifdef WOLFSSL_HAVE_SP_ECC
#ifndef WOLFSSL_SP_NO_256
    if (private_key->idx != ECC_CUSTOM_IDX &&
                               ecc_sets[private_key->idx].id == ECC_SECP256R1) {
        err = sp_ecc_secret_gen_256(k, point, out, outlen, private_key->heap);
    }
    else
#endif
#endif
#ifdef WOLFSSL_SP_MATH
    {
        err = WC_KEY_SIZE_E;

        (void)curve;
    }
#else
    {
        /* make new point */
        result = wc_ecc_new_point_h(private_key->heap);
        if (result == NULL) {
#ifdef HAVE_ECC_CDH
            if (k == &k_lcl)
                mp_clear(k);
#endif
            return MEMORY_E;
        }

        err = wc_ecc_mulmod_ex(k, point, result, curve->Af, curve->prime, 1,
                                                             private_key->heap);
        if (err == MP_OKAY) {
            x = mp_unsigned_bin_size(curve->prime);
            if (*outlen < x || (int)x < mp_unsigned_bin_size(result->x)) {
                err = BUFFER_E;
            }
        }

        if (err == MP_OKAY) {
            XMEMSET(out, 0, x);
            err = mp_to_unsigned_bin(result->x,out +
                                     (x - mp_unsigned_bin_size(result->x)));
        }
        *outlen = x;

        wc_ecc_del_point_h(result, private_key->heap);
    }
#endif
#ifdef HAVE_ECC_CDH
    if (k == &k_lcl)
        mp_clear(k);
#endif

    return err;
}

int wc_ecc_shared_secret_gen(ecc_key* private_key, ecc_point* point,
                                                    byte* out, word32 *outlen)
{
    int err;
    DECLARE_CURVE_SPECS(curve, 2);

    if (private_key == NULL || point == NULL || out == NULL ||
                                                            outlen == NULL) {
        return BAD_FUNC_ARG;
    }

    ALLOC_CURVE_SPECS(2);

    /* load curve info */
    err = wc_ecc_curve_load(private_key->dp, &curve,
        (ECC_CURVE_FIELD_PRIME | ECC_CURVE_FIELD_AF));
    if (err != MP_OKAY) {
        FREE_CURVE_SPECS();
        return err;
    }

    {
        err = wc_ecc_shared_secret_gen_sync(private_key, point,
            out, outlen, curve);
    }

    wc_ecc_curve_free(curve);
    FREE_CURVE_SPECS();

    return err;
}

/**
 Create an ECC shared secret between private key and public point
 private_key      The private ECC key (heap hint based on private key)
 point            The point to use (public key)
 out              [out] Destination of the shared secret
                        Conforms to EC-DH from ANSI X9.63
 outlen           [in/out] The max size and resulting size of the shared secret
 return           MP_OKAY if successful
*/
int wc_ecc_shared_secret_ex(ecc_key* private_key, ecc_point* point,
                            byte* out, word32 *outlen)
{
    int err;

    if (private_key == NULL || point == NULL || out == NULL ||
                                                            outlen == NULL) {
        return BAD_FUNC_ARG;
    }

    /* type valid? */
    if (private_key->type != ECC_PRIVATEKEY &&
            private_key->type != ECC_PRIVATEKEY_ONLY) {
        return ECC_BAD_ARG_E;
    }

    /* Verify domain params supplied */
    if (wc_ecc_is_valid_idx(private_key->idx) == 0)
        return ECC_BAD_ARG_E;

    switch(private_key->state) {
        case ECC_STATE_NONE:
        case ECC_STATE_SHARED_SEC_GEN:
            private_key->state = ECC_STATE_SHARED_SEC_GEN;

            err = wc_ecc_shared_secret_gen(private_key, point, out, outlen);
            if (err < 0) {
                break;
            }
            FALL_THROUGH;

        case ECC_STATE_SHARED_SEC_RES:
            private_key->state = ECC_STATE_SHARED_SEC_RES;
            err = 0;
            break;

        default:
            err = BAD_STATE_E;
    } /* switch */

    /* if async pending then return and skip done cleanup below */
    if (err == WC_PENDING_E) {
        private_key->state++;
        return err;
    }

    /* cleanup */
    private_key->state = ECC_STATE_NONE;

    return err;
}
#endif /* !WOLFSSL_ATECC508A && !WOLFSSL_CRYPTOCELL */
#endif /* HAVE_ECC_DHE */


#if !defined(WOLFSSL_ATECC508A) && !defined(WOLFSSL_CRYPTOCELL)
/* get_digit_count copied from wolfmath.c */
int get_digit_count(mp_int* a)
{
    if (a == NULL)
        return 0;

    return a->used;
}

/* return 1 if point is at infinity, 0 if not, < 0 on error */
int wc_ecc_point_is_at_infinity(ecc_point* p)
{
    if (p == NULL)
        return BAD_FUNC_ARG;

    if (get_digit_count(p->x) == 0 && get_digit_count(p->y) == 0)
        return 1;

    return 0;
}

#endif /* !WOLFSSL_ATECC508A && !WOLFSSL_CRYPTOCELL */

static WC_INLINE void wc_ecc_reset(ecc_key* key)
{
    /* make sure required key variables are reset */
    key->state = ECC_STATE_NONE;
}


/* create the public ECC key from a private key
 *
 * key     an initialized private key to generate public part from
 * curveIn [in]curve for key, can be NULL
 * pubOut  [out]ecc_point holding the public key, if NULL then public key part
 *         is cached in key instead.
 *
 * Note this function is local to the file because of the argument type
 *      ecc_curve_spec. Having this argument allows for not having to load the
 *      curve type multiple times when generating a key with wc_ecc_make_key().
 *
 * returns MP_OKAY on success
 */
static int wc_ecc_make_pub_ex(ecc_key* key, ecc_curve_spec* curveIn,
        ecc_point* pubOut)
{
    int err = MP_OKAY;
#ifndef WOLFSSL_ATECC508A
#ifndef WOLFSSL_SP_MATH
    ecc_point* base = NULL;
#endif
    ecc_point* pub;
    DECLARE_CURVE_SPECS(curve, ECC_CURVE_FIELD_COUNT);
#endif /* !WOLFSSL_ATECC508A */

    if (key == NULL) {
        return BAD_FUNC_ARG;
    }

#ifndef WOLFSSL_ATECC508A

    /* if ecc_point passed in then use it as output for public key point */
    if (pubOut != NULL) {
        pub = pubOut;
    }
    else {
        /* caching public key making it a ECC_PRIVATEKEY instead of
           ECC_PRIVATEKEY_ONLY */
        pub = &key->pubkey;
        key->type = ECC_PRIVATEKEY_ONLY;
    }

    /* avoid loading the curve unless it is not passed in */
    if (curveIn != NULL) {
        curve = curveIn;
    }
    else {
        ALLOC_CURVE_SPECS(ECC_CURVE_FIELD_COUNT);

        /* load curve info */
        if (err == MP_OKAY)
            err = wc_ecc_curve_load(key->dp, &curve, ECC_CURVE_FIELD_ALL);
    }

    if (err == MP_OKAY) {
    #ifndef ALT_ECC_SIZE
        err = mp_init_multi(pub->x, pub->y, pub->z, NULL, NULL, NULL);
    #else
        pub->x = (mp_int*)&pub->xyz[0];
        pub->y = (mp_int*)&pub->xyz[1];
        pub->z = (mp_int*)&pub->xyz[2];
        alt_fp_init(pub->x);
        alt_fp_init(pub->y);
        alt_fp_init(pub->z);
    #endif
    }


#ifdef WOLFSSL_HAVE_SP_ECC
#ifndef WOLFSSL_SP_NO_256
    if (key->idx != ECC_CUSTOM_IDX && ecc_sets[key->idx].id == ECC_SECP256R1) {
        if (err == MP_OKAY)
            err = sp_ecc_mulmod_base_256(&key->k, pub, 1, key->heap);
    }
    else
#endif
#endif
#ifdef WOLFSSL_SP_MATH
        err = WC_KEY_SIZE_E;
#else
#endif

#ifdef WOLFSSL_VALIDATE_ECC_KEYGEN
    /* validate the public key, order * pubkey = point at infinity */
    if (err == MP_OKAY)
        err = ecc_check_pubkey_order(key, pub, curve->Af, curve->prime,
                curve->order);
#endif /* WOLFSSL_VALIDATE_KEYGEN */

    if (err != MP_OKAY) {
        /* clean up if failed */
    #ifndef ALT_ECC_SIZE
        mp_clear(pub->x);
        mp_clear(pub->y);
        mp_clear(pub->z);
    #endif
    }

    /* free up local curve */
    if (curveIn == NULL) {
        wc_ecc_curve_free(curve);
        FREE_CURVE_SPECS();
    }

#else
    (void)curveIn;
    err = NOT_COMPILED_IN;
#endif /* WOLFSSL_ATECC508A */

    /* change key state if public part is cached */
    if (key->type == ECC_PRIVATEKEY_ONLY && pubOut == NULL) {
        key->type = ECC_PRIVATEKEY;
    }

    return err;
}


/* create the public ECC key from a private key
 *
 * key     an initialized private key to generate public part from
 * pubOut  [out]ecc_point holding the public key, if NULL then public key part
 *         is cached in key instead.
 *
 *
 * returns MP_OKAY on success
 */
int wc_ecc_make_pub(ecc_key* key, ecc_point* pubOut)
{
    WOLFSSL_ENTER("wc_ecc_make_pub");

    return wc_ecc_make_pub_ex(key, NULL, pubOut);
}


int wc_ecc_make_key_ex(WC_RNG* rng, int keysize, ecc_key* key, int curve_id)
{
    int err;
#if !defined(WOLFSSL_ATECC508A) && !defined(WOLFSSL_CRYPTOCELL)
#ifndef WOLFSSL_SP_MATH
    DECLARE_CURVE_SPECS(curve, ECC_CURVE_FIELD_COUNT);
#endif
#endif /* !WOLFSSL_ATECC508A */
#if defined(WOLFSSL_CRYPTOCELL)
    const CRYS_ECPKI_Domain_t*  pDomain;
    CRYS_ECPKI_KG_TempData_t    tempBuff;
    CRYS_ECPKI_KG_FipsContext_t fipsCtx;
    byte ucompressed_key[ECC_MAX_CRYPTO_HW_SIZE*2 + 1];
    word32 raw_size = (word32) (key->dp->size)*2 + 1;
#endif
    if (key == NULL || rng == NULL) {
        return BAD_FUNC_ARG;
    }

    /* make sure required variables are reset */
    wc_ecc_reset(key);

    err = wc_ecc_set_curve(key, keysize, curve_id);
    if (err != 0) {
        return err;
    }

#ifdef WOLFSSL_ATECC508A
#elif defined(WOLFSSL_CRYPTOCELL)
#else

#ifdef WOLFSSL_HAVE_SP_ECC
#ifndef WOLFSSL_SP_NO_256
    if (key->idx != ECC_CUSTOM_IDX && ecc_sets[key->idx].id == ECC_SECP256R1) {
        err = sp_ecc_make_key_256(rng, &key->k, &key->pubkey, key->heap);
        if (err == MP_OKAY)
            key->type = ECC_PRIVATEKEY;
    }
    else
#endif
#endif /* WOLFSSL_HAVE_SP_ECC */

   { /* software key gen */
#ifdef WOLFSSL_SP_MATH
        err = WC_KEY_SIZE_E;
#else
#endif /* WOLFSSL_SP_MATH */
    }
#endif /* WOLFSSL_ATECC508A */

    return err;
}

/**
 Make a new ECC key
 rng          An active RNG state
 keysize      The keysize for the new key (in octets from 20 to 65 bytes)
 key          [out] Destination of the newly created key
 return       MP_OKAY if successful,
 upon error all allocated memory will be freed
 */
int wc_ecc_make_key(WC_RNG* rng, int keysize, ecc_key* key)
{
    return wc_ecc_make_key_ex(rng, keysize, key, ECC_CURVE_DEF);
}

/* Setup dynamic pointers if using normal math for proper freeing */
int wc_ecc_init_ex(ecc_key* key, void* heap, int devId)
{
    int ret = 0;

    if (key == NULL) {
        return BAD_FUNC_ARG;
    }

#ifdef ECC_DUMP_OID
    wc_ecc_dump_oids();
#endif

    XMEMSET(key, 0, sizeof(ecc_key));
    key->state = ECC_STATE_NONE;

#if defined(PLUTON_CRYPTO_ECC) || defined(WOLF_CRYPTO_CB)
    key->devId = devId;
#else
    (void)devId;
#endif

#ifdef WOLFSSL_ATECC508A
#else
#ifdef ALT_ECC_SIZE
    key->pubkey.x = (mp_int*)&key->pubkey.xyz[0];
    key->pubkey.y = (mp_int*)&key->pubkey.xyz[1];
    key->pubkey.z = (mp_int*)&key->pubkey.xyz[2];
    alt_fp_init(key->pubkey.x);
    alt_fp_init(key->pubkey.y);
    alt_fp_init(key->pubkey.z);
    ret = mp_init(&key->k);
#else
    ret = mp_init_multi(&key->k, key->pubkey.x, key->pubkey.y, key->pubkey.z,
                                                                    NULL, NULL);
#endif /* ALT_ECC_SIZE */
    if (ret != MP_OKAY) {
        return MEMORY_E;
    }
#endif /* WOLFSSL_ATECC508A */

#ifdef WOLFSSL_HEAP_TEST
    key->heap = (void*)WOLFSSL_HEAP_TEST;
#else
    key->heap = heap;
#endif

    return ret;
}

int wc_ecc_init(ecc_key* key)
{
    return wc_ecc_init_ex(key, NULL, INVALID_DEVID);
}

int wc_ecc_set_flags(ecc_key* key, word32 flags)
{
    if (key == NULL) {
        return BAD_FUNC_ARG;
    }
    key->flags |= flags;
    return 0;
}

static int wc_ecc_get_curve_order_bit_count(const ecc_set_type* dp)
{
    int err;
    word32 orderBits;
    DECLARE_CURVE_SPECS(curve, 1);

    ALLOC_CURVE_SPECS(1);
    err = wc_ecc_curve_load(dp, &curve, ECC_CURVE_FIELD_ORDER);
    if (err != 0) {
       FREE_CURVE_SPECS();
       return err;
    }
    orderBits = mp_count_bits(curve->order);

    wc_ecc_curve_free(curve);
    FREE_CURVE_SPECS();
    return (int)orderBits;
}

#ifdef HAVE_ECC_SIGN

#ifndef NO_ASN

/**
 Sign a message digest
 in        The message digest to sign
 inlen     The length of the digest
 out       [out] The destination for the signature
 outlen    [in/out] The max size and resulting size of the signature
 key       A private ECC key
 return    MP_OKAY if successful
 */
int wc_ecc_sign_hash(const byte* in, word32 inlen, byte* out, word32 *outlen,
                     WC_RNG* rng, ecc_key* key)
{
    int err;
#if !defined(WOLFSSL_ASYNC_CRYPT) || !defined(WC_ASYNC_ENABLE_ECC)
#ifdef WOLFSSL_SMALL_STACK
#else
    mp_int r[1], s[1];
#endif
#endif

    if (in == NULL || out == NULL || outlen == NULL || key == NULL ||
                                                                rng == NULL) {
        return ECC_BAD_ARG_E;
    }

#if defined(WOLFSSL_ASYNC_CRYPT) && defined(WC_ASYNC_ENABLE_ECC)
#else
    XMEMSET(r, 0, sizeof(mp_int));
    XMEMSET(s, 0, sizeof(mp_int));

    if ((err = mp_init_multi(r, s, NULL, NULL, NULL, NULL)) != MP_OKAY){
        return err;
    }

/* hardware crypto */
#if defined(WOLFSSL_ATECC508A) || defined(PLUTON_CRYPTO_ECC) || defined(WOLFSSL_CRYPTOCELL)
    err = wc_ecc_sign_hash_hw(in, inlen, r, s, out, outlen, rng, key);
#else
    err = wc_ecc_sign_hash_ex(in, inlen, rng, key, r, s);
#endif
    if (err < 0) {
        return err;
    }

    /* encoded with DSA header */
    err = StoreECC_DSA_Sig(out, outlen, r, s);

    /* cleanup */
    mp_clear(r);
    mp_clear(s);

#endif /* WOLFSSL_ASYNC_CRYPT */

    return err;
}
#endif /* !NO_ASN */

#if !defined(WOLFSSL_ATECC508A) && !defined(WOLFSSL_CRYPTOCELL)
/**
  Sign a message digest
  in        The message digest to sign
  inlen     The length of the digest
  key       A private ECC key
  r         [out] The destination for r component of the signature
  s         [out] The destination for s component of the signature
  return    MP_OKAY if successful
*/
int wc_ecc_sign_hash_ex(const byte* in, word32 inlen, WC_RNG* rng,
                     ecc_key* key, mp_int *r, mp_int *s)
{
   int    err = 0;
#ifndef WOLFSSL_SP_MATH
   mp_int* e;
#if (!defined(WOLFSSL_ASYNC_CRYPT) || !defined(HAVE_CAVIUM_V)) && \
                                                   !defined(WOLFSSL_SMALL_STACK)
#endif
   DECLARE_CURVE_SPECS(curve, 1);
#endif /* !WOLFSSL_SP_MATH */

   if (in == NULL || r == NULL || s == NULL || key == NULL || rng == NULL)
       return ECC_BAD_ARG_E;

   /* is this a private key? */
   if (key->type != ECC_PRIVATEKEY && key->type != ECC_PRIVATEKEY_ONLY) {
      return ECC_BAD_ARG_E;
   }

   /* is the IDX valid ?  */
   if (wc_ecc_is_valid_idx(key->idx) != 1) {
      return ECC_BAD_ARG_E;
   }

#ifdef WOLFSSL_SP_MATH
    if (key->idx != ECC_CUSTOM_IDX && ecc_sets[key->idx].id == ECC_SECP256R1)
        return sp_ecc_sign_256(in, inlen, rng, &key->k, r, s, key->heap);
    else
        return WC_KEY_SIZE_E;
#else
#endif /* WOLFSSL_SP_MATH */

   return err;
}
#endif /* WOLFSSL_ATECC508A && WOLFSSL_CRYPTOCELL*/
#endif /* HAVE_ECC_SIGN */

/**
  Free an ECC key from memory
  key   The key you wish to free
*/
int wc_ecc_free(ecc_key* key)
{
    if (key == NULL) {
        return 0;
    }

#ifdef WOLFSSL_ATECC508A
#else

    mp_clear(key->pubkey.x);
    mp_clear(key->pubkey.y);
    mp_clear(key->pubkey.z);

    mp_forcezero(&key->k);
#endif /* WOLFSSL_ATECC508A */

    return 0;
}

#ifdef HAVE_ECC_VERIFY
#ifndef NO_ASN
/* verify
 *
 * w  = s^-1 mod n
 * u1 = xw
 * u2 = rw
 * X = u1*G + u2*Q
 * v = X_x1 mod n
 * accept if v == r
 */

/**
 Verify an ECC signature
 sig         The signature to verify
 siglen      The length of the signature (octets)
 hash        The hash (message digest) that was signed
 hashlen     The length of the hash (octets)
 res         Result of signature, 1==valid, 0==invalid
 key         The corresponding public ECC key
 return      MP_OKAY if successful (even if the signature is not valid)
 */
int wc_ecc_verify_hash(const byte* sig, word32 siglen, const byte* hash,
                       word32 hashlen, int* res, ecc_key* key)
{
    int err;
    mp_int *r = NULL, *s = NULL;
#if (!defined(WOLFSSL_ASYNC_CRYPT) || !defined(WC_ASYNC_ENABLE_ECC)) && \
    !defined(WOLFSSL_SMALL_STACK)
    mp_int r_lcl, s_lcl;
#endif

    if (sig == NULL || hash == NULL || res == NULL || key == NULL) {
        return ECC_BAD_ARG_E;
    }

#if defined(WOLFSSL_ASYNC_CRYPT) && defined(WC_ASYNC_ENABLE_ECC)
#else
    #ifndef WOLFSSL_SMALL_STACK
    r = &r_lcl;
    s = &s_lcl;
    #else
    #endif
    XMEMSET(r, 0, sizeof(mp_int));
    XMEMSET(s, 0, sizeof(mp_int));
#endif /* WOLFSSL_ASYNC_CRYPT */

    switch (key->state) {
        case ECC_STATE_NONE:
        case ECC_STATE_VERIFY_DECODE:
            key->state = ECC_STATE_VERIFY_DECODE;

            /* default to invalid signature */
            *res = 0;

            /* Note, DecodeECC_DSA_Sig() calls mp_init() on r and s.
             * If either of those don't allocate correctly, none of
             * the rest of this function will execute, and everything
             * gets cleaned up at the end. */
            /* decode DSA header */
            err = DecodeECC_DSA_Sig(sig, siglen, r, s);
            if (err < 0) {
                break;
            }
            FALL_THROUGH;

        case ECC_STATE_VERIFY_DO:
            key->state = ECC_STATE_VERIFY_DO;

            err = wc_ecc_verify_hash_ex(r, s, hash, hashlen, res, key);

        #ifndef WOLFSSL_ASYNC_CRYPT
            /* done with R/S */
            mp_clear(r);
            mp_clear(s);
        #endif

            if (err < 0) {
                break;
            }
            FALL_THROUGH;

        case ECC_STATE_VERIFY_RES:
            key->state = ECC_STATE_VERIFY_RES;
            err = 0;
            break;

        default:
            err = BAD_STATE_E;
    }

    /* if async pending then return and skip done cleanup below */
    if (err == WC_PENDING_E) {
        key->state++;
        return err;
    }

    key->state = ECC_STATE_NONE;

    return err;
}
#endif /* !NO_ASN */


/**
   Verify an ECC signature
   r           The signature R component to verify
   s           The signature S component to verify
   hash        The hash (message digest) that was signed
   hashlen     The length of the hash (octets)
   res         Result of signature, 1==valid, 0==invalid
   key         The corresponding public ECC key
   return      MP_OKAY if successful (even if the signature is not valid)
*/
int wc_ecc_verify_hash_ex(mp_int *r, mp_int *s, const byte* hash,
                    word32 hashlen, int* res, ecc_key* key)
{
   int           err;
   word32        keySz;
#ifdef WOLFSSL_ATECC508A
#elif defined(WOLFSSL_CRYPTOCELL)
#elif !defined(WOLFSSL_SP_MATH)
   int          did_init = 0;
   ecc_point    *mG = NULL, *mQ = NULL;
#ifdef WOLFSSL_SMALL_STACK
#else /* WOLFSSL_SMALL_STACK */
   mp_int        v[1];
   mp_int        w[1];
   mp_int        u1[1];
   mp_int        u2[1];
#endif /* WOLFSSL_SMALL_STACK */
   mp_int*       e;
   DECLARE_CURVE_SPECS(curve, ECC_CURVE_FIELD_COUNT);
#endif

   if (r == NULL || s == NULL || hash == NULL || res == NULL || key == NULL)
       return ECC_BAD_ARG_E;

   /* default to invalid signature */
   *res = 0;

   /* is the IDX valid ?  */
   if (wc_ecc_is_valid_idx(key->idx) != 1) {
      return ECC_BAD_ARG_E;
   }

   keySz = key->dp->size;

#ifdef WOLFSSL_ATECC508A
#elif defined(WOLFSSL_CRYPTOCELL)
#else
  /* checking if private key with no public part */
  if (key->type == ECC_PRIVATEKEY_ONLY) {
      WOLFSSL_MSG("Verify called with private key, generating public part");
      err = wc_ecc_make_pub_ex(key, NULL, NULL);
      if (err != MP_OKAY) {
           WOLFSSL_MSG("Unable to extract public key");
           return err;
      }
  }

#ifdef WOLFSSL_SP_MATH
  if (key->idx != ECC_CUSTOM_IDX && ecc_sets[key->idx].id == ECC_SECP256R1) {
      return sp_ecc_verify_256(hash, hashlen, key->pubkey.x, key->pubkey.y,
                                           key->pubkey.z, r, s, res, key->heap);
  }
  else
      return WC_KEY_SIZE_E;
#else
#if defined(WOLFSSL_ASYNC_CRYPT) && defined(HAVE_CAVIUM_V)
#else
   e = e_lcl;
#endif /* WOLFSSL_ASYNC_CRYPT && HAVE_CAVIUM_V */
   /* check for async hardware acceleration */
#ifdef FREESCALE_LTC_ECC
#else
#ifndef ECC_SHAMIR
    {
        mp_digit mp = 0;

        /* compute u1*mG + u2*mQ = mG */
        if (err == MP_OKAY) {
            err = wc_ecc_mulmod_ex(u1, mG, mG, curve->Af, curve->prime, 0,
                                                                     key->heap);
        }
        if (err == MP_OKAY) {
            err = wc_ecc_mulmod_ex(u2, mQ, mQ, curve->Af, curve->prime, 0,
                                                                     key->heap);
        }

        /* find the montgomery mp */
        if (err == MP_OKAY)
            err = mp_montgomery_setup(curve->prime, &mp);

        /* add them */
        if (err == MP_OKAY)
            err = ecc_projective_add_point(mQ, mG, mG, curve->Af,
                                                             curve->prime, mp);

        /* reduce */
        if (err == MP_OKAY)
            err = ecc_map(mG, curve->prime, mp);
    }
#else
        /* use Shamir's trick to compute u1*mG + u2*mQ using half the doubles */
        if (err == MP_OKAY) {
            err = ecc_mul2add(mG, u1, mQ, u2, mG, curve->Af, curve->prime,
                                                                    key->heap);
        }
#endif /* ECC_SHAMIR */
#endif /* FREESCALE_LTC_ECC */
   /* v = X_x1 mod n */
   if (err == MP_OKAY)
       err = mp_mod(mG->x, curve->order, v);

   /* does v == r */
   if (err == MP_OKAY) {
       if (mp_cmp(v, r) == MP_EQ)
           *res = 1;
   }

   /* cleanup */
   wc_ecc_del_point_h(mG, key->heap);
   wc_ecc_del_point_h(mQ, key->heap);

   mp_clear(e);
   if (did_init) {
       mp_clear(v);
       mp_clear(w);
       mp_clear(u1);
       mp_clear(u2);
   }
   wc_ecc_curve_free(curve);
   FREE_CURVE_SPECS();

#endif /* WOLFSSL_SP_MATH */
#endif /* WOLFSSL_ATECC508A */

   (void)keySz;
   (void)hashlen;

   return err;
}
#endif /* HAVE_ECC_VERIFY */

#ifdef HAVE_ECC_KEY_IMPORT
/* import point from der */
int wc_ecc_import_point_der(byte* in, word32 inLen, const int curve_idx,
                            ecc_point* point)
{
    int err = 0;
    int compressed = 0;
    int keysize;
    byte pointType;

    if (in == NULL || point == NULL || (curve_idx < 0) ||
        (wc_ecc_is_valid_idx(curve_idx) == 0))
        return ECC_BAD_ARG_E;

    /* must be odd */
    if ((inLen & 1) == 0) {
        return ECC_BAD_ARG_E;
    }

    /* init point */
#ifdef ALT_ECC_SIZE
    point->x = (mp_int*)&point->xyz[0];
    point->y = (mp_int*)&point->xyz[1];
    point->z = (mp_int*)&point->xyz[2];
    alt_fp_init(point->x);
    alt_fp_init(point->y);
    alt_fp_init(point->z);
#else
    err = mp_init_multi(point->x, point->y, point->z, NULL, NULL, NULL);
#endif
    if (err != MP_OKAY)
        return MEMORY_E;

    /* check for point type (4, 2, or 3) */
    pointType = in[0];
    if (pointType != ECC_POINT_UNCOMP && pointType != ECC_POINT_COMP_EVEN &&
                                         pointType != ECC_POINT_COMP_ODD) {
        err = ASN_PARSE_E;
    }

    if (pointType == ECC_POINT_COMP_EVEN || pointType == ECC_POINT_COMP_ODD) {
#ifdef HAVE_COMP_KEY
        compressed = 1;
#else
        err = NOT_COMPILED_IN;
#endif
    }

    /* adjust to skip first byte */
    inLen -= 1;
    in += 1;

    /* calculate key size based on inLen / 2 */
    keysize = inLen>>1;

    /* read data */
    if (err == MP_OKAY)
        err = mp_read_unsigned_bin(point->x, (byte*)in, keysize);
    if (err == MP_OKAY && compressed == 0)
        err = mp_read_unsigned_bin(point->y, (byte*)in + keysize, keysize);
    if (err == MP_OKAY)
        err = mp_set(point->z, 1);

    if (err != MP_OKAY) {
        mp_clear(point->x);
        mp_clear(point->y);
        mp_clear(point->z);
    }

    return err;
}
#endif /* HAVE_ECC_KEY_IMPORT */

#ifdef HAVE_ECC_KEY_EXPORT
/* export point to der */
int wc_ecc_export_point_der(const int curve_idx, ecc_point* point, byte* out,
                            word32* outLen)
{
    int    ret = MP_OKAY;
    word32 numlen;
    byte   buf[ECC_BUFSIZE];

    if ((curve_idx < 0) || (wc_ecc_is_valid_idx(curve_idx) == 0))
        return ECC_BAD_ARG_E;

    /* return length needed only */
    if (point != NULL && out == NULL && outLen != NULL) {
        numlen = ecc_sets[curve_idx].size;
        *outLen = 1 + 2*numlen;
        return LENGTH_ONLY_E;
    }

    if (point == NULL || out == NULL || outLen == NULL)
        return ECC_BAD_ARG_E;

    numlen = ecc_sets[curve_idx].size;

    if (*outLen < (1 + 2*numlen)) {
        *outLen = 1 + 2*numlen;
        return BUFFER_E;
    }

    /* store byte point type */
    out[0] = ECC_POINT_UNCOMP;

    /* pad and store x */
    XMEMSET(buf, 0, ECC_BUFSIZE);
    ret = mp_to_unsigned_bin(point->x, buf +
                                 (numlen - mp_unsigned_bin_size(point->x)));
    if (ret != MP_OKAY)
        goto done;
    XMEMCPY(out+1, buf, numlen);

    /* pad and store y */
    XMEMSET(buf, 0, ECC_BUFSIZE);
    ret = mp_to_unsigned_bin(point->y, buf +
                                 (numlen - mp_unsigned_bin_size(point->y)));
    if (ret != MP_OKAY)
        goto done;
    XMEMCPY(out+1+numlen, buf, numlen);

    *outLen = 1 + 2*numlen;

done:
    return ret;
}


/* export public ECC key in ANSI X9.63 format */
int wc_ecc_export_x963(ecc_key* key, byte* out, word32* outLen)
{
   int    ret = MP_OKAY;
   word32 numlen;
#ifdef WOLFSSL_SMALL_STACK
#else
   byte   buf[ECC_BUFSIZE];
#endif
   word32 pubxlen, pubylen;

   /* return length needed only */
   if (key != NULL && out == NULL && outLen != NULL) {
      /* if key hasn't been setup assume max bytes for size estimation */
      numlen = key->dp ? key->dp->size : MAX_ECC_BYTES;
      *outLen = 1 + 2*numlen;
      return LENGTH_ONLY_E;
   }

   if (key == NULL || out == NULL || outLen == NULL)
      return ECC_BAD_ARG_E;

   if (key->type == ECC_PRIVATEKEY_ONLY)
       return ECC_PRIVATEONLY_E;

   if (wc_ecc_is_valid_idx(key->idx) == 0 || key->dp == NULL) {
      return ECC_BAD_ARG_E;
   }
   numlen = key->dp->size;

    /* verify room in out buffer */
   if (*outLen < (1 + 2*numlen)) {
      *outLen = 1 + 2*numlen;
      return BUFFER_E;
   }

   /* verify public key length is less than key size */
   pubxlen = mp_unsigned_bin_size(key->pubkey.x);
   pubylen = mp_unsigned_bin_size(key->pubkey.y);
   if ((pubxlen > numlen) || (pubylen > numlen)) {
      WOLFSSL_MSG("Public key x/y invalid!");
      return BUFFER_E;
   }

   /* store byte point type */
   out[0] = ECC_POINT_UNCOMP;

   /* pad and store x */
   XMEMSET(buf, 0, ECC_BUFSIZE);
   ret = mp_to_unsigned_bin(key->pubkey.x, buf + (numlen - pubxlen));
   if (ret != MP_OKAY)
      goto done;
   XMEMCPY(out+1, buf, numlen);

   /* pad and store y */
   XMEMSET(buf, 0, ECC_BUFSIZE);
   ret = mp_to_unsigned_bin(key->pubkey.y, buf + (numlen - pubylen));
   if (ret != MP_OKAY)
      goto done;
   XMEMCPY(out+1+numlen, buf, numlen);

   *outLen = 1 + 2*numlen;

done:
   return ret;
}


/* export public ECC key in ANSI X9.63 format, extended with
 * compression option */
int wc_ecc_export_x963_ex(ecc_key* key, byte* out, word32* outLen,
                          int compressed)
{
    if (compressed == 0)
        return wc_ecc_export_x963(key, out, outLen);
#ifdef HAVE_COMP_KEY
    else
        return wc_ecc_export_x963_compressed(key, out, outLen);
#else
    return NOT_COMPILED_IN;
#endif
}
#endif /* HAVE_ECC_KEY_EXPORT */


#if !defined(WOLFSSL_ATECC508A) && !defined(WOLFSSL_CRYPTOCELL)

/* is ecc point on curve described by dp ? */
int wc_ecc_is_point(ecc_point* ecp, mp_int* a, mp_int* b, mp_int* prime)
{
#ifndef WOLFSSL_SP_MATH
#else
   (void)a;
   (void)b;
   (void)prime;

   return sp_ecc_is_point_256(ecp->x, ecp->y);
#endif
}

#endif /* !WOLFSSL_ATECC508A && !WOLFSSL_CRYPTOCELL*/


/* perform sanity checks on ecc key validity, 0 on success */
int wc_ecc_check_key(ecc_key* key)
{
    int    err;
#ifndef WOLFSSL_SP_MATH
#else
    if (key == NULL)
        return BAD_FUNC_ARG;

    /* pubkey point cannot be at infinity */
    if (key->idx != ECC_CUSTOM_IDX && ecc_sets[key->idx].id == ECC_SECP256R1) {
        err = sp_ecc_check_key_256(key->pubkey.x, key->pubkey.y, &key->k,
                                                                     key->heap);
    }
    else
        err = WC_KEY_SIZE_E;
#endif

    return err;
}

#ifdef HAVE_ECC_KEY_IMPORT
/* import public ECC key in ANSI X9.63 format */
int wc_ecc_import_x963_ex(const byte* in, word32 inLen, ecc_key* key,
                          int curve_id)
{
    int err = MP_OKAY;
    int compressed = 0;
    int keysize = 0;
    byte pointType;

    if (in == NULL || key == NULL)
        return BAD_FUNC_ARG;

    /* must be odd */
    if ((inLen & 1) == 0) {
        return ECC_BAD_ARG_E;
    }

    /* make sure required variables are reset */
    wc_ecc_reset(key);

    /* init key */
    #ifdef ALT_ECC_SIZE
        key->pubkey.x = (mp_int*)&key->pubkey.xyz[0];
        key->pubkey.y = (mp_int*)&key->pubkey.xyz[1];
        key->pubkey.z = (mp_int*)&key->pubkey.xyz[2];
        alt_fp_init(key->pubkey.x);
        alt_fp_init(key->pubkey.y);
        alt_fp_init(key->pubkey.z);
        err = mp_init(&key->k);
    #else
        err = mp_init_multi(&key->k,
                    key->pubkey.x, key->pubkey.y, key->pubkey.z, NULL, NULL);
    #endif
    if (err != MP_OKAY)
        return MEMORY_E;

    /* check for point type (4, 2, or 3) */
    pointType = in[0];
    if (pointType != ECC_POINT_UNCOMP && pointType != ECC_POINT_COMP_EVEN &&
                                         pointType != ECC_POINT_COMP_ODD) {
        err = ASN_PARSE_E;
    }

    if (pointType == ECC_POINT_COMP_EVEN || pointType == ECC_POINT_COMP_ODD) {
    #ifdef HAVE_COMP_KEY
        compressed = 1;
    #else
        err = NOT_COMPILED_IN;
    #endif
    }

    /* adjust to skip first byte */
    inLen -= 1;
    in += 1;

    if (err == MP_OKAY) {
    #ifdef HAVE_COMP_KEY
        /* adjust inLen if compressed */
        if (compressed)
            inLen = inLen*2 + 1;  /* used uncompressed len */
    #endif

        /* determine key size */
        keysize = (inLen>>1);
        err = wc_ecc_set_curve(key, keysize, curve_id);
        key->type = ECC_PUBLICKEY;
    }

    /* read data */
    if (err == MP_OKAY)
        err = mp_read_unsigned_bin(key->pubkey.x, (byte*)in, keysize);
    if (err == MP_OKAY && compressed == 0)
        err = mp_read_unsigned_bin(key->pubkey.y, (byte*)in + keysize, keysize);
    if (err == MP_OKAY)
        err = mp_set(key->pubkey.z, 1);

#ifdef WOLFSSL_VALIDATE_ECC_IMPORT
    if (err == MP_OKAY)
        err = wc_ecc_check_key(key);
#endif

    if (err != MP_OKAY) {
        mp_clear(key->pubkey.x);
        mp_clear(key->pubkey.y);
        mp_clear(key->pubkey.z);
        mp_clear(&key->k);
    }

    return err;
}

int wc_ecc_import_x963(const byte* in, word32 inLen, ecc_key* key)
{
    return wc_ecc_import_x963_ex(in, inLen, key, ECC_CURVE_DEF);
}
#endif /* HAVE_ECC_KEY_IMPORT */

#ifdef HAVE_ECC_KEY_EXPORT

/* wc_export_int() copied from wolfmath.c */

/* export an mp_int as unsigned char or hex string
 * encType is WC_TYPE_UNSIGNED_BIN or WC_TYPE_HEX_STR
 * return MP_OKAY on success */
int wc_export_int(mp_int* mp, byte* buf, word32* len, word32 keySz,
    int encType)
{
    int err;

    if (mp == NULL)
        return BAD_FUNC_ARG;

    /* check buffer size */
    if (*len < keySz) {
        *len = keySz;
        return BUFFER_E;
    }

    *len = keySz;
    XMEMSET(buf, 0, *len);

    if (encType == WC_TYPE_HEX_STR) {
    #ifdef WC_MP_TO_RADIX
        err = mp_tohex(mp, (char*)buf);
    #else
        err = NOT_COMPILED_IN;
    #endif
    }
    else {
        err = mp_to_unsigned_bin(mp, buf + (keySz - mp_unsigned_bin_size(mp)));
    }

    return err;
}

/* export ecc key to component form, d is optional if only exporting public
 * encType is WC_TYPE_UNSIGNED_BIN or WC_TYPE_HEX_STR
 * return MP_OKAY on success */
int wc_ecc_export_ex(ecc_key* key, byte* qx, word32* qxLen,
                 byte* qy, word32* qyLen, byte* d, word32* dLen, int encType)
{
    int err = 0;
    word32 keySz;

    if (key == NULL) {
        return BAD_FUNC_ARG;
    }

    if (wc_ecc_is_valid_idx(key->idx) == 0) {
        return ECC_BAD_ARG_E;
    }
    keySz = key->dp->size;

    /* private key, d */
    if (d != NULL) {
        if (dLen == NULL ||
            (key->type != ECC_PRIVATEKEY && key->type != ECC_PRIVATEKEY_ONLY))
            return BAD_FUNC_ARG;

    #ifdef WOLFSSL_ATECC508A
        /* Hardware cannot export private portion */
        return NOT_COMPILED_IN;
    #else
        err = wc_export_int(&key->k, d, dLen, keySz, encType);
        if (err != MP_OKAY)
            return err;
    #endif
    }

    /* public x component */
    if (qx != NULL) {
        if (qxLen == NULL || key->type == ECC_PRIVATEKEY_ONLY)
            return BAD_FUNC_ARG;

        err = wc_export_int(key->pubkey.x, qx, qxLen, keySz, encType);
        if (err != MP_OKAY)
            return err;
    }

    /* public y component */
    if (qy != NULL) {
        if (qyLen == NULL || key->type == ECC_PRIVATEKEY_ONLY)
            return BAD_FUNC_ARG;

        err = wc_export_int(key->pubkey.y, qy, qyLen, keySz, encType);
        if (err != MP_OKAY)
            return err;
    }

    return err;
}


/* export ecc private key only raw, outLen is in/out size as unsigned bin
   return MP_OKAY on success */
int wc_ecc_export_private_only(ecc_key* key, byte* out, word32* outLen)
{
    if (out == NULL || outLen == NULL) {
        return BAD_FUNC_ARG;
    }

    return wc_ecc_export_ex(key, NULL, NULL, NULL, NULL, out, outLen,
        WC_TYPE_UNSIGNED_BIN);
}

/* export public key to raw elements including public (Qx,Qy) as unsigned bin
 * return MP_OKAY on success, negative on error */
int wc_ecc_export_public_raw(ecc_key* key, byte* qx, word32* qxLen,
                             byte* qy, word32* qyLen)
{
    if (qx == NULL || qxLen == NULL || qy == NULL || qyLen == NULL) {
        return BAD_FUNC_ARG;
    }

    return wc_ecc_export_ex(key, qx, qxLen, qy, qyLen, NULL, NULL,
        WC_TYPE_UNSIGNED_BIN);
}

/* export ecc key to raw elements including public (Qx,Qy) and
 *   private (d) as unsigned bin
 * return MP_OKAY on success, negative on error */
int wc_ecc_export_private_raw(ecc_key* key, byte* qx, word32* qxLen,
                              byte* qy, word32* qyLen, byte* d, word32* dLen)
{
    return wc_ecc_export_ex(key, qx, qxLen, qy, qyLen, d, dLen,
        WC_TYPE_UNSIGNED_BIN);
}

#endif /* HAVE_ECC_KEY_EXPORT */

#ifndef NO_ASN
#ifdef HAVE_ECC_KEY_IMPORT
/* import private key, public part optional if (pub) passed as NULL */
int wc_ecc_import_private_key_ex(const byte* priv, word32 privSz,
                                 const byte* pub, word32 pubSz, ecc_key* key,
                                 int curve_id)
{
    int ret;
    word32 idx = 0;
#if defined(WOLFSSL_CRYPTOCELL)
    const CRYS_ECPKI_Domain_t* pDomain;
    CRYS_ECPKI_BUILD_TempData_t tempBuff;
#endif
    if (key == NULL || priv == NULL)
        return BAD_FUNC_ARG;

    /* public optional, NULL if only importing private */
    if (pub != NULL) {
        ret = wc_ecc_import_x963_ex(pub, pubSz, key, curve_id);
        if (ret < 0)
            ret = wc_EccPublicKeyDecode(pub, &idx, key, pubSz);
        key->type = ECC_PRIVATEKEY;
    }
    else {
        /* make sure required variables are reset */
        wc_ecc_reset(key);

        /* set key size */
        ret = wc_ecc_set_curve(key, privSz, curve_id);
        key->type = ECC_PRIVATEKEY_ONLY;
    }

    if (ret != 0)
        return ret;

#ifdef WOLFSSL_ATECC508A
#elif defined(WOLFSSL_CRYPTOCELL)
#else

    ret = mp_read_unsigned_bin(&key->k, priv, privSz);
#ifdef HAVE_WOLF_BIGINT
    if (ret == 0 &&
                  wc_bigint_from_unsigned_bin(&key->k.raw, priv, privSz) != 0) {
        mp_clear(&key->k);
        ret = ASN_GETINT_E;
    }
#endif /* HAVE_WOLF_BIGINT */


#endif /* WOLFSSL_ATECC508A */

#ifdef WOLFSSL_VALIDATE_ECC_IMPORT
    if ((pub != NULL) && (ret == MP_OKAY))
        /* public key needed to perform key validation */
        ret = ecc_check_privkey_gen_helper(key);
#endif

    return ret;
}

/* ecc private key import, public key in ANSI X9.63 format, private raw */
int wc_ecc_import_private_key(const byte* priv, word32 privSz, const byte* pub,
                           word32 pubSz, ecc_key* key)
{
    return wc_ecc_import_private_key_ex(priv, privSz, pub, pubSz, key,
                                                                ECC_CURVE_DEF);
}
#endif /* HAVE_ECC_KEY_IMPORT */

/**
   Convert ECC R,S to signature
   r       R component of signature
   s       S component of signature
   out     DER-encoded ECDSA signature
   outlen  [in/out] output buffer size, output signature size
   return  MP_OKAY on success
*/
int wc_ecc_rs_to_sig(const char* r, const char* s, byte* out, word32* outlen)
{
    int err;
#ifdef WOLFSSL_SMALL_STACK
#else
    mp_int  rtmp[1];
    mp_int  stmp[1];
#endif

    if (r == NULL || s == NULL || out == NULL || outlen == NULL)
        return ECC_BAD_ARG_E;

    err = mp_init_multi(rtmp, stmp, NULL, NULL, NULL, NULL);
    if (err != MP_OKAY) {
        return err;
    }

    err = mp_read_radix(rtmp, r, MP_RADIX_HEX);
    if (err == MP_OKAY)
        err = mp_read_radix(stmp, s, MP_RADIX_HEX);

    /* convert mp_ints to ECDSA sig, initializes rtmp and stmp internally */
    if (err == MP_OKAY)
        err = StoreECC_DSA_Sig(out, outlen, rtmp, stmp);

    if (err == MP_OKAY) {
        if (mp_iszero(rtmp) == MP_YES || mp_iszero(stmp) == MP_YES)
            err = MP_ZERO_E;
    }

    mp_clear(rtmp);
    mp_clear(stmp);
    return err;
}

/**
   Convert ECC R,S raw unsigned bin to signature
   r       R component of signature
   rSz     R size
   s       S component of signature
   sSz     S size
   out     DER-encoded ECDSA signature
   outlen  [in/out] output buffer size, output signature size
   return  MP_OKAY on success
*/
int wc_ecc_rs_raw_to_sig(const byte* r, word32 rSz, const byte* s, word32 sSz,
    byte* out, word32* outlen)
{
    int err;
#ifdef WOLFSSL_SMALL_STACK
#else
    mp_int  rtmp[1];
    mp_int  stmp[1];
#endif

    if (r == NULL || s == NULL || out == NULL || outlen == NULL)
        return ECC_BAD_ARG_E;
    err = mp_init_multi(rtmp, stmp, NULL, NULL, NULL, NULL);
    if (err != MP_OKAY) {
        return err;
    }

    err = mp_read_unsigned_bin(rtmp, r, rSz);
    if (err == MP_OKAY)
        err = mp_read_unsigned_bin(stmp, s, sSz);

    /* convert mp_ints to ECDSA sig, initializes rtmp and stmp internally */
    if (err == MP_OKAY)
        err = StoreECC_DSA_Sig(out, outlen, rtmp, stmp);

    if (err == MP_OKAY) {
        if (mp_iszero(rtmp) == MP_YES || mp_iszero(stmp) == MP_YES)
            err = MP_ZERO_E;
    }

    mp_clear(rtmp);
    mp_clear(stmp);

    return err;
}

/**
   Convert ECC signature to R,S
   sig     DER-encoded ECDSA signature
   sigLen  length of signature in octets
   r       R component of signature
   rLen    [in/out] output "r" buffer size, output "r" size
   s       S component of signature
   sLen    [in/out] output "s" buffer size, output "s" size
   return  MP_OKAY on success, negative on error
*/
int wc_ecc_sig_to_rs(const byte* sig, word32 sigLen, byte* r, word32* rLen,
                     byte* s, word32* sLen)
{
    int err;
    int tmp_valid = 0;
    word32 x = 0;
#ifdef WOLFSSL_SMALL_STACK
#else
    mp_int  rtmp[1];
    mp_int  stmp[1];
#endif

    if (sig == NULL || r == NULL || rLen == NULL || s == NULL || sLen == NULL)
        return ECC_BAD_ARG_E;

    err = DecodeECC_DSA_Sig(sig, sigLen, rtmp, stmp);

    /* rtmp and stmp are initialized */
    if (err == MP_OKAY) {
        tmp_valid = 1;
    }

    /* extract r */
    if (err == MP_OKAY) {
        x = mp_unsigned_bin_size(rtmp);
        if (*rLen < x)
            err = BUFFER_E;

        if (err == MP_OKAY) {
            *rLen = x;
            err = mp_to_unsigned_bin(rtmp, r);
        }
    }

    /* extract s */
    if (err == MP_OKAY) {
        x = mp_unsigned_bin_size(stmp);
        if (*sLen < x)
            err = BUFFER_E;

        if (err == MP_OKAY) {
            *sLen = x;
            err = mp_to_unsigned_bin(stmp, s);
        }
    }

    if (tmp_valid) {
        mp_clear(rtmp);
        mp_clear(stmp);
    }

    return err;
}
#endif /* !NO_ASN */

#ifdef HAVE_ECC_KEY_IMPORT
static int wc_ecc_import_raw_private(ecc_key* key, const char* qx,
          const char* qy, const char* d, int curve_id, int encType)
{
    int err = MP_OKAY;
    /* if d is NULL, only import as public key using Qx,Qy */
    if (key == NULL || qx == NULL || qy == NULL) {
        return BAD_FUNC_ARG;
    }

    /* make sure required variables are reset */
    wc_ecc_reset(key);

    /* set curve type and index */
    err = wc_ecc_set_curve(key, 0, curve_id);
    if (err != 0) {
        return err;
    }

    /* init key */
#ifdef ALT_ECC_SIZE
    key->pubkey.x = (mp_int*)&key->pubkey.xyz[0];
    key->pubkey.y = (mp_int*)&key->pubkey.xyz[1];
    key->pubkey.z = (mp_int*)&key->pubkey.xyz[2];
    alt_fp_init(key->pubkey.x);
    alt_fp_init(key->pubkey.y);
    alt_fp_init(key->pubkey.z);
    err = mp_init(&key->k);
#else
    err = mp_init_multi(&key->k, key->pubkey.x, key->pubkey.y, key->pubkey.z,
                                                                  NULL, NULL);
#endif
    if (err != MP_OKAY)
        return MEMORY_E;

    /* read Qx */
    if (err == MP_OKAY) {
        if (encType == WC_TYPE_HEX_STR)
            err = mp_read_radix(key->pubkey.x, qx, MP_RADIX_HEX);
        else
            err = mp_read_unsigned_bin(key->pubkey.x, (const byte*)qx,
                key->dp->size);
    }

    /* read Qy */
    if (err == MP_OKAY) {
        if (encType == WC_TYPE_HEX_STR)
            err = mp_read_radix(key->pubkey.y, qy, MP_RADIX_HEX);
        else
            err = mp_read_unsigned_bin(key->pubkey.y, (const byte*)qy,
                key->dp->size);

    }

    if (err == MP_OKAY)
        err = mp_set(key->pubkey.z, 1);

#ifdef WOLFSSL_ATECC508A
#elif defined(WOLFSSL_CRYPTOCELL)
#endif

    /* import private key */
    if (err == MP_OKAY) {
        if (d != NULL && d[0] != '\0') {
        #ifdef WOLFSSL_ATECC508A
            /* Hardware doesn't support loading private key */
            err = NOT_COMPILED_IN;

        #elif defined(WOLFSSL_CRYPTOCELL)
        #else
            key->type = ECC_PRIVATEKEY;

            if (encType == WC_TYPE_HEX_STR)
                err = mp_read_radix(&key->k, d, MP_RADIX_HEX);
            else
                err = mp_read_unsigned_bin(&key->k, (const byte*)d,
                    key->dp->size);
        #endif /* WOLFSSL_ATECC508A */
        } else {
            key->type = ECC_PUBLICKEY;
        }
    }

#ifdef WOLFSSL_VALIDATE_ECC_IMPORT
    if (err == MP_OKAY)
        err = wc_ecc_check_key(key);
#endif

    if (err != MP_OKAY) {
        mp_clear(key->pubkey.x);
        mp_clear(key->pubkey.y);
        mp_clear(key->pubkey.z);
        mp_clear(&key->k);
    }

    return err;
}

/**
   Import raw ECC key
   key       The destination ecc_key structure
   qx        x component of the public key, as ASCII hex string
   qy        y component of the public key, as ASCII hex string
   d         private key, as ASCII hex string, optional if importing public
             key only
   dp        Custom ecc_set_type
   return    MP_OKAY on success
*/
int wc_ecc_import_raw_ex(ecc_key* key, const char* qx, const char* qy,
                   const char* d, int curve_id)
{
    return wc_ecc_import_raw_private(key, qx, qy, d, curve_id,
        WC_TYPE_HEX_STR);

}

/* Import x, y and optional private (d) as unsigned binary */
int wc_ecc_import_unsigned(ecc_key* key, byte* qx, byte* qy,
                   byte* d, int curve_id)
{
    return wc_ecc_import_raw_private(key, (const char*)qx, (const char*)qy,
        (const char*)d, curve_id, WC_TYPE_UNSIGNED_BIN);
}

/**
   Import raw ECC key
   key       The destination ecc_key structure
   qx        x component of the public key, as ASCII hex string
   qy        y component of the public key, as ASCII hex string
   d         private key, as ASCII hex string, optional if importing public
             key only
   curveName ECC curve name, from ecc_sets[]
   return    MP_OKAY on success
*/
int wc_ecc_import_raw(ecc_key* key, const char* qx, const char* qy,
                   const char* d, const char* curveName)
{
    int err, x;

    /* if d is NULL, only import as public key using Qx,Qy */
    if (key == NULL || qx == NULL || qy == NULL || curveName == NULL) {
        return BAD_FUNC_ARG;
    }

    /* set curve type and index */
    for (x = 0; ecc_sets[x].size != 0; x++) {
        if (XSTRNCMP(ecc_sets[x].name, curveName,
                     XSTRLEN(curveName)) == 0) {
            break;
        }
    }

    if (ecc_sets[x].size == 0) {
        WOLFSSL_MSG("ecc_set curve name not found");
        err = ASN_PARSE_E;
    } else {
        return wc_ecc_import_raw_private(key, qx, qy, d, ecc_sets[x].id,
            WC_TYPE_HEX_STR);
    }

    return err;
}
#endif /* HAVE_ECC_KEY_IMPORT */

/* key size in octets */
int wc_ecc_size(ecc_key* key)
{
    if (key == NULL)
        return 0;

    return key->dp->size;
}

/* maximum signature size based on key size */
int wc_ecc_sig_size_calc(int sz)
{
    int maxSigSz = 0;

    /* calculate based on key bits */
    /* maximum possible signature header size is 7 bytes plus 2 bytes padding */
    maxSigSz = (sz * 2) + SIG_HEADER_SZ + ECC_MAX_PAD_SZ;

    /* if total length is less than 128 + SEQ(1)+LEN(1) then subtract 1 */
    if (maxSigSz < (128 + 2)) {
        maxSigSz -= 1;
    }

    return maxSigSz;
}

/* maximum signature size based on actual key curve */
int wc_ecc_sig_size(ecc_key* key)
{
    int maxSigSz;
    int orderBits, keySz;

    if (key == NULL || key->dp == NULL)
        return 0;

    /* the signature r and s will always be less than order */
    /* if the order MSB (top bit of byte) is set then ASN encoding needs
        extra byte for r and s, so add 2 */
    keySz = key->dp->size;
    orderBits = wc_ecc_get_curve_order_bit_count(key->dp);
    /* maximum possible signature header size is 7 bytes */
    maxSigSz = (keySz * 2) + SIG_HEADER_SZ;
    if ((orderBits % 8) == 0) {
        /* MSB can be set, so add 2 */
        maxSigSz += ECC_MAX_PAD_SZ;
    }
    /* if total length is less than 128 + SEQ(1)+LEN(1) then subtract 1 */
    if (maxSigSz < (128 + 2)) {
        maxSigSz -= 1;
    }

    return maxSigSz;
}

int wc_ecc_get_oid(word32 oidSum, const byte** oid, word32* oidSz)
{
    int x;

    if (oidSum == 0) {
        return BAD_FUNC_ARG;
    }

    /* find matching OID sum (based on encoded value) */
    for (x = 0; ecc_sets[x].size != 0; x++) {
        if (ecc_sets[x].oidSum == oidSum) {
            int ret = 0;
        #ifdef HAVE_OID_ENCODING
        #else
            if (oidSz) {
                *oidSz = ecc_sets[x].oidSz;
            }
            if (oid) {
                *oid = ecc_sets[x].oid;
            }
        #endif
            /* on success return curve id */
            if (ret == 0) {
                ret = ecc_sets[x].id;
            }
            return ret;
        }
    }

    return NOT_COMPILED_IN;
}

#endif /* HAVE_ECC */
#endif /* HAVE_DO178 */
