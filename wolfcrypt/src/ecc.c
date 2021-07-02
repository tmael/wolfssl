/* ecc.c
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



#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

/* in case user set HAVE_ECC there */
#include <wolfssl/wolfcrypt/settings.h>

/* public ASN interface */
#include <wolfssl/wolfcrypt/asn_public.h>

/*
Possible ECC enable options:
 * HAVE_ECC:            Overall control of ECC                  default: on
 * HAVE_ECC_SIGN:       ECC sign                                default: on
 * HAVE_ECC_VERIFY:     ECC verify                              default: on
 * HAVE_ECC_DHE:        ECC build shared secret                 default: on
 */

/*
ECC Curve Types:
 * NO_ECC_SECP          Disables SECP curves                    default: off (not defined)
 */

#ifdef HAVE_ECC

#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/types.h>

#ifdef WOLFSSL_HAVE_SP_ECC
#include <wolfssl/wolfcrypt/sp.h>
#endif

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
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

#if (defined(HAVE_ECC384) || defined(HAVE_ALL_CURVES)) && ECC_MIN_KEY_SZ <= 384
    #define ECC384
#endif

#ifdef ECC384
    #ifndef NO_ECC_SECP
        #ifdef HAVE_OID_ENCODING
            #define CODED_SECP384R1    {1,3,132,0,34}
            #define CODED_SECP384R1_SZ 5
        #else
            #define CODED_SECP384R1    {0x2B,0x81,0x04,0x00,0x22}
            #define CODED_SECP384R1_SZ 5
        #endif
        #ifndef WOLFSSL_ECC_CURVE_STATIC
static const ecc_oid_t ecc_oid_secp384r1[] = CODED_SECP384R1;
            #define CODED_SECP384R1_OID ecc_oid_secp384r1
        #else
			#define ecc_oid_secp384r1 CODED_SECP384R1
        #endif
        #define ecc_oid_secp384r1_sz CODED_SECP384R1_SZ
    #endif /* !NO_ECC_SECP */
    #ifdef HAVE_ECC_BRAINPOOL
        #ifdef HAVE_OID_ENCODING
            #define CODED_BRAINPOOLP384R1    {1,3,36,3,3,2,8,1,1,11}
            #define CODED_BRAINPOOLP384R1_SZ 10
        #else
            #define CODED_BRAINPOOLP384R1    {0x2B,0x24,0x03,0x03,0x02,0x08,0x01,0x01,0x0B}
            #define CODED_BRAINPOOLP384R1_SZ 9
        #endif
        #ifndef WOLFSSL_ECC_CURVE_STATIC
            static const ecc_oid_t ecc_oid_brainpoolp384r1[] = CODED_BRAINPOOLP384R1;
        #else
            #define ecc_oid_brainpoolp384r1 CODED_BRAINPOOLP384R1
        #endif
        #define ecc_oid_brainpoolp384r1_sz CODED_BRAINPOOLP384R1_SZ
    #endif /* HAVE_ECC_BRAINPOOL */
#endif /* ECC384 */

/* This holds the key settings.
   ***MUST*** be organized by size from smallest to largest. */

const ecc_set_type ecc_sets[] = {
#ifdef ECC384
    #ifndef NO_ECC_SECP
    {
        48,                                                                                                 /* size/bytes */
        ECC_SECP384R1,                                                                                      /* ID         */
        "SECP384R1",                                                                                        /* curve name */
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF", /* prime      */
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC", /* A          */
        "B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF", /* B          */
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973", /* order      */
        "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7", /* Gx         */
        "3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F", /* Gy         */
        ecc_oid_secp384r1, ecc_oid_secp384r1_sz,                                                            /* oid/oidSz  */
        ECC_SECP384R1_OID,                                                                                  /* oid sum    */
        1,                                                                                                  /* cofactor   */
    },
    #endif /* !NO_ECC_SECP */
    #ifdef HAVE_ECC_BRAINPOOL
    {
        48,                                                                                                 /* size/bytes */
        ECC_BRAINPOOLP384R1,                                                                                /* ID         */
        "BRAINPOOLP384R1",                                                                                  /* curve name */
        "8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B412B1DA197FB71123ACD3A729901D1A71874700133107EC53", /* prime      */
        "7BC382C63D8C150C3C72080ACE05AFA0C2BEA28E4FB22787139165EFBA91F90F8AA5814A503AD4EB04A8C7DD22CE2826", /* A          */
        "04A8C7DD22CE28268B39B55416F0447C2FB77DE107DCD2A62E880EA53EEB62D57CB4390295DBC9943AB78696FA504C11", /* B          */
        "8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B31F166E6CAC0425A7CF3AB6AF6B7FC3103B883202E9046565", /* order      */
        "1D1C64F068CF45FFA2A63A81B7C13F6B8847A3E77EF14FE3DB7FCAFE0CBD10E8E826E03436D646AAEF87B2E247D4AF1E", /* Gx         */
        "8ABE1D7520F9C2A45CB1EB8E95CFD55262B70B29FEEC5864E19C054FF99129280E4646217791811142820341263C5315", /* Gy         */
        ecc_oid_brainpoolp384r1, ecc_oid_brainpoolp384r1_sz,                                                /* oid/oidSz  */
        ECC_BRAINPOOLP384R1_OID,                                                                            /* oid sum    */
        1,                                                                                                  /* cofactor   */
    },
    #endif /* HAVE_ECC_BRAINPOOL */
#endif /* ECC384 */
    {
        0,
        ECC_CURVE_INVALID,
        #ifndef WOLFSSL_ECC_CURVE_STATIC
            NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
        #else
            {0},{0},{0},{0},{0},{0},{0},{0},
        #endif
        0, 0, 0
    }
};
#define ECC_SET_COUNT   (sizeof(ecc_sets)/sizeof(ecc_set_type))
const size_t ecc_sets_count = ECC_SET_COUNT - 1;

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


#define DECLARE_CURVE_SPECS(curve, intcount) \
	mp_int spec_ints[(intcount)]; \
	ecc_curve_spec curve_lcl; \
	ecc_curve_spec* curve = &curve_lcl; \
	XMEMSET(curve, 0, sizeof(ecc_curve_spec)); \
	curve->spec_ints = spec_ints; \
	curve->spec_count = intcount
#define ALLOC_CURVE_SPECS(intcount)
#define FREE_CURVE_SPECS()

static void wc_ecc_curve_cache_free_spec_item(ecc_curve_spec* curve, mp_int* item,
    byte mask)
{
    if (item) {
        mp_clear(item);
    }
    curve->load_mask &= ~mask;
}
static void wc_ecc_curve_cache_free_spec(ecc_curve_spec* curve)
{
    if (curve == NULL) {
        return;
    }

    if (curve->load_mask & ECC_CURVE_FIELD_PRIME)
        wc_ecc_curve_cache_free_spec_item(curve, curve->prime, ECC_CURVE_FIELD_PRIME);
    if (curve->load_mask & ECC_CURVE_FIELD_AF)
        wc_ecc_curve_cache_free_spec_item(curve, curve->Af, ECC_CURVE_FIELD_AF);
#ifdef USE_ECC_B_PARAM
    if (curve->load_mask & ECC_CURVE_FIELD_BF)
        wc_ecc_curve_cache_free_spec_item(curve, curve->Bf, ECC_CURVE_FIELD_BF);
#endif
    if (curve->load_mask & ECC_CURVE_FIELD_ORDER)
        wc_ecc_curve_cache_free_spec_item(curve, curve->order, ECC_CURVE_FIELD_ORDER);
    if (curve->load_mask & ECC_CURVE_FIELD_GX)
        wc_ecc_curve_cache_free_spec_item(curve, curve->Gx, ECC_CURVE_FIELD_GX);
    if (curve->load_mask & ECC_CURVE_FIELD_GY)
        wc_ecc_curve_cache_free_spec_item(curve, curve->Gy, ECC_CURVE_FIELD_GY);

    curve->load_mask = 0;
}

static void wc_ecc_curve_free(ecc_curve_spec* curve)
{
    if (curve) {
        wc_ecc_curve_cache_free_spec(curve);
    }
}

static int wc_ecc_curve_cache_load_item(ecc_curve_spec* curve, const char* src, 
    mp_int** dst, byte mask)
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

    }
    return err;
}

static int wc_ecc_curve_load(const ecc_set_type* dp, ecc_curve_spec** pCurve,
    byte load_mask)
{
    int ret = 0;
    ecc_curve_spec* curve;
    byte load_items = 0; /* mask of items to load */

    if (dp == NULL || pCurve == NULL)
        return BAD_FUNC_ARG;
    curve = *pCurve;

    /* make sure the curve is initialized */
    if (curve->dp != dp) {
        curve->load_mask = 0;
    }
    curve->dp = dp; /* set dp info */

    /* determine items to load */
    load_items = (((byte)~(word32)curve->load_mask) & load_mask);
    curve->load_mask |= load_items;

    /* load items */
    if (load_items & ECC_CURVE_FIELD_PRIME)
        ret += wc_ecc_curve_cache_load_item(curve, dp->prime, &curve->prime,
            ECC_CURVE_FIELD_PRIME);
    if (load_items & ECC_CURVE_FIELD_AF)
        ret += wc_ecc_curve_cache_load_item(curve, dp->Af, &curve->Af,
            ECC_CURVE_FIELD_AF);
#ifdef USE_ECC_B_PARAM
    if (load_items & ECC_CURVE_FIELD_BF)
        ret += wc_ecc_curve_cache_load_item(curve, dp->Bf, &curve->Bf,
            ECC_CURVE_FIELD_BF);
#endif
    if (load_items & ECC_CURVE_FIELD_ORDER)
        ret += wc_ecc_curve_cache_load_item(curve, dp->order, &curve->order,
            ECC_CURVE_FIELD_ORDER);
    if (load_items & ECC_CURVE_FIELD_GX)
        ret += wc_ecc_curve_cache_load_item(curve, dp->Gx, &curve->Gx,
            ECC_CURVE_FIELD_GX);
    if (load_items & ECC_CURVE_FIELD_GY)
        ret += wc_ecc_curve_cache_load_item(curve, dp->Gy, &curve->Gy,
            ECC_CURVE_FIELD_GY);

    /* check for error */
    if (ret != 0) {
        wc_ecc_curve_free(curve);
        ret = MP_READ_E;
    }
    return ret;
}
/*!
    \ingroup ECC

    \brief This function retrieves the curve name for the ECC curve id.

    \return the name stored from the curve if available, otherwise NULL.

    \param curve_id  The id of the curve.
*/

const char* wc_ecc_get_name(int curve_id)
{
    int curve_idx = wc_ecc_get_curve_idx(curve_id);
    if (curve_idx == ECC_CURVE_INVALID)
        return NULL;
    return ecc_sets[curve_idx].name;
}

/*!
    \ingroup ECC

    \brief This function search for ecc_set based on curve_id or key size.

    \return the ecc_set if available
    \return BAD_FUNC_ARGS if keysize and curve id are invalid
    \return ECC_BAD_ARG_E if keysize is greater than max ECC key

    \param key  ECC key to use
    \param keysize  size of ECC key
    \param curve_id The id of the curve
*/

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


#if !defined(WOLFSSL_SP_MATH) || !defined(FP_ECC)
/*!
    \ingroup ECC

    \brief This function performs a point multiplication

    \return MP_OKAY on success
    \return ECC_BAD_ARG_E if input parameters are invalid

    \param k    The scalar to multiply by
    \param G    The base point
    \param R    [out] Destination for kG
    \param a    ECC curve parameter a
    \param modulus  The modulus of the field the ECC curve is in
    \param map      Boolean whether to map back to affine or not
                (1==map, 0 == leave in projective)
*/

int wc_ecc_mulmod_ex(mp_int* k, ecc_point *G, ecc_point *R, mp_int* a,
                     mp_int* modulus, int map, void* heap)
{
   if (k == NULL || G == NULL || R == NULL || modulus == NULL) {
       return ECC_BAD_ARG_E;
   }

   (void)a;

#ifdef WOLFSSL_SP_384
   if (mp_count_bits(modulus) == 384) {
       return sp_ecc_mulmod_384(k, G, R, map, heap);
   }
#endif
   return ECC_BAD_ARG_E;
}
#endif /* !WOLFSSL_SP_MATH || !FP_ECC */

/*!
    \ingroup ECC

    \brief This function performs fixed point mulmod global

    \return MP_OKAY on success
    \return ECC_BAD_ARG_E if input parameters are invalid

    \param k        The multiplicand
    \param G        Base point to multiply
    \param R        [out] Destination of product
    \param a        ECC curve parameter a
    \param modulus  The modulus for the curve
    \param map      [boolean] If non-zero maps the point back to affine coordinates,
                     otherwise it's left in jacobian-montgomery form
*/
int wc_ecc_mulmod(mp_int* k, ecc_point *G, ecc_point *R, mp_int* a,
                  mp_int* modulus, int map)
{
    return wc_ecc_mulmod_ex(k, G, R, a, modulus, map, NULL);
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
        if (
        #ifndef WOLFSSL_ECC_CURVE_STATIC
            ecc_sets[curve_idx].name &&
        #endif
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
    mp_int  a[1], b[1];

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

    if (dp == NULL
    #ifndef WOLFSSL_ECC_CURVE_STATIC
         || dp->prime == NULL ||  dp->Af == NULL ||
        dp->Bf == NULL || dp->order == NULL || dp->Gx == NULL || dp->Gy == NULL
    #endif
    ) {
        return BAD_FUNC_ARG;
    }

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
        if (
        #ifndef WOLFSSL_ECC_CURVE_STATIC
            ecc_sets[curve_idx].oid &&
        #endif
            ecc_sets[curve_idx].oidSz == len &&
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
   if (private_key == NULL || public_key == NULL || out == NULL ||
                                                            outlen == NULL) {
       return BAD_FUNC_ARG;
   }

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

   err = wc_ecc_shared_secret_ex(private_key, &public_key->pubkey, out, outlen);

   return err;
}


#if !defined(WOLFSSL_ATECC508A) && !defined(WOLFSSL_ATECC608A) && \
    !defined(WOLFSSL_CRYPTOCELL)

static int wc_ecc_shared_secret_gen_sync(ecc_key* private_key, ecc_point* point,
                               byte* out, word32* outlen, ecc_curve_spec* curve)
{
    int err = MP_OKAY;

    mp_int* k = &private_key->k;

    WOLFSSL_ENTER("wc_ecc_shared_secret_gen_sync");

#ifdef WOLFSSL_HAVE_SP_ECC
#ifdef WOLFSSL_SP_384
    if (private_key->idx != ECC_CUSTOM_IDX &&
                               ecc_sets[private_key->idx].id == ECC_SECP384R1) {
        err = sp_ecc_secret_gen_384(k, point, out, outlen, private_key->heap);
    }
    else
#endif
#endif
    err = WC_KEY_SIZE_E;

    (void)curve;

    WOLFSSL_LEAVE("wc_ecc_shared_secret_gen_sync", err);

    return err;
}

int wc_ecc_shared_secret_gen(ecc_key* private_key, ecc_point* point,
                                                    byte* out, word32 *outlen)
{
    int err;
    DECLARE_CURVE_SPECS(curve, 3);

    if (private_key == NULL || point == NULL || out == NULL ||
                                                            outlen == NULL) {
        return BAD_FUNC_ARG;
    }

    /* load curve info */
    ALLOC_CURVE_SPECS(3);
    err = wc_ecc_curve_load(private_key->dp, &curve,
        (ECC_CURVE_FIELD_PRIME | ECC_CURVE_FIELD_AF | ECC_CURVE_FIELD_ORDER));
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
        WOLFSSL_MSG("ECC_BAD_ARG_E");
        return ECC_BAD_ARG_E;
    }

    /* Verify domain params supplied */
    if (wc_ecc_is_valid_idx(private_key->idx) == 0) {
        WOLFSSL_MSG("wc_ecc_is_valid_idx failed");
        return ECC_BAD_ARG_E;
    }

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

    WOLFSSL_LEAVE("wc_ecc_shared_secret_ex", err);

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

#ifdef USE_ECC_B_PARAM
/* Checks if a point p lies on the curve with index curve_idx */
int wc_ecc_point_is_on_curve(ecc_point *p, int curve_idx)
{
    int err;
    DECLARE_CURVE_SPECS(curve, 3);

    if (p == NULL)
        return BAD_FUNC_ARG;

    /* is the IDX valid ?  */
    if (wc_ecc_is_valid_idx(curve_idx) != 1) {
       return ECC_BAD_ARG_E;
    }

    ALLOC_CURVE_SPECS(3);
    err = wc_ecc_curve_load(wc_ecc_get_curve_params(curve_idx), &curve,
                                ECC_CURVE_FIELD_PRIME | ECC_CURVE_FIELD_AF |
                                ECC_CURVE_FIELD_BF);
    if (err == MP_OKAY) {
        err = wc_ecc_is_point(p, curve->Af, curve->Bf, curve->prime);
    }

    wc_ecc_curve_free(curve);
    FREE_CURVE_SPECS();

    return err;
}
#endif /* USE_ECC_B_PARAM */

/* return 1 if point is at infinity, 0 if not, < 0 on error */
int wc_ecc_point_is_at_infinity(ecc_point* p)
{
    if (p == NULL)
        return BAD_FUNC_ARG;

    if (p->x->used && p->y->used)
        return 1;

    return 0;
}

/* generate random and ensure its greater than 0 and less than order */
int wc_ecc_gen_k(WC_RNG* rng, int size, mp_int* k, mp_int* order)
{
#ifndef WC_NO_RNG
    int err;
    byte buf[ECC_MAXSIZE_GEN];

    /*generate 8 extra bytes to mitigate bias from the modulo operation below*/
    /*see section A.1.2 in 'Suite B Implementor's Guide to FIPS 186-3 (ECDSA)'*/
    size += 8;

    /* make up random string */
    err = wc_RNG_GenerateBlock(rng, buf, size);

    /* load random buffer data into k */
    if (err == 0)
        err = mp_read_unsigned_bin(k, (byte*)buf, size);

    /* the key should be smaller than the order of base point */
    if (err == MP_OKAY) {
        if (mp_cmp(k, order) != MP_LT) {
            err = mp_mod(k, order, k);
        }
    }

    /* quick sanity check to make sure we're not dealing with a 0 key */
    if (err == MP_OKAY) {
        if (mp_iszero(k) == MP_YES)
          err = MP_ZERO_E;
    }

    ForceZero(buf, ECC_MAXSIZE);

    return err;
#else
    (void)rng;
    (void)size;
    (void)k;
    (void)order;
    return NOT_COMPILED_IN;
#endif /* !WC_NO_RNG */
}

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
static int ecc_make_pub_ex(ecc_key* key, ecc_curve_spec* curveIn,
        ecc_point* pubOut, WC_RNG* rng)
{
    int err = MP_OKAY;
    ecc_point* pub;
    DECLARE_CURVE_SPECS(curve, ECC_CURVE_FIELD_COUNT);

    (void)rng;

    if (key == NULL) {
        return BAD_FUNC_ARG;
    }

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
        /* load curve info */
        if (err == MP_OKAY) {
            ALLOC_CURVE_SPECS(ECC_CURVE_FIELD_COUNT);
            err = wc_ecc_curve_load(key->dp, &curve, ECC_CURVE_FIELD_ALL);
        }
    }

    if ((err == MP_OKAY) && (mp_iszero(&key->k) || mp_isneg(&key->k) ||
                                      (mp_cmp(&key->k, curve->order) != MP_LT)))
    {
        err = ECC_PRIV_KEY_E;
    }

    if (err == MP_OKAY) {
    	err = mp_init_multi(pub->x, pub->y, pub->z, NULL, NULL, NULL);
    }

    if (err != MP_OKAY) {
    }
    else
#ifdef WOLFSSL_HAVE_SP_ECC
#ifdef WOLFSSL_SP_384
    if (key->idx != ECC_CUSTOM_IDX && ecc_sets[key->idx].id == ECC_SECP384R1) {
        err = sp_ecc_mulmod_base_384(&key->k, pub, 1, key->heap);
    }
    else
#endif
#endif
    err = WC_KEY_SIZE_E;

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

    return ecc_make_pub_ex(key, NULL, pubOut, NULL);
}

/* create the public ECC key from a private key - mask timing use random z
 *
 * key     an initialized private key to generate public part from
 * pubOut  [out]ecc_point holding the public key, if NULL then public key part
 *         is cached in key instead.
 *
 *
 * returns MP_OKAY on success
 */
int wc_ecc_make_pub_ex(ecc_key* key, ecc_point* pubOut, WC_RNG* rng)
{
    WOLFSSL_ENTER("wc_ecc_make_pub");

    return ecc_make_pub_ex(key, NULL, pubOut, rng);
}


int wc_ecc_make_key_ex2(WC_RNG* rng, int keysize, ecc_key* key, int curve_id,
                        int flags)
{

    int err;

    if (key == NULL || rng == NULL) {
        return BAD_FUNC_ARG;
    }

    /* make sure required variables are reset */
    wc_ecc_reset(key);

    err = wc_ecc_set_curve(key, keysize, curve_id);
    if (err != 0) {
        return err;
    }

    key->flags = flags;

#ifdef WOLFSSL_HAVE_SP_ECC
#ifdef WOLFSSL_SP_384
    if (key->idx != ECC_CUSTOM_IDX && ecc_sets[key->idx].id == ECC_SECP384R1) {
        err = sp_ecc_make_key_384(rng, &key->k, &key->pubkey, key->heap);
        if (err == MP_OKAY) {
            key->type = ECC_PRIVATEKEY;
        }
    }
    else
#endif
#endif /* WOLFSSL_HAVE_SP_ECC */

   { /* software key gen */
        err = WC_KEY_SIZE_E;
    }

    return err;
}

WOLFSSL_ABI
int wc_ecc_make_key_ex(WC_RNG* rng, int keysize, ecc_key* key, int curve_id)
{
    return wc_ecc_make_key_ex2(rng, keysize, key, curve_id, WC_ECC_FLAG_NONE);
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
WOLFSSL_ABI
int wc_ecc_init_ex(ecc_key* key, void* heap, int devId)
{
    int ret = 0;

    if (key == NULL) {
        return BAD_FUNC_ARG;
    }

    XMEMSET(key, 0, sizeof(ecc_key));
    key->state = ECC_STATE_NONE;

    (void)devId;

    ret = mp_init_multi(&key->k, key->pubkey.x, key->pubkey.y, key->pubkey.z,
                                                                    NULL, NULL);
    if (ret != MP_OKAY) {
        return MEMORY_E;
    }

    key->heap = heap;

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
WOLFSSL_ABI
int wc_ecc_sign_hash(const byte* in, word32 inlen, byte* out, word32 *outlen,
                     WC_RNG* rng, ecc_key* key)
{
    int err;
#if !defined(WOLFSSL_ASYNC_CRYPT) || !defined(WC_ASYNC_ENABLE_ECC)
    mp_int r[1], s[1];
#endif

    if (in == NULL || out == NULL || outlen == NULL || key == NULL ||
                                                                rng == NULL) {
        return ECC_BAD_ARG_E;
    }

    XMEMSET(r, 0, sizeof(mp_int));
    XMEMSET(s, 0, sizeof(mp_int));

    if ((err = mp_init_multi(r, s, NULL, NULL, NULL, NULL)) != MP_OKAY){
        return err;
    }

    err = wc_ecc_sign_hash_ex(in, inlen, rng, key, r, s);
    if (err < 0) {
        mp_clear(r);
        mp_clear(s);
        return err;
    }

    /* encoded with DSA header */
    err = StoreECC_DSA_Sig(out, outlen, r, s);

    /* cleanup */
    mp_clear(r);
    mp_clear(s);

    return err;
}
#endif /* !NO_ASN */

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

   if (in == NULL || r == NULL || s == NULL || key == NULL || rng == NULL) {
       return ECC_BAD_ARG_E;
   }

   /* is this a private key? */
   if (key->type != ECC_PRIVATEKEY && key->type != ECC_PRIVATEKEY_ONLY) {
      return ECC_BAD_ARG_E;
   }

   /* is the IDX valid ?  */
   if (wc_ecc_is_valid_idx(key->idx) != 1) {
      return ECC_BAD_ARG_E;
   }

#if defined(WOLFSSL_SP_MATH)
    if (key->idx == ECC_CUSTOM_IDX || 
            (ecc_sets[key->idx].id != ECC_SECP256R1 && 
             ecc_sets[key->idx].id != ECC_SECP384R1)) {
        return WC_KEY_SIZE_E;
    }
#endif

#if defined(WOLFSSL_SP_MATH) || defined(WOLFSSL_HAVE_SP_ECC) || \
                  (defined(WOLFSSL_SP_MATH_ALL) && defined(WOLFSSL_HAVE_SP_ECC))
    if (key->idx != ECC_CUSTOM_IDX) {
    #if defined(WOLFSSL_ECDSA_SET_K) || defined(WOLFSSL_ECDSA_SET_K_ONE_LOOP)
        mp_int* sign_k = key->sign_k;
    #else
        mp_int* sign_k = NULL;
    #endif
    #ifdef WOLFSSL_SP_384
        if (ecc_sets[key->idx].id == ECC_SECP384R1) {
        #if !defined(WC_ECC_NONBLOCK) || (defined(WC_ECC_NONBLOCK) && !defined(WC_ECC_NONBLOCK_ONLY))
            return sp_ecc_sign_384(in, inlen, rng, &key->k, r, s, sign_k, 
                key->heap);
        #endif
        }
    #endif
    }
#endif

   return err;
}

#endif /* !HAVE_ECC_SIGN */

/**
  Free an ECC key from memory
  key   The key you wish to free
*/
WOLFSSL_ABI
int wc_ecc_free(ecc_key* key)
{
    if (key == NULL) {
        return 0;
    }

    mp_clear(key->pubkey.x);
    mp_clear(key->pubkey.y);
    mp_clear(key->pubkey.z);

    mp_forcezero(&key->k);

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

    r = &r_lcl;
    s = &s_lcl;
    XMEMSET(r, 0, sizeof(mp_int));
    XMEMSET(s, 0, sizeof(mp_int));

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

static int wc_ecc_check_r_s_range(ecc_key* key, mp_int* r, mp_int* s)
{
    int err;
    DECLARE_CURVE_SPECS(curve, 1);

    ALLOC_CURVE_SPECS(1);
    err = wc_ecc_curve_load(key->dp, &curve, ECC_CURVE_FIELD_ORDER);
    if (err != 0) {
        FREE_CURVE_SPECS();
        return err;
    }

    if (mp_iszero(r) || mp_iszero(s)) {
        err = MP_ZERO_E;
    }
    if ((err == 0) && (mp_cmp(r, curve->order) != MP_LT)) {
        err = MP_VAL;
    }
    if ((err == 0) && (mp_cmp(s, curve->order) != MP_LT)) {
        err = MP_VAL;
    }

    wc_ecc_curve_free(curve);
    FREE_CURVE_SPECS();
    return err;
}

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
   word32        keySz = 0;

   if (r == NULL || s == NULL || hash == NULL || res == NULL || key == NULL)
       return ECC_BAD_ARG_E;

   /* default to invalid signature */
   *res = 0;

   /* is the IDX valid ?  */
   if (wc_ecc_is_valid_idx(key->idx) != 1) {
      return ECC_BAD_ARG_E;
   }

   err = wc_ecc_check_r_s_range(key, r, s);
   if (err != MP_OKAY) {
      return err;
   }

   keySz = key->dp->size;

  /* checking if private key with no public part */
  if (key->type == ECC_PRIVATEKEY_ONLY) {
      WOLFSSL_MSG("Verify called with private key, generating public part");
      err = ecc_make_pub_ex(key, NULL, NULL, NULL);
      if (err != MP_OKAY) {
           WOLFSSL_MSG("Unable to extract public key");
           return err;
      }
  }

#if defined(WOLFSSL_SP_MATH) && !defined(FREESCALE_LTC_ECC)
    if (key->idx == ECC_CUSTOM_IDX || 
            (ecc_sets[key->idx].id != ECC_SECP256R1 && 
             ecc_sets[key->idx].id != ECC_SECP384R1)) {
        return WC_KEY_SIZE_E;
    }
#endif

#if defined(WOLFSSL_SP_MATH) || defined(WOLFSSL_HAVE_SP_ECC) || \
             (defined(WOLFSSL_SP_MATH_ALL) && defined(WOLFSSL_HAVE_SP_ECC)) && \
                                                     !defined(FREESCALE_LTC_ECC)
    if (key->idx != ECC_CUSTOM_IDX) {
    #ifdef WOLFSSL_SP_384
        if (ecc_sets[key->idx].id == ECC_SECP384R1) {
        #if !defined(WC_ECC_NONBLOCK) || (defined(WC_ECC_NONBLOCK) && !defined(WC_ECC_NONBLOCK_ONLY))
            return sp_ecc_verify_384(hash, hashlen, key->pubkey.x, 
                key->pubkey.y, key->pubkey.z, r, s, res, key->heap);
        #endif
        }
    #endif
    }

#endif /* WOLFSSL_ATECC508A */

   (void)keySz;
   (void)hashlen;

   return err;
}
#endif /* HAVE_ECC_VERIFY */

#ifdef HAVE_ECC_KEY_IMPORT
/* import point from der
 * if shortKeySize != 0 then keysize is always (inLen-1)>>1 */
int wc_ecc_import_point_der_ex(byte* in, word32 inLen, const int curve_idx,
                               ecc_point* point, int shortKeySize)
{
    int err = 0;
    int keysize;
    byte pointType;

#ifndef HAVE_COMP_KEY
    (void)shortKeySize;
#endif

    if (in == NULL || point == NULL || (curve_idx < 0) ||
        (wc_ecc_is_valid_idx(curve_idx) == 0))
        return ECC_BAD_ARG_E;

    /* must be odd */
    if ((inLen & 1) == 0) {
        return ECC_BAD_ARG_E;
    }

    /* init point */
    err = mp_init_multi(point->x, point->y, point->z, NULL, NULL, NULL);
    if (err != MP_OKAY)
        return MEMORY_E;

    /* check for point type (4, 2, or 3) */
    pointType = in[0];
    if (pointType != ECC_POINT_UNCOMP && pointType != ECC_POINT_COMP_EVEN &&
                                         pointType != ECC_POINT_COMP_ODD) {
        err = ASN_PARSE_E;
    }

    if (pointType == ECC_POINT_COMP_EVEN || pointType == ECC_POINT_COMP_ODD) {
        err = NOT_COMPILED_IN;
    }

    /* adjust to skip first byte */
    inLen -= 1;
    in += 1;

    /* calculate key size based on inLen / 2 if uncompressed or shortKeySize
     * is true */
    keysize = inLen>>1;

    /* read data */
    if (err == MP_OKAY)
        err = mp_read_unsigned_bin(point->x, (byte*)in, keysize);

    if (err == MP_OKAY) {
        err = mp_read_unsigned_bin(point->y, (byte*)in + keysize, keysize);
     }
    if (err == MP_OKAY)
        err = mp_set(point->z, 1);

    if (err != MP_OKAY) {
        mp_clear(point->x);
        mp_clear(point->y);
        mp_clear(point->z);
    }

    return err;
}

/* function for backwards compatiblity with previous implementations */
int wc_ecc_import_point_der(byte* in, word32 inLen, const int curve_idx,
                            ecc_point* point)
{
    return wc_ecc_import_point_der_ex(in, inLen, curve_idx, point, 1);
}
#endif /* HAVE_ECC_KEY_IMPORT */


/* is ecc point on curve described by dp ? */
int wc_ecc_is_point(ecc_point* ecp, mp_int* a, mp_int* b, mp_int* prime)
{
   (void)a;
   (void)b;
#ifdef WOLFSSL_SP_384
   if (mp_count_bits(prime) == 384) {
       return sp_ecc_is_point_384(ecp->x, ecp->y);
   }
#endif
   return WC_KEY_SIZE_E;
}

/*!
    \ingroup ECC

    \brief Perform sanity checks on ecc key validity.

    \return MP_OKAY Success, key is OK.
    \return BAD_FUNC_ARG Returns if key is NULL.
    \return ECC_INF_E Returns if wc_ecc_point_is_at_infinity returns 1.

    \param key Pointer to key to check.

    _Example_
    \code
    ecc_key key;
    WC_WC_RNG rng;
    int check_result;
    wc_ecc_init(&key);
    wc_InitRng(&rng);
    wc_ecc_make_key(&rng, 32, &key);
    check_result = wc_ecc_check_key(&key);

    if (check_result == MP_OKAY)
    {
        // key check succeeded
    }
    else
    {
        // key check failed
    }
    \endcode

    \sa wc_ecc_point_is_at_infinity
*/

/* perform sanity checks on ecc key validity, 0 on success */
int wc_ecc_check_key(ecc_key* key)
{
    if (key == NULL)
        return BAD_FUNC_ARG;

#ifdef WOLFSSL_HAVE_SP_ECC
#ifdef WOLFSSL_SP_384
    if (key->idx != ECC_CUSTOM_IDX && ecc_sets[key->idx].id == ECC_SECP384R1) {
        return sp_ecc_check_key_384(key->pubkey.x, key->pubkey.y,
            key->type == ECC_PRIVATEKEY ? &key->k : NULL, key->heap);
    }
#endif
#endif

    return WC_KEY_SIZE_E;
}

#ifdef HAVE_ECC_KEY_IMPORT
/*!
    \ingroup ECC

    \brief This function imports a public ECC key from a buffer containing the
    key stored in ANSI X9.63 format. This function will handle both compressed
    and uncompressed keys, as long as compressed keys are enabled at compile
    time through the HAVE_COMP_KEY option.

    \return 0 Returned on successfully importing the ecc_key
    \return NOT_COMPILED_IN Returned if the HAVE_COMP_KEY was not enabled at
    compile time, but the key is stored in compressed format
    \return ECC_BAD_ARG_E Returned if in or key evaluate to NULL, or the
    inLen is even (according to the x9.63 standard, the key must be odd)
    \return MEMORY_E Returned if there is an error allocating memory
    \return ASN_PARSE_E Returned if there is an error parsing the ECC key;
    may indicate that the ECC key is not stored in valid ANSI X9.63 format
    \return IS_POINT_E Returned if the public key exported is not a point
    on the ECC curve
    \return MP_INIT_E if there is an error processing the
    ecc_key
    \return MP_READ_E if there is an error processing the
    ecc_key
    \return MP_CMP_E if there is an error processing the
    ecc_key
    \return MP_INVMOD_E if there is an error processing the
    ecc_key
    \return MP_EXPTMOD_E if there is an error processing the
    ecc_key
    \return MP_MOD_E if there is an error processing the
    ecc_key
    \return MP_MUL_E if there is an error processing the
    ecc_key
    \return MP_ADD_E if there is an error processing the
    ecc_key
    \return MP_MULMOD_E if there is an error processing the
    ecc_key
    \return MP_TO_E if there is an error processing the ecc_key
    \return MP_MEM if there is an error processing the ecc_key

    \param in pointer to the buffer containing the ANSI x9.63 formatted ECC key
    \param inLen length of the input buffer
    \param key pointer to the ecc_key object in which to store the imported key

    _Example_
    \code
    int ret;
    byte buff[] = { initialize with ANSI X9.63 formatted key };

    ecc_key pubKey;
    wc_ecc_init(&pubKey);

    ret = wc_ecc_import_x963(buff, sizeof(buff), &pubKey);
    if ( ret != 0) {
        // error importing key
    }
    \endcode

    \sa wc_ecc_import_private_key
*/
int wc_ecc_import_x963_ex(const byte* in, word32 inLen, ecc_key* key,
                          int curve_id)
{
    int err = MP_OKAY;
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
    err = mp_init_multi(&key->k,
                    key->pubkey.x, key->pubkey.y, key->pubkey.z, NULL, NULL);
    if (err != MP_OKAY)
        return MEMORY_E;

    /* check for point type (4, 2, or 3) */
    pointType = in[0];
    if (pointType != ECC_POINT_UNCOMP && pointType != ECC_POINT_COMP_EVEN &&
                                         pointType != ECC_POINT_COMP_ODD) {
        err = ASN_PARSE_E;
    }

    if (pointType == ECC_POINT_COMP_EVEN || pointType == ECC_POINT_COMP_ODD) {
        err = NOT_COMPILED_IN;
    }

    /* adjust to skip first byte */
    inLen -= 1;
    in += 1;

    if (err == MP_OKAY) {
        /* determine key size */
        keysize = (inLen>>1);
        err = wc_ecc_set_curve(key, keysize, curve_id);
        key->type = ECC_PUBLICKEY;
    }

    /* read data */
    if (err == MP_OKAY)
        err = mp_read_unsigned_bin(key->pubkey.x, (byte*)in, keysize);


    if (err == MP_OKAY) {
        err = mp_read_unsigned_bin(key->pubkey.y, (byte*)in + keysize,
                                                                      keysize);
    }
    if (err == MP_OKAY)
        err = mp_set(key->pubkey.z, 1);

    if (err != MP_OKAY) {
        mp_clear(key->pubkey.x);
        mp_clear(key->pubkey.y);
        mp_clear(key->pubkey.z);
        mp_clear(&key->k);
    }

    return err;
}

WOLFSSL_ABI
int wc_ecc_import_x963(const byte* in, word32 inLen, ecc_key* key)
{
    return wc_ecc_import_x963_ex(in, inLen, key, ECC_CURVE_DEF);
}
#endif /* HAVE_ECC_KEY_IMPORT */

#ifdef HAVE_ECC_KEY_IMPORT
/*!
    \ingroup ECC

    \brief This function imports a public/private ECC key pair from a buffer
    containing the raw private key, and a second buffer containing the ANSI
    X9.63 formatted public key. This function will handle both compressed and
    uncompressed keys, as long as compressed keys are enabled at compile time
    through the HAVE_COMP_KEY option.

    \return 0 Returned on successfully importing the ecc_key
    \return ECC_BAD_ARG_E Returned if in or key evaluate to NULL, or the
    inLen is even (according to the x9.63 standard, the key must be odd)
    \return MEMORY_E Returned if there is an error allocating memory
    \return ASN_PARSE_E Returned if there is an error parsing the ECC key;
    may indicate that the ECC key is not stored in valid ANSI X9.63 format
    \return IS_POINT_E Returned if the public key exported is not a point
    on the ECC curve
    \return one of the following if there is an error processing the ecc_key:
            MP_INIT_E, MP_READ_E, MP_CMP_E, MP_INVMOD_E MP_EXPTMOD_E MP_MOD_E MP_MUL_E
            MP_ADD_E MP_MULMOD_E MP_TO_E MP_MEM

    \param priv pointer to the buffer containing the raw private key
    \param privSz size of the private key buffer
    \param pub pointer to the buffer containing the ANSI x9.63 formatted ECC
    public key
    \param pubSz length of the public key input buffer
    \param key pointer to the ecc_key object in which to store the imported
    private/public key pair

    _Example_
    \code
    int ret;
    byte pub[] = { initialize with ANSI X9.63 formatted key };
    byte priv[] = { initialize with the raw private key };

    ecc_key key;
    wc_ecc_init(&key);
    ret = wc_ecc_import_private_key(priv, sizeof(priv), pub, sizeof(pub),
    &key);
    if ( ret != 0) {
        // error importing key
    }
    \endcode

*/
int wc_ecc_import_private_key_ex(const byte* priv, word32 privSz,
                                 const byte* pub, word32 pubSz, ecc_key* key,
                                 int curve_id)
{
    int ret;
    if (key == NULL || priv == NULL)
        return BAD_FUNC_ARG;

    /* public optional, NULL if only importing private */
    if (pub != NULL) {
        word32 idx = 0;
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

    ret = mp_read_unsigned_bin(&key->k, priv, privSz);

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

#ifndef NO_ASN
/*!
    \ingroup ECC

    \brief This function converts the R and S portions of an ECC signature
    into a DER-encoded ECDSA signature. This function also stores the length
    written to the output buffer, out, in outlen.

    \return 0 Returned on successfully converting the signature
    \return ECC_BAD_ARG_E Returned if any of the input parameters evaluate
    to NULL, or if the input buffer is not large enough to hold the
    DER-encoded ECDSA signature
    \return one of the following if there is an error processing:
            MP_INIT_E MP_READ_E MP_CMP_E MP_INVMOD_E MP_EXPTMOD_E MP_MOD_E
            MP_MUL_E MP_ADD_E MP_MULMOD_E MP_TO_E MP_MEM

    \param r pointer to the buffer containing the R portion of the signature as a string
    \param s pointer to the buffer containing the S portion of the signature as a string
    \param out pointer to the buffer in which to store the DER-encoded ECDSA signature
    \param outlen length of the output buffer available. Will store the bytes
    written to the buffer after successfully converting the signature to
    ECDSA format

    _Example_
    \code
    int ret;
    ecc_key key;
    // initialize key, generate R and S

    char r[] = { initialize with R };
    char s[] = { initialize with S };
    byte sig[wc_ecc_sig_size(key)];
    // signature size will be 2 * ECC key size + ~10 bytes for ASN.1 overhead
    word32 sigSz = sizeof(sig);
    ret = wc_ecc_rs_to_sig(r, s, sig, &sigSz);
    if ( ret != 0) {
        // error converting parameters to signature
    }
    \endcode

    \sa wc_ecc_sign_hash
    \sa wc_ecc_sig_size
*/

int wc_ecc_rs_to_sig(const char* r, const char* s, byte* out, word32* outlen)
{
    int err;
    mp_int  rtmp[1];
    mp_int  stmp[1];

    if (r == NULL || s == NULL || out == NULL || outlen == NULL)
        return ECC_BAD_ARG_E;

    err = mp_init_multi(rtmp, stmp, NULL, NULL, NULL, NULL);
    if (err != MP_OKAY) {
        return err;
    }

    err = mp_read_radix(rtmp, r, MP_RADIX_HEX);
    if (err == MP_OKAY)
        err = mp_read_radix(stmp, s, MP_RADIX_HEX);

    if (err == MP_OKAY) {
        if (mp_iszero(rtmp) == MP_YES || mp_iszero(stmp) == MP_YES)
            err = MP_ZERO_E;
    }

    /* convert mp_ints to ECDSA sig, initializes rtmp and stmp internally */
    if (err == MP_OKAY)
        err = StoreECC_DSA_Sig(out, outlen, rtmp, stmp);

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
    if (r == NULL || s == NULL || out == NULL || outlen == NULL)
        return ECC_BAD_ARG_E;

    /* convert mp_ints to ECDSA sig, initializes rtmp and stmp internally */
    return StoreECC_DSA_Sig_Bin(out, outlen, r, rSz, s, sSz);
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
    if (sig == NULL || r == NULL || rLen == NULL || s == NULL || sLen == NULL)
        return ECC_BAD_ARG_E;

    return DecodeECC_DSA_Sig_Bin(sig, sigLen, r, rLen, s, sLen);
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
    err = mp_init_multi(&key->k, key->pubkey.x, key->pubkey.y, key->pubkey.z,
                                                                  NULL, NULL);
    if (err != MP_OKAY)
        return MEMORY_E;

    /* read Qx */
    if (err == MP_OKAY) {
        if (encType == WC_TYPE_HEX_STR)
            err = mp_read_radix(key->pubkey.x, qx, MP_RADIX_HEX);
        else
            err = mp_read_unsigned_bin(key->pubkey.x, (const byte*)qx,
                key->dp->size);

        if (mp_iszero(key->pubkey.x)) {
            WOLFSSL_MSG("Invalid Qx");
            err = BAD_FUNC_ARG;
        }
    }

    /* read Qy */
    if (err == MP_OKAY) {
        if (encType == WC_TYPE_HEX_STR)
            err = mp_read_radix(key->pubkey.y, qy, MP_RADIX_HEX);
        else
            err = mp_read_unsigned_bin(key->pubkey.y, (const byte*)qy,
                key->dp->size);

        if (mp_iszero(key->pubkey.y)) {
            WOLFSSL_MSG("Invalid Qy");
            err = BAD_FUNC_ARG;
        }
    }

    if (err == MP_OKAY)
        err = mp_set(key->pubkey.z, 1);

    /* import private key */
    if (err == MP_OKAY) {
        if (d != NULL) {

            key->type = ECC_PRIVATEKEY;

            if (encType == WC_TYPE_HEX_STR)
                err = mp_read_radix(&key->k, d, MP_RADIX_HEX);
            else
                err = mp_read_unsigned_bin(&key->k, (const byte*)d,
                    key->dp->size);
            if (mp_iszero(&key->k)) {
                WOLFSSL_MSG("Invalid private key");
                return BAD_FUNC_ARG;
            }
        } else {
            key->type = ECC_PUBLICKEY;
        }
    }

    if (err != MP_OKAY) {
        mp_clear(key->pubkey.x);
        mp_clear(key->pubkey.y);
        mp_clear(key->pubkey.z);
        mp_clear(&key->k);
    }

    return err;
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
    if (orderBits > keySz * 8) {
        keySz = (orderBits + 7) / 8;
    }
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

#ifdef ECC_TIMING_RESISTANT
int wc_ecc_set_rng(ecc_key* key, WC_RNG* rng)
{
    int err = 0;

    if (key == NULL) {
        err = BAD_FUNC_ARG;
    }
    else {
        key->rng = rng;
    }

    return err;
}
#endif

/*!
    \ingroup ECC

    \brief This function finds and returns a matching OID sum.

    \return oid if found
    \return BAD_FUNC_ARG if oidSum is zero

    \param oidSum
    \param oid
    \param oidSz

*/

int wc_ecc_get_oid(word32 oidSum, const byte** oid, word32* oidSz)
{
    int x;

    if (oidSum == 0) {
        return BAD_FUNC_ARG;
    }

    /* find matching OID sum (based on encoded value) */
    for (x = 0; ecc_sets[x].size != 0; x++) {
        if (ecc_sets[x].oidSum == oidSum) {
            int ret;
            if (oidSz) {
                *oidSz = ecc_sets[x].oidSz;
            }
            if (oid) {
                *oid = ecc_sets[x].oid;
            }
            ret = ecc_sets[x].id;
            return ret;
        }
    }

    return NOT_COMPILED_IN;
}
#if defined(HAVE_ECC) || defined(WOLFSSL_EXPORT_INT)
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
#endif

#ifdef HAVE_ECC_KEY_EXPORT
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

    if (wc_ecc_is_valid_idx(key->idx) == 0 || key->dp == NULL) {
        return ECC_BAD_ARG_E;
    }
    keySz = key->dp->size;

    /* private key, d */
    if (d != NULL) {
        if (dLen == NULL ||
            (key->type != ECC_PRIVATEKEY && key->type != ECC_PRIVATEKEY_ONLY))
            return BAD_FUNC_ARG;

        {
            err = wc_export_int(&key->k, d, dLen, keySz, encType);
            if (err != MP_OKAY)
                return err;
        }

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

/* export point to der */

int wc_ecc_export_point_der_ex(const int curve_idx, ecc_point* point, byte* out,
                               word32* outLen, int compressed)
{
    if (compressed == 0)
        return wc_ecc_export_point_der(curve_idx, point, out, outLen);
#ifdef HAVE_COMP_KEY
    else
        return wc_ecc_export_point_der_compressed(curve_idx, point, out, outLen);
#else
    return NOT_COMPILED_IN;
#endif
}

int wc_ecc_export_point_der(const int curve_idx, ecc_point* point, byte* out,
                            word32* outLen)
{
    int    ret = MP_OKAY;
    word32 numlen;
#ifdef WOLFSSL_SMALL_STACK
    byte*  buf;
#else
    byte   buf[ECC_BUFSIZE];
#endif

    if ((curve_idx < 0) || (wc_ecc_is_valid_idx(curve_idx) == 0))
        return ECC_BAD_ARG_E;

    numlen = ecc_sets[curve_idx].size;

    /* return length needed only */
    if (point != NULL && out == NULL && outLen != NULL) {
        *outLen = 1 + 2*numlen;
        return LENGTH_ONLY_E;
    }

    if (point == NULL || out == NULL || outLen == NULL)
        return ECC_BAD_ARG_E;

    if (*outLen < (1 + 2*numlen)) {
        *outLen = 1 + 2*numlen;
        return BUFFER_E;
    }

    /* store byte point type */
    out[0] = ECC_POINT_UNCOMP;

#ifdef WOLFSSL_SMALL_STACK
    buf = (byte*)XMALLOC(ECC_BUFSIZE, NULL, DYNAMIC_TYPE_ECC_BUFFER);
    if (buf == NULL)
        return MEMORY_E;
#endif

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
#ifdef WOLFSSL_SMALL_STACK
    XFREE(buf, NULL, DYNAMIC_TYPE_ECC_BUFFER);
#endif

    return ret;
}


/* export point to der */
#ifdef HAVE_COMP_KEY
int wc_ecc_export_point_der_compressed(const int curve_idx, ecc_point* point,
                                       byte* out, word32* outLen)
{
    int    ret = MP_OKAY;
    word32 numlen;
    word32 output_len;
#ifdef WOLFSSL_SMALL_STACK
    byte*  buf;
#else
    byte   buf[ECC_BUFSIZE];
#endif

    if ((curve_idx < 0) || (wc_ecc_is_valid_idx(curve_idx) == 0))
        return ECC_BAD_ARG_E;

    numlen = ecc_sets[curve_idx].size;
    output_len = 1 + numlen; /* y point type + x */

    /* return length needed only */
    if (point != NULL && out == NULL && outLen != NULL) {
        *outLen = output_len;
        return LENGTH_ONLY_E;
    }

    if (point == NULL || out == NULL || outLen == NULL)
        return ECC_BAD_ARG_E;


    if (*outLen < output_len) {
        *outLen = output_len;
        return BUFFER_E;
    }

    /* store byte point type */
    out[0] = mp_isodd(point->y) == MP_YES ? ECC_POINT_COMP_ODD :
                                            ECC_POINT_COMP_EVEN;

#ifdef WOLFSSL_SMALL_STACK
    buf = (byte*)XMALLOC(ECC_BUFSIZE, NULL, DYNAMIC_TYPE_ECC_BUFFER);
    if (buf == NULL)
        return MEMORY_E;
#endif

    /* pad and store x */
    XMEMSET(buf, 0, ECC_BUFSIZE);
    ret = mp_to_unsigned_bin(point->x, buf +
                                 (numlen - mp_unsigned_bin_size(point->x)));
    if (ret != MP_OKAY)
        goto done;
    XMEMCPY(out+1, buf, numlen);

    *outLen = output_len;

done:
#ifdef WOLFSSL_SMALL_STACK
    XFREE(buf, NULL, DYNAMIC_TYPE_ECC_BUFFER);
#endif

    return ret;
}
#endif /* HAVE_COMP_KEY */

/* export public ECC key in ANSI X9.63 format */
int wc_ecc_export_x963(ecc_key* key, byte* out, word32* outLen)
{
   int    ret = MP_OKAY;
   word32 numlen;
#ifdef WOLFSSL_SMALL_STACK
   byte*  buf;
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

   if (key->type == 0 || wc_ecc_is_valid_idx(key->idx) == 0 || key->dp == NULL){
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

#ifdef WOLFSSL_SMALL_STACK
   buf = (byte*)XMALLOC(ECC_BUFSIZE, NULL, DYNAMIC_TYPE_ECC_BUFFER);
   if (buf == NULL)
      return MEMORY_E;
#endif

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
#ifdef WOLFSSL_SMALL_STACK
   XFREE(buf, NULL, DYNAMIC_TYPE_ECC_BUFFER);
#endif

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

#endif /* HAVE_ECC */
