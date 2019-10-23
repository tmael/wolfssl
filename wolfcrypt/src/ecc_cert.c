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

/* in case user set HAVE_ECC there */
#include <wolfssl/wolfcrypt/settings.h>

/* public ASN interface */
#include <wolfssl/wolfcrypt/asn_public.h>

#ifdef HAVE_DO178
/*
Only supports ECC SP with WOLFSSL_SP_MATH
*/

/*
Possible ECC enable options:
 * HAVE_ECC:            Overall control of ECC                  default: on
 * HAVE_ECC_SIGN:       ECC sign                                default: on
 * HAVE_ECC_VERIFY:     ECC verify                              default: on
 * HAVE_ECC_DHE:        ECC build shared secret                 default: on
 * HAVE_ECC_KEY_IMPORT: ECC Key import                          default: on
 * HAVE_ECC_KEY_EXPORT: ECC Key export                          default: on
 */

/*
ECC Curve Types:
 * NO_ECC_SECP          Disables SECP curves                    default: off (not defined)
   ECC_SECP256R1
 */

/*
ECC Curve Sizes:
 * NO_ECC256: Disables 256 bit key (on by default)
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
};

/* 256-bit curve on by default whether user curves or not */
#if !defined(NO_ECC256)  || defined(HAVE_ALL_CURVES)
    #define ECC256
#endif

/* The encoded OID's for ECC curves */
#ifdef ECC256
    #ifndef NO_ECC_SECP
        #define CODED_SECP256R1    {0x2A,0x86,0x48,0xCE,0x3D,0x03,0x01,0x07}
        #define CODED_SECP256R1_SZ 8
        #ifndef USE_WINDOWS_API
            static const ecc_oid_t ecc_oid_secp256r1[] = CODED_SECP256R1;
        #else
            #define ecc_oid_secp256r1 CODED_SECP256R1
        #endif
        #define ecc_oid_secp256r1_sz CODED_SECP256R1_SZ
    #endif /* !NO_ECC_SECP */
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
#endif /* ECC256 */
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

/* not thread safe, only supports SINGLE_THREADED */
#ifdef ECC_POINTS_LIST_SZ
	static ecc_point ecc_pointGlobal[ECC_POINTS_LIST_SZ];
#else
	static ecc_point ecc_pointGlobal[4];
#endif
static int ecc_pointGlobalInx = 0;

/* Curve Specs */
typedef struct ecc_curve_spec {
    const ecc_set_type* dp;

    mp_int* prime;
    mp_int* Af;
    mp_int* order;
    mp_int* Gx;
    mp_int* Gy;

    mp_int* spec_ints;
    word32 spec_count;
    word32 spec_use;

    byte load_mask;
} ecc_curve_spec;

enum ecc_curve_load_mask {
    ECC_CURVE_FIELD_NONE    = 0x00,
    ECC_CURVE_FIELD_PRIME   = 0x01,
    ECC_CURVE_FIELD_AF      = 0x02,
    ECC_CURVE_FIELD_ORDER   = 0x08,
    ECC_CURVE_FIELD_GX      = 0x10,
    ECC_CURVE_FIELD_GY      = 0x20,
    ECC_CURVE_FIELD_ALL     = 0x3B,
    ECC_CURVE_FIELD_COUNT   = 5,
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

static void _wc_ecc_curve_free(ecc_curve_spec* curve)
{
    if (curve == NULL) {
        return;
    }

    if (curve->load_mask & ECC_CURVE_FIELD_PRIME)
        mp_clear(curve->prime);
    if (curve->load_mask & ECC_CURVE_FIELD_AF)
        mp_clear(curve->Af);
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
    _wc_ecc_curve_free(curve);
    (void)curve;
}

static int wc_ecc_curve_load_item(const char* src, mp_int** dst,
    ecc_curve_spec* curve, byte mask)
{
    int err;

    /* get mp_int from temp */
    if (curve->spec_use >= curve->spec_count) {
        WOLFSSL_MSG("Invalid DECLARE_CURVE_SPECS count");
        return ECC_BAD_ARG_E;
    }
    *dst = &curve->spec_ints[curve->spec_use++];

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
    int ret = 0, x;
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
    x = 0;
    if (load_items & ECC_CURVE_FIELD_PRIME)
        x += wc_ecc_curve_load_item(dp->prime, &curve->prime, curve,
            ECC_CURVE_FIELD_PRIME);
    if (load_items & ECC_CURVE_FIELD_AF)
        x += wc_ecc_curve_load_item(dp->Af, &curve->Af, curve,
            ECC_CURVE_FIELD_AF);
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
int wc_ecc_mulmod_ex(mp_int* k, ecc_point *G, ecc_point *R,
                  mp_int* a, mp_int* modulus, int map,
                  void* heap)
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

/**
 * use a heap hint when creating new ecc_point
 * return an allocated point on success or NULL on failure
 */
ecc_point* wc_ecc_new_point_h(void* heap)
{
#ifdef ECC_POINTS_LIST_SZ
   ecc_point* p = &ecc_pointGlobal[ecc_pointGlobalInx++ % ECC_POINTS_LIST_SZ];
#else
   ecc_point* p = &ecc_pointGlobal[ecc_pointGlobalInx++ % 4];
#endif
   (void)heap;

   XMEMSET(p, 0, sizeof(ecc_point));

   if (mp_init_multi(p->x, p->y, p->z, NULL, NULL, NULL) != MP_OKAY) {
      return NULL;

   }
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
      //XFREE(p, heap, DYNAMIC_TYPE_ECC);
      ecc_pointGlobalInx--;
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

static int wc_ecc_shared_secret_gen_sync(ecc_key* private_key, ecc_point* point,
                               byte* out, word32* outlen, ecc_curve_spec* curve)
{
    int err;
#ifndef WOLFSSL_SP_MATH
    ecc_point* result = NULL;
    word32 x = 0;
#endif
    mp_int* k = &private_key->k;
#ifdef WOLFSSL_HAVE_SP_ECC
#ifndef WOLFSSL_SP_NO_256
    if (private_key->idx != ECC_CUSTOM_IDX &&
                               ecc_sets[private_key->idx].id == ECC_SECP256R1) {
        err = sp_ecc_secret_gen_256(k, point, out, outlen, private_key->heap);
    }
    else
#endif
#endif
    {
        err = WC_KEY_SIZE_E;

        (void)curve;
    }

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

    err = wc_ecc_shared_secret_gen(private_key, point, out, outlen);

    return err;
}
#endif /* HAVE_ECC_DHE */

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
    ecc_point* pub;
    DECLARE_CURVE_SPECS(curve, ECC_CURVE_FIELD_COUNT);
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
        ALLOC_CURVE_SPECS(ECC_CURVE_FIELD_COUNT);

        /* load curve info */
        if (err == MP_OKAY)
            err = wc_ecc_curve_load(key->dp, &curve, ECC_CURVE_FIELD_ALL);
    }

    if (err == MP_OKAY) {
        err = mp_init_multi(pub->x, pub->y, pub->z, NULL, NULL, NULL);
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

    if (err != MP_OKAY) {
        /* clean up if failed */
        mp_clear(pub->x);
        mp_clear(pub->y);
        mp_clear(pub->z);
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

    return wc_ecc_make_pub_ex(key, NULL, pubOut);
}


int wc_ecc_make_key_ex(WC_RNG* rng, int keysize, ecc_key* key, int curve_id)
{
    int err;

    if (key == NULL || rng == NULL) {
        return BAD_FUNC_ARG;
    }

    err = wc_ecc_set_curve(key, keysize, curve_id);
    if (err != 0) {
        return err;
    }


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
int wc_ecc_sign_hash(const byte* in, word32 inlen, byte* out, word32 *outlen,
                     WC_RNG* rng, ecc_key* key)
{
    int err;
    mp_int r[1], s[1];

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

   if (key->idx != ECC_CUSTOM_IDX && ecc_sets[key->idx].id == ECC_SECP256R1)
       return sp_ecc_sign_256(in, inlen, rng, &key->k, r, s, key->heap);
   else
       return WC_KEY_SIZE_E;

   return err;
}
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
    mp_int r_lcl, s_lcl;

    if (sig == NULL || hash == NULL || res == NULL || key == NULL) {
        return ECC_BAD_ARG_E;
    }

    r = &r_lcl;
    s = &s_lcl;
    XMEMSET(r, 0, sizeof(mp_int));
    XMEMSET(s, 0, sizeof(mp_int));

    /* default to invalid signature */
    *res = 0;

    /* Note, DecodeECC_DSA_Sig() calls mp_init() on r and s.
     * If either of those don't allocate correctly, none of
     * the rest of this function will execute, and everything
     * gets cleaned up at the end. */
    /* decode DSA header */
    err = DecodeECC_DSA_Sig(sig, siglen, r, s);

    if (err == MP_OKAY)
        err = wc_ecc_verify_hash_ex(r, s, hash, hashlen, res, key);

    /* done with R/S */
    mp_clear(r);
    mp_clear(s);

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

   if (r == NULL || s == NULL || hash == NULL || res == NULL || key == NULL)
       return ECC_BAD_ARG_E;

   /* default to invalid signature */
   *res = 0;

   /* is the IDX valid ?  */
   if (wc_ecc_is_valid_idx(key->idx) != 1) {
      return ECC_BAD_ARG_E;
   }

   keySz = key->dp->size;

  /* checking if private key with no public part */
  if (key->type == ECC_PRIVATEKEY_ONLY) {
      WOLFSSL_MSG("Verify called with private key, generating public part");
      err = wc_ecc_make_pub_ex(key, NULL, NULL);
      if (err != MP_OKAY) {
           WOLFSSL_MSG("Unable to extract public key");
           return err;
      }
  }

  if (key->idx != ECC_CUSTOM_IDX && ecc_sets[key->idx].id == ECC_SECP256R1) {
      return sp_ecc_verify_256(hash, hashlen, key->pubkey.x, key->pubkey.y,
                                           key->pubkey.z, r, s, res, key->heap);
  }
  else
      return WC_KEY_SIZE_E;

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
   byte   buf[ECC_BUFSIZE];
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

    return NOT_COMPILED_IN;
}
#endif /* HAVE_ECC_KEY_EXPORT */

/* is ecc point on curve described by dp ? */
int wc_ecc_is_point(ecc_point* ecp, mp_int* a, mp_int* b, mp_int* prime)
{

   (void)a;
   (void)b;
   (void)prime;

   return sp_ecc_is_point_256(ecp->x, ecp->y);
}

/* perform sanity checks on ecc key validity, 0 on success */
int wc_ecc_check_key(ecc_key* key)
{
    int    err;

    if (key == NULL)
        return BAD_FUNC_ARG;

    /* pubkey point cannot be at infinity */
    if (key->idx != ECC_CUSTOM_IDX && ecc_sets[key->idx].id == ECC_SECP256R1) {
        err = sp_ecc_check_key_256(key->pubkey.x, key->pubkey.y, &key->k,
                                                                     key->heap);
    }
    else
        err = WC_KEY_SIZE_E;
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
    if (err == MP_OKAY && compressed == 0)
        err = mp_read_unsigned_bin(key->pubkey.y, (byte*)in + keysize, keysize);
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
        err = wc_export_int(&key->k, d, dLen, keySz, encType);
        if (err != MP_OKAY)
            return err;
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
    mp_int  rtmp[1];
    mp_int  stmp[1];

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
    mp_int  rtmp[1];
    mp_int  stmp[1];

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

    /* import private key */
    if (err == MP_OKAY) {
        if (d != NULL && d[0] != '\0') {
            key->type = ECC_PRIVATEKEY;

            if (encType == WC_TYPE_HEX_STR)
                err = mp_read_radix(&key->k, d, MP_RADIX_HEX);
            else
                err = mp_read_unsigned_bin(&key->k, (const byte*)d,
                    key->dp->size);
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
            if (oidSz) {
                *oidSz = ecc_sets[x].oidSz;
            }
            if (oid) {
                *oid = ecc_sets[x].oid;
            }
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
