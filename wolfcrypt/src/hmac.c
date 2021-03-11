/* hmac.c
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

#include <wolfssl/wolfcrypt/wc_port.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#ifndef NO_HMAC

#include <wolfssl/wolfcrypt/hmac.h>

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

int wc_HmacSizeByType(int type)
{
    int ret;

    if (!(type == WC_SHA256 || type == WC_SHA384)) {
        return BAD_FUNC_ARG;
    }

    switch (type) {
    #ifndef NO_SHA256
        case WC_SHA256:
            ret = WC_SHA256_DIGEST_SIZE;
            break;
    #endif /* !NO_SHA256 */

    #ifdef WOLFSSL_SHA384
        case WC_SHA384:
            ret = WC_SHA384_DIGEST_SIZE;
            break;
    #endif /* WOLFSSL_SHA384 */

        default:
            ret = BAD_FUNC_ARG;
            break;
    }

    return ret;
}

int _InitHmac(Hmac* hmac, int type, void* heap)
{
    int ret = 0;

    switch (type) {

    #ifndef NO_SHA256
        case WC_SHA256:
            ret = wc_InitSha256(&hmac->hash.sha256);
            break;
    #endif /* !NO_SHA256 */

    #ifdef WOLFSSL_SHA384
        case WC_SHA384:
            ret = wc_InitSha384(&hmac->hash.sha384);
            break;
    #endif /* WOLFSSL_SHA384 */
        default:
            ret = BAD_FUNC_ARG;
            break;
    }
    hmac->heap = heap;

    return ret;
}


int wc_HmacSetKey(Hmac* hmac, int type, const byte* key, word32 length)
{
    byte*  ip;
    byte*  op;
    word32 i, hmac_block_size = 0;
    int    ret = 0;
    void*  heap = NULL;

    if (hmac == NULL || (key == NULL && length != 0) ||
       !(type == WC_SHA256 ||type == WC_SHA384)) {
        return BAD_FUNC_ARG;
    }

    /* if set key has already been run then make sure and free existing */
    /* This is for async and PIC32MZ situations, and just normally OK,
       provided the user calls wc_HmacInit() first. That function is not
       available in FIPS builds. In current FIPS builds, the hashes are
       not allocating resources. */
    if (hmac->macType != WC_HASH_TYPE_NONE) {
        wc_HmacFree(hmac);
    }

    hmac->innerHashKeyed = 0;
    hmac->macType = (byte)type;

    ret = _InitHmac(hmac, type, heap);
    if (ret != 0)
        return ret;

    ip = (byte*)hmac->ipad;
    op = (byte*)hmac->opad;

    switch (hmac->macType) {
    #ifndef NO_SHA256
        case WC_SHA256:
            hmac_block_size = WC_SHA256_BLOCK_SIZE;
            if (length <= WC_SHA256_BLOCK_SIZE) {
                if (key != NULL) {
                    XMEMCPY(ip, key, length);
                }
            }
            else {
                ret = wc_Sha256Update(&hmac->hash.sha256, key, length);
                if (ret != 0)
                    break;
                ret = wc_Sha256Final(&hmac->hash.sha256, ip);
                if (ret != 0)
                    break;

                length = WC_SHA256_DIGEST_SIZE;
            }
            break;
    #endif /* !NO_SHA256 */

    #ifdef WOLFSSL_SHA384
        case WC_SHA384:
            hmac_block_size = WC_SHA384_BLOCK_SIZE;
            if (length <= WC_SHA384_BLOCK_SIZE) {
                if (key != NULL) {
                    XMEMCPY(ip, key, length);
                }
            }
            else {
                ret = wc_Sha384Update(&hmac->hash.sha384, key, length);
                if (ret != 0)
                    break;
                ret = wc_Sha384Final(&hmac->hash.sha384, ip);
                if (ret != 0)
                    break;

                length = WC_SHA384_DIGEST_SIZE;
            }
            break;
    #endif /* WOLFSSL_SHA384 */
        default:
            return BAD_FUNC_ARG;
    }
    if (ret == 0) {
        if (length < hmac_block_size)
            XMEMSET(ip + length, 0, hmac_block_size - length);

        for(i = 0; i < hmac_block_size; i++) {
            op[i] = ip[i] ^ OPAD;
            ip[i] ^= IPAD;
        }
    }

    return ret;
}


static int HmacKeyInnerHash(Hmac* hmac)
{
    int ret = 0;

    switch (hmac->macType) {
    #ifndef NO_SHA256
        case WC_SHA256:
            ret = wc_Sha256Update(&hmac->hash.sha256, (byte*)hmac->ipad,
                                                          WC_SHA256_BLOCK_SIZE);
            break;
    #endif /* !NO_SHA256 */

    #ifdef WOLFSSL_SHA384
        case WC_SHA384:
            ret = wc_Sha384Update(&hmac->hash.sha384, (byte*)hmac->ipad,
                                                          WC_SHA384_BLOCK_SIZE);
            break;
    #endif /* WOLFSSL_SHA384 */

        default:
            break;
    }

    if (ret == 0)
        hmac->innerHashKeyed = WC_HMAC_INNER_HASH_KEYED_SW;

    return ret;
}


int wc_HmacUpdate(Hmac* hmac, const byte* msg, word32 length)
{
    int ret = 0;

    if (hmac == NULL || (msg == NULL && length > 0)) {
        return BAD_FUNC_ARG;
    }

    if (!hmac->innerHashKeyed) {
        ret = HmacKeyInnerHash(hmac);
        if (ret != 0)
            return ret;
    }

    switch (hmac->macType) {
    #ifndef NO_SHA256
        case WC_SHA256:
            ret = wc_Sha256Update(&hmac->hash.sha256, msg, length);
            break;
    #endif /* !NO_SHA256 */

    #ifdef WOLFSSL_SHA384
        case WC_SHA384:
            ret = wc_Sha384Update(&hmac->hash.sha384, msg, length);
            break;
    #endif /* WOLFSSL_SHA384 */

        default:
            break;
    }

    return ret;
}


int wc_HmacFinal(Hmac* hmac, byte* hash)
{
    int ret;

    if (hmac == NULL || hash == NULL) {
        return BAD_FUNC_ARG;
    }
    if (!hmac->innerHashKeyed) {
        ret = HmacKeyInnerHash(hmac);
        if (ret != 0)
            return ret;
    }

    switch (hmac->macType) {
    #ifndef NO_SHA256
        case WC_SHA256:
            ret = wc_Sha256Final(&hmac->hash.sha256, (byte*)hmac->innerHash);
            if (ret != 0)
                break;
            ret = wc_Sha256Update(&hmac->hash.sha256, (byte*)hmac->opad,
                                                          WC_SHA256_BLOCK_SIZE);
            if (ret != 0)
                break;
            ret = wc_Sha256Update(&hmac->hash.sha256, (byte*)hmac->innerHash,
                                                         WC_SHA256_DIGEST_SIZE);
            if (ret != 0)
                break;
            ret = wc_Sha256Final(&hmac->hash.sha256, hash);
            break;
    #endif /* !NO_SHA256 */

    #ifdef WOLFSSL_SHA384
        case WC_SHA384:
            ret = wc_Sha384Final(&hmac->hash.sha384, (byte*)hmac->innerHash);
            if (ret != 0)
                break;
            ret = wc_Sha384Update(&hmac->hash.sha384, (byte*)hmac->opad,
                                                          WC_SHA384_BLOCK_SIZE);
            if (ret != 0)
                break;
            ret = wc_Sha384Update(&hmac->hash.sha384, (byte*)hmac->innerHash,
                                                         WC_SHA384_DIGEST_SIZE);
            if (ret != 0)
                break;
            ret = wc_Sha384Final(&hmac->hash.sha384, hash);
            break;
    #endif /* WOLFSSL_SHA384 */

        default:
            ret = BAD_FUNC_ARG;
            break;
    }

    if (ret == 0) {
        hmac->innerHashKeyed = 0;
    }

    return ret;
}


/* Initialize Hmac for use with async device */
int wc_HmacInit(Hmac* hmac, void* heap, int devId)
{
    int ret = 0;

    if (hmac == NULL)
        return BAD_FUNC_ARG;

    XMEMSET(hmac, 0, sizeof(Hmac));
    hmac->macType = WC_HASH_TYPE_NONE;
    hmac->heap = heap;

    (void)devId;

    return ret;
}

/* Free Hmac from use with async device */
void wc_HmacFree(Hmac* hmac)
{
    if (hmac == NULL)
        return;

    switch (hmac->macType) {
    #ifndef NO_SHA256
        case WC_SHA256:
            wc_Sha256Free(&hmac->hash.sha256);
            break;
    #endif /* !NO_SHA256 */

    #ifdef WOLFSSL_SHA384
        case WC_SHA384:
            wc_Sha384Free(&hmac->hash.sha384);
            break;
    #endif /* WOLFSSL_SHA384 */

        default:
            break;
    }

}

int wolfSSL_GetHmacMaxSize(void)
{
    return WC_MAX_DIGEST_SIZE;
}

#endif /* NO_HMAC */
