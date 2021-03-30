/* cmac.c
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

#include <wolfssl/wolfcrypt/settings.h>

#if defined(WOLFSSL_CMAC) && !defined(NO_AES) && defined(WOLFSSL_AES_DIRECT)

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/cmac.h>


static void ShiftAndXorRb(byte* out, byte* in)
{
    int i, j, xorRb;
    int mask = 0, last = 0;
    byte Rb = 0x87;

    xorRb = (in[0] & 0x80) != 0;

    for (i = 1, j = AES_BLOCK_SIZE - 1; i <= AES_BLOCK_SIZE; i++, j--) {
        last = (in[j] & 0x80) ? 1 : 0;
        out[j] = (byte)((in[j] << 1) | mask);
        mask = last;
        if (xorRb) {
            out[j] ^= Rb;
            Rb = 0;
        }
    }
}

/*!
    \ingroup CMAC

    \brief This function initializes CMAC.

    \return 0 Returned upon successfully initializing
    \return BAD_FUNC_ARG error returned if cmac or key is null or
                         key size is 0 or type is not set

    \param cmac pointer to the CMAC structure to use for hash calculation
    \param key 16, 24, or 32 byte secret key for authentication
    \param keySz length of the key
    \param type of CMAC method
*/

int wc_InitCmac(Cmac* cmac, const byte* key, word32 keySz,
                int type, void* unused)
{
    int ret;

    (void)unused;

    if (cmac == NULL || key == NULL || keySz == 0 || type != WC_CMAC_AES)
        return BAD_FUNC_ARG;

    XMEMSET(cmac, 0, sizeof(Cmac));
    ret = wc_AesSetKey(&cmac->aes, key, keySz, NULL, AES_ENCRYPTION);
    if (ret == 0) {
        byte l[AES_BLOCK_SIZE];

        XMEMSET(l, 0, AES_BLOCK_SIZE);
        wc_AesEncryptDirect(&cmac->aes, l, l);
        ShiftAndXorRb(cmac->k1, l);
        ShiftAndXorRb(cmac->k2, cmac->k1);
        ForceZero(l, AES_BLOCK_SIZE);
    }
    return ret;
}

/*!
    \ingroup CMAC

    \brief This function updates the message to authenticate using CMAC.
    It should be called after the Cmac object has been initialized with
    wc_InitCmac. You may call this function multiple times to update
    the message to hash. After calling wc_CmacUpdate as desired, you must
    call wc_CmacFinal to obtain the final authenticated message tag.

    \return 0 Returned on successfully updating the message to authenticate
    \return BAD_FUNC_ARG error if cmac or in is null

    \param cmac pointer to the Cmac object for which to update the message
    \param in pointer to the buffer containing the message to append
    \param inSz length of the message to append
*/

int wc_CmacUpdate(Cmac* cmac, const byte* in, word32 inSz)
{
    if ((cmac == NULL) || (in == NULL && inSz != 0))
        return BAD_FUNC_ARG;

    while (inSz != 0) {
        word32 add = min(inSz, AES_BLOCK_SIZE - cmac->bufferSz);
        XMEMCPY(&cmac->buffer[cmac->bufferSz], in, add);

        cmac->bufferSz += add;
        in += add;
        inSz -= add;

        if (cmac->bufferSz == AES_BLOCK_SIZE && inSz != 0) {
            if (cmac->totalSz != 0)
                xorbuf(cmac->buffer, cmac->digest, AES_BLOCK_SIZE);
            wc_AesEncryptDirect(&cmac->aes,
                                cmac->digest,
                                cmac->buffer);
            cmac->totalSz += AES_BLOCK_SIZE;
            cmac->bufferSz = 0;
        }
    }

    return 0;
}

/*!
    \ingroup CMAC

    \brief This function computes the final hash of an Cmac object's message.

    \return 0 Returned on successfully computing the final hash
    \return BAD_FUNC_ARG error returned if cmac or out or outSz is null
    \return BUFFER_E error if outSz is outside the min and max tag window

    \param cmac pointer to the Hmac object for which to calculate the
    final hash
    \param hash pointer to the buffer in which to store the final hash
    Should have room available as required by the hashing algorithm chosen
    \param outSz pointer length of the tag
*/

int wc_CmacFinal(Cmac* cmac, byte* out, word32* outSz)
{
    const byte* subKey;

    if (cmac == NULL || out == NULL || outSz == NULL)
        return BAD_FUNC_ARG;

    if (*outSz < WC_CMAC_TAG_MIN_SZ || *outSz > WC_CMAC_TAG_MAX_SZ)
        return BUFFER_E;

    if (cmac->bufferSz == AES_BLOCK_SIZE) {
        subKey = cmac->k1;
    }
    else {
        word32 remainder = AES_BLOCK_SIZE - cmac->bufferSz;

        if (remainder == 0)
            remainder = AES_BLOCK_SIZE;

        if (remainder > 1)
            XMEMSET(cmac->buffer + AES_BLOCK_SIZE - remainder, 0, remainder);
        cmac->buffer[AES_BLOCK_SIZE - remainder] = 0x80;
        subKey = cmac->k2;
    }
    xorbuf(cmac->buffer, cmac->digest, AES_BLOCK_SIZE);
    xorbuf(cmac->buffer, subKey, AES_BLOCK_SIZE);
    wc_AesEncryptDirect(&cmac->aes, cmac->digest, cmac->buffer);

    XMEMCPY(out, cmac->digest, *outSz);

    ForceZero(cmac, sizeof(Cmac));

    return 0;
}

/*!
    \ingroup CMAC

    \brief This function computes the final hash of an Cmac object's message.

    \return 0 Returned on successfully computing the final hash
    \return BAD_FUNC_ARG error returned if cmac or out or key is null

    \param out hash pointer to the buffer in which to store the final hash
    \param outSz pointer length of the tag
    \param in pointer to the buffer containing the message to append
    \param inSz length of the message to append
    \param key 16, 24, or 32 byte secret key for authentication
    \param keySz length of the key
*/

int wc_AesCmacGenerate(byte* out, word32* outSz,
                       const byte* in, word32 inSz,
                       const byte* key, word32 keySz)
{
    Cmac cmac[1];
    int ret;

    if (out == NULL || (in == NULL && inSz > 0) || key == NULL || keySz == 0)
        return BAD_FUNC_ARG;

    ret = wc_InitCmac(cmac, key, keySz, WC_CMAC_AES, NULL);
    if (ret != 0)
        goto out;

    ret = wc_CmacUpdate(cmac, in, inSz);
    if (ret != 0)
        goto out;

    ret = wc_CmacFinal(cmac, out, outSz);
    if (ret != 0)
        goto out;

  out:

    return ret;
}

/*!
    \ingroup CMAC

    \brief This function verifies the final tag of a Cmac object's message

    \return 0 Returned on successfully computing the final hash
    \return BAD_FUNC_ARG error returned if cmac or out or key is null

    \param check pointer to the buffer containing a tag to be verified
    \param checkSz length of the tag
    \param in pointer to the buffer containing the message to process
    \param inSz length of the message to process
    \param key 16, 24, or 32 byte secret key for authentication
    \param keySz length of the key

*/

int wc_AesCmacVerify(const byte* check, word32 checkSz,
                     const byte* in, word32 inSz,
                     const byte* key, word32 keySz)
{
    byte a[AES_BLOCK_SIZE];
    word32 aSz = sizeof(a);
    int result;
    int compareRet;

    if (check == NULL || checkSz == 0 || (in == NULL && inSz != 0) ||
        key == NULL || keySz == 0)

        return BAD_FUNC_ARG;

    XMEMSET(a, 0, aSz);
    result = wc_AesCmacGenerate(a, &aSz, in, inSz, key, keySz);
    compareRet = ConstantCompare(check, a, min(checkSz, aSz));

    if (result == 0)
        result = compareRet ? 1 : 0;

    return result;
}


#endif /* WOLFSSL_CMAC && NO_AES && WOLFSSL_AES_DIRECT */
