#include <stdio.h>
#include <string.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/aes.h>
#include "test_vectors/gcm_vectors.h"
#include "test_vectors/gcm_vectors.c"

#ifdef HAVE_CUSTOMBOARD_GPC3
#include <zTestPort.h>
#include <ztimer.h>
#include <zapitype.h>
#endif

#define MAX_CT_LEN 128

int main(void)
{

    int ret;
    int tp_passed = 1;
    int comp_ret;

    static int executed_count = 0;
    static int passed_count = 0;
    static int dec_executed_count = 0;
    static int dec_passed_count = 0;

    static Aes aes __attribute__((aligned(4)));
    static byte ciphertext[MAX_CT_LEN] __attribute__((aligned(4)));
    static byte plaintext[MAX_CT_LEN] __attribute__((aligned(4)));
    static byte obs_tag[MAX_CT_LEN] __attribute__((aligned(4)));

#ifdef HAVE_CUSTOMBOARD_GPC3
    BSPTimestamp aulStart;
    BSPMicrosecondCount auiElapsed;

    BSPTestPortInitialize();
    aulStart = BSPTimestampGetCurrentTime( );

    auiElapsed = BSPTimestampGetElapsedMicroseconds( aulStart );

    (void)auiElapsed;
    printf("Entering aesgcm-test.c \n");
#endif
    for (int i = gcm_vectors_count-1; i > gcm_vectors_count - 52; i--)
    {

        printf("\r\n ---- Vector %d ---- \r\n", i);

        const gcm_tv_t *tv = &gcm_vectors[i];

        printf("key addr %p", &tv->key);
        printf("aes addr %p", &aes);

        ret = wc_AesGcmSetKey(&aes, tv->key, tv->key_len);
        if (ret != 0)
        {
            printf("AES GCM key not set correctly, error code: %d\r\n", ret);
        }
        else
        {
            printf("\r\nAES GCM key set did not return any error.\r\n");
        }

        /* Encryption Part */

        executed_count++;

        ret = wc_AesGcmEncrypt(&aes, ciphertext, tv->pt, tv->pt_len,
                               tv->iv, tv->iv_len, obs_tag, tv->tag_len, tv->aad, tv->aad_len);

        if (ret != 0)
        {
            printf("AES GCM encryption failed, return error: %d\r\n", ret);
        }

        printf("\r\nObtained ciphertext\r\n");
        for (int j = 0; j < tv->pt_len; j++)
        {
            printf("%x", ciphertext[j]);
        }
        printf("\r\nExpected ciphertext\r\n");
        for (int j = 0; j < tv->pt_len; j++)
        {
            printf("%x", tv->ct[j]);
        }

        /* Decryption part */

        dec_executed_count++;
        ret = wc_AesGcmDecrypt(&aes, plaintext, tv->ct, tv->ct_len,
                               tv->iv, tv->iv_len, tv->tag, tv->tag_len, tv->aad, tv->aad_len);

        printf("\r\nObtained plaintext\r\n");
        for (int j = 0; j < tv->pt_len; j++)
        {
            printf("%x", plaintext[j]);
        }
        printf("\r\nExpected plaintext\r\n");
        for (int j = 0; j < tv->pt_len; j++)
        {
            printf("%x", tv->pt[j]);
        }
    }
}
