/* Auto-generated from .rsp by rsp_to_c_gcm.py */
#ifndef GCM_VECTORS_H_
#define GCM_VECTORS_H_

#include <stddef.h>
#include <stdint.h>

typedef unsigned char byte;

typedef struct {
    int count;
    const byte *key;
    size_t key_len;
    const byte *iv;
    size_t iv_len;
    const byte *pt;
    size_t pt_len;
    const byte *aad;
    size_t aad_len;
    const byte *ct;
    size_t ct_len;
    const byte *tag;
    size_t tag_len;
} gcm_tv_t __attribute__((aligned(4)));

extern const gcm_tv_t gcm_vectors[];
extern const size_t gcm_vectors_count;

#endif /* GCM_VECTORS_H_ */
