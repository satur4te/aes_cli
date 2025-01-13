#include <stdlib.h>
#ifndef _AES_H_
#define _AES_H_

#define AES_ROUND_KEY_LEN 16

#define AES_128_KEY_LEN 16
#define AES_128_ROUNDS 10
#define AES_192_KEY_LEN 24
#define AES_192_ROUNDS 12
#define AES_256_KEY_LEN 32
#define AES_256_ROUNDS 14

#define AES_KEY_LEN(type) \
    ((type == AES_128) ? \
     AES_128_KEY_LEN : \
    ((type == AES_192) ? \
     AES_192_KEY_LEN : \
     AES_256_KEY_LEN))

#define AES_ROUNDS(type) \
    ((type == AES_128) ? \
     AES_128_ROUNDS : \
    ((type == AES_192) ? \
     AES_192_ROUNDS : \
     AES_256_ROUNDS))

#define AES_KEY_BUFFER_LEN(type) \
    ((1 + AES_ROUNDS(type)) * 16)

typedef unsigned char byte;

typedef enum {
    AES_128,
    AES_192,
    AES_256
} AES_TYPE;

typedef struct {
    AES_TYPE type;
    byte *key;
} aes_ctx;

void aes_init_ctx(aes_ctx *ctx, AES_TYPE type, byte *key);
void aes_free_ctx(aes_ctx *ctx);
// void aes_encrypt(aes_ctx *ctx);
void aes_encrypt(aes_ctx *ctx, byte *buffer, size_t size);
void aes_decrypt(aes_ctx *ctx, byte *buffer, size_t size);

#endif // _AES_H_
