#ifndef AES_CFB_H
#define AES_CFB_H

#include "aes.h"
#include <unistd.h>

#ifdef __cplusplus
extern "C" {
#endif

int aes_cfb_encrypt(const unsigned char *plaintext, size_t plaintext_len,
                    const unsigned char key[AES_KEY_SIZE],
                    const unsigned char iv[AES_BLOCK_SIZE],
                    unsigned char *ciphertext);

int aes_cfb_decrypt(const unsigned char *ciphertext, size_t ciphertext_len,
                    const unsigned char key[AES_KEY_SIZE],
                    const unsigned char iv[AES_BLOCK_SIZE],
                    unsigned char *plaintext);

#ifdef __cplusplus
}
#endif

#endif
