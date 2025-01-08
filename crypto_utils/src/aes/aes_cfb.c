#include "aes/aes_cfb.h"
#include <string.h>

int aes_cfb_encrypt(const unsigned char *plaintext, size_t plaintext_len,
                    const unsigned char key[AES_KEY_SIZE],
                    const unsigned char iv[AES_BLOCK_SIZE],
                    unsigned char *ciphertext) {
  unsigned char feedback[AES_BLOCK_SIZE];
  unsigned char encryptedBlock[AES_BLOCK_SIZE];
  unsigned char encSubKeys[AES_EXPANDED_KEY_BLOCK][AES_BLOCK_SIZE];
  size_t i, j;
  size_t remaining;

  // 生成加密子密钥
  if (aes_make_enc_subkeys(key, encSubKeys) != 0) {
    return 1;
  }

  // 初始化反馈寄存器为IV
  memcpy(feedback, iv, AES_BLOCK_SIZE);

  // 分块处理数据
  for (i = 0; i < plaintext_len; i += AES_BLOCK_SIZE) {
    // 加密
    aes_encrypt_block(feedback, encSubKeys, encryptedBlock);

    // 计算当前块还剩下多少字节
    remaining = plaintext_len - i;
    if (remaining > AES_BLOCK_SIZE) {
      remaining = AES_BLOCK_SIZE;
    }

    // 与明文异或生成密文
    for (j = 0; j < remaining; j++) {
      ciphertext[i + j] = plaintext[i + j] ^ encryptedBlock[j];
    }

    // 更新反馈寄存器
    if (remaining == AES_BLOCK_SIZE) {
      memcpy(feedback, ciphertext + i, AES_BLOCK_SIZE);
    } else {
      // 最后一个不完整块的处理
      memcpy(feedback, ciphertext + i, remaining);
    }
  }

  return 0;
}

int aes_cfb_decrypt(const unsigned char *ciphertext, size_t ciphertext_len,
                    const unsigned char key[AES_KEY_SIZE],
                    const unsigned char iv[AES_BLOCK_SIZE],
                    unsigned char *plaintext) {
  unsigned char feedback[AES_BLOCK_SIZE];
  unsigned char encryptedBlock[AES_BLOCK_SIZE];
  unsigned char encSubKeys[AES_EXPANDED_KEY_BLOCK][AES_BLOCK_SIZE];
  size_t i, j;
  size_t remaining;

  // 生成加密子密钥（CFB解密也使用加密子密钥）
  if (aes_make_enc_subkeys(key, encSubKeys) != 0) {
    return 1;
  }

  // 初始化反馈寄存器为IV
  memcpy(feedback, iv, AES_BLOCK_SIZE);

  // 分块处理数据
  for (i = 0; i < ciphertext_len; i += AES_BLOCK_SIZE) {
    // 加密
    aes_encrypt_block(feedback, encSubKeys, encryptedBlock);

    // 计算当前块还有多少字节
    remaining = ciphertext_len - i;
    if (remaining > AES_BLOCK_SIZE) {
      remaining = AES_BLOCK_SIZE;
    }

    // 与密文异或生成明文
    for (j = 0; j < remaining; j++) {
      plaintext[i + j] = ciphertext[i + j] ^ encryptedBlock[j];
    }

    // 更新反馈寄存器
    if (remaining == AES_BLOCK_SIZE) {
      memcpy(feedback, ciphertext + i, AES_BLOCK_SIZE);
    } else {
      // 最后一个不完整块的处理
      memcpy(feedback, ciphertext + i, remaining);
    }
  }

  return 0;
}
