#ifndef ECDSA_H
#define ECDSA_H

#include "ecdh/ecdh.h"

typedef struct {
  uint8_t r[32];
  uint8_t s[32];
} ECDSASignature;

// 初始化ECDSA上下文（可以使用相同的曲线参数）
int ecdsa_init_context(ECurve *curve);

// 生成专用于签名的密钥对
int ecdsa_generate_keypair(ECurve *curve, uint8_t *public_key,
                           size_t public_key_len, uint8_t *private_key,
                           size_t private_key_len);

// 签名函数
int ecdsa_sign(ECurve *curve, const uint8_t *private_key,
               size_t private_key_len, const uint8_t *hash, size_t hash_len,
               ECDSASignature *signature);

// 验证函数
int ecdsa_verify(ECurve *curve, const uint8_t *public_key,
                 size_t public_key_len, const uint8_t *hash, size_t hash_len,
                 const ECDSASignature *signature);

#endif
