#ifndef ECDH_PROTOCOL_H
#define ECDH_PROTOCOL_H

#include <stdint.h>
#include "ecdh.h"

// 错误码
#define ECDH_SUCCESS 0
#define ECDH_ERROR_INVALID_PARAM -1
#define ECDH_ERROR_RANDOM_FAILED -2
#define ECDH_ERROR_SERIALIZE_FAILED -3

// 公钥序列化后的长度 (65字节: 1字节压缩标志0x04 + 32字节x坐标 + 32字节y坐标)
#define PUBKEY_SERIALIZED_LEN 65
// 共享密钥长度 (32字节)
#define SHARED_SECRET_LEN 32

// 公钥格式定义
#define PUBKEY_FORMAT_UNCOMPRESSED 0x04
#define PUBKEY_FORMAT_COMPRESSED_EVEN 0x02
#define PUBKEY_FORMAT_COMPRESSED_ODD 0x03

// 序列化长度定义
#define PUBKEY_COMPRESSED_LEN 33    // 1字节标记 + 32字节x坐标
#define PUBKEY_UNCOMPRESSED_LEN 65  // 1字节标记 + 32字节x + 32字节y

// 初始化ECDH上下文
int ecdh_init_context(ECurve *curve);

// 生成密钥对，返回序列化的公钥
int ecdh_generate_keypair(ECurve *curve, 
                         uint8_t *public_key_out, size_t public_key_len,
                         uint8_t *private_key_out, size_t private_key_len);

// 从序列化数据还原公钥点
int ecdh_deserialize_pubkey(ECurve *curve, ECPoint *pubkey,
                           const uint8_t *data, size_t len);

// 序列化公钥点
int ecdh_serialize_pubkey(const ECPoint *pubkey,
                         uint8_t *out, size_t out_len);

// 压缩格式的序列化函数
int ecdh_serialize_pubkey_compressed(const ECPoint *pubkey,
                                   uint8_t *out, size_t out_len);

// 计算共享密钥
int ecdh_compute_secret(ECurve *curve,
                       const uint8_t *their_public, size_t their_public_len,
                       const uint8_t *my_private, size_t my_private_len,
                       uint8_t *secret_out, size_t secret_len);

// 清理ECDH
void ecdh_free_context(ECurve *curve);

#endif
