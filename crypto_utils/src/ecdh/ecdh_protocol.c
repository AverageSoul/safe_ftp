#include "ecdh_protocol.h"
#include <string.h>

int ecdh_init_context(ECurve *curve) {
    if (!curve) return ECDH_ERROR_INVALID_PARAM;
    
    ec_init_curve(curve);

    // 使用 secp256r1 参数
    mpz_set_str(curve->p, "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16);
    
    mpz_t temp;
    mpz_init(temp);
    mpz_set_si(temp, -3);
    mpz_mod(curve->a, temp, curve->p);
    mpz_clear(temp);
    
    mpz_set_str(curve->b, "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 16);
    mpz_set_str(curve->n, "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16);
    mpz_set_str(curve->G.x, "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296", 16);
    mpz_set_str(curve->G.y, "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5", 16);
    curve->G.infinity = 0;
    
    return ECDH_SUCCESS;
}

int ecdh_generate_keypair(ECurve *curve, 
                         uint8_t *public_key_out, size_t public_key_len,
                         uint8_t *private_key_out, size_t private_key_len) {
    if (!curve || !public_key_out || !private_key_out || 
        public_key_len < PUBKEY_SERIALIZED_LEN || 
        private_key_len < 32) {
        return ECDH_ERROR_INVALID_PARAM;
    }

    mpz_t private_key;
    ECPoint public_key;
    mpz_init(private_key);
    ec_init_point(&public_key);

    // 生成密钥对
    generate_keypair(private_key, &public_key, curve);

    // 序列化私钥
    size_t count;
    mpz_export(private_key_out, &count, 1, 1, 0, 0, private_key);
    
    // 序列化公钥
    public_key_out[0] = 0x04;
    mpz_export(public_key_out + 1, &count, 1, 1, 0, 0, public_key.x);
    mpz_export(public_key_out + 33, &count, 1, 1, 0, 0, public_key.y);

    mpz_clear(private_key);
    ec_clear_point(&public_key);
    return ECDH_SUCCESS;
}

int ecdh_deserialize_pubkey(ECurve *curve, ECPoint *pubkey,
                           const uint8_t *data, size_t len) {
    if (!curve || !pubkey || !data || len < PUBKEY_SERIALIZED_LEN) {
        return ECDH_ERROR_INVALID_PARAM;
    }

    if (data[0] != 0x04) {  // 检查未压缩格式标记
        return ECDH_ERROR_INVALID_PARAM;
    }

    mpz_import(pubkey->x, 32, 1, 1, 0, 0, data + 1);
    mpz_import(pubkey->y, 32, 1, 1, 0, 0, data + 33);
    pubkey->infinity = 0;

    return ECDH_SUCCESS;
}

int ecdh_serialize_pubkey(const ECPoint *pubkey,
                         uint8_t *out, size_t out_len) {
    if (!pubkey || !out || out_len < PUBKEY_SERIALIZED_LEN) {
        return ECDH_ERROR_INVALID_PARAM;
    }

    out[0] = 0x04;
    size_t count;
    mpz_export(out + 1, &count, 1, 1, 0, 0, pubkey->x);
    mpz_export(out + 33, &count, 1, 1, 0, 0, pubkey->y);

    return ECDH_SUCCESS;
}

int ecdh_serialize_pubkey_compressed(const ECPoint *pubkey,
                                   uint8_t *out, size_t out_len) {
    if (!pubkey || !out || out_len < PUBKEY_COMPRESSED_LEN) {
        return ECDH_ERROR_INVALID_PARAM;
    }

    // 判断y坐标的奇偶性
    mpz_t temp;
    mpz_init(temp);
    mpz_mod_ui(temp, pubkey->y, 2);
    
    // 设置压缩格式标记
    out[0] = mpz_cmp_ui(temp, 0) == 0 ? 
             PUBKEY_FORMAT_COMPRESSED_EVEN : 
             PUBKEY_FORMAT_COMPRESSED_ODD;
    
    mpz_clear(temp);

    // 导出x坐标
    size_t count;
    mpz_export(out + 1, &count, 1, 1, 0, 0, pubkey->x);

    return ECDH_SUCCESS;
}

// 从压缩格式反序列化
static int decompress_pubkey(ECurve *curve, ECPoint *pubkey,
                           const uint8_t *data, size_t len) {
    if (len < PUBKEY_COMPRESSED_LEN) return ECDH_ERROR_INVALID_PARAM;

    // 导入x坐标
    mpz_import(pubkey->x, 32, 1, 1, 0, 0, data + 1);

    // 计算 y² = x³ + ax + b
    mpz_t temp;
    mpz_init(temp);
    
    mpz_powm_ui(temp, pubkey->x, 3, curve->p);     // x³
    mpz_mul(pubkey->y, curve->a, pubkey->x);       // ax
    mpz_add(temp, temp, pubkey->y);                // x³ + ax
    mpz_add(temp, temp, curve->b);                 // x³ + ax + b
    
    // 计算平方根
    mpz_sqrt(pubkey->y, temp);
    
    // 根据标记调整y的符号
    if ((data[0] == PUBKEY_FORMAT_COMPRESSED_EVEN && mpz_tstbit(pubkey->y, 0)) ||
        (data[0] == PUBKEY_FORMAT_COMPRESSED_ODD && !mpz_tstbit(pubkey->y, 0))) {
        mpz_sub(pubkey->y, curve->p, pubkey->y);  // y = p - y
    }
    
    mpz_clear(temp);
    return ECDH_SUCCESS;
}

int ecdh_compute_secret(ECurve *curve,
                       const uint8_t *their_public, size_t their_public_len,
                       const uint8_t *my_private, size_t my_private_len,
                       uint8_t *secret_out, size_t secret_len) {
    if (!curve || !their_public || !my_private || !secret_out ||
        their_public_len < PUBKEY_SERIALIZED_LEN ||
        my_private_len < 32 || secret_len < SHARED_SECRET_LEN) {
        return ECDH_ERROR_INVALID_PARAM;
    }

    ECPoint their_pubkey;
    mpz_t my_privkey, shared;
    
    ec_init_point(&their_pubkey);
    mpz_init(my_privkey);
    mpz_init(shared);

    // 反序列化对方的公钥
    if (ecdh_deserialize_pubkey(curve, &their_pubkey, their_public, their_public_len) != ECDH_SUCCESS) {
        ec_clear_point(&their_pubkey);
        mpz_clear(my_privkey);
        mpz_clear(shared);
        return ECDH_ERROR_SERIALIZE_FAILED;
    }

    // 导入私钥
    mpz_import(my_privkey, my_private_len, 1, 1, 0, 0, my_private);

    // 计算共享密钥
    compute_shared_secret(shared, &their_pubkey, my_privkey, curve);

    // 导出共享密钥
    size_t count;
    mpz_export(secret_out, &count, 1, 1, 0, 0, shared);
    if (count < secret_len) {
        memset(secret_out + count, 0, secret_len - count);
    }

    ec_clear_point(&their_pubkey);
    mpz_clear(my_privkey);
    mpz_clear(shared);

    return ECDH_SUCCESS;
}


void ecdh_free_context(ECurve *curve) {
    if (curve) {
        ec_clear_curve(curve);
    }
}
