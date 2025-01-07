#include "ecdsa.h"
#include "ecdh.h"
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

// 生成随机数k (1 < k < n-1)
static int generate_k(mpz_t k, const mpz_t n) {
    unsigned char buf[32];
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd == -1) return -1;
    
    if (read(fd, buf, sizeof(buf)) != sizeof(buf)) {
        close(fd);
        return -1;
    }
    close(fd);
    
    mpz_import(k, sizeof(buf), 1, 1, 0, 0, buf);
    mpz_mod(k, k, n);
    
    // 确保k在正确范围内
    if (mpz_cmp_ui(k, 1) <= 0) {
        mpz_add_ui(k, k, 2);
    }
    
    return 0;
}

int ecdsa_init_context(ECurve *curve) {
    return ecdh_init_context(curve);
}

int ecdsa_generate_keypair(ECurve *curve, uint8_t *public_key, size_t public_key_len,
                          uint8_t *private_key, size_t private_key_len) {
    return ecdh_generate_keypair(curve, public_key, public_key_len,
                               private_key, private_key_len);
}

int ecdsa_sign(ECurve *curve, const uint8_t *private_key, size_t private_key_len,
               const uint8_t *hash, size_t hash_len,
               ECDSASignature *signature) {
    if (!curve || !private_key || !hash || !signature ||
        private_key_len < 32 || hash_len < 32) {
        return -1;
    }

    mpz_t d, k, r, s, e, kinv;
    ECPoint kG;
    int result = -1;  // 使用result替代ret
    
    mpz_init(d);
    mpz_init(k);
    mpz_init(r);
    mpz_init(s);
    mpz_init(e);
    mpz_init(kinv);
    ec_init_point(&kG);
    
    // 导入私钥和消息哈希
    mpz_import(d, private_key_len, 1, 1, 0, 0, private_key);
    mpz_import(e, hash_len, 1, 1, 0, 0, hash);
    
    int retry = 0;
    int max_retries = 10;
    
    do {
        // 生成随机数k
        if (generate_k(k, curve->n) < 0) {
            result = -1;
            goto cleanup;
        }
        
        // 计算 kG
        ec_point_mul(&kG, &curve->G, k, curve);
        
        // r = kG.x mod n
        mpz_mod(r, kG.x, curve->n);
        if (mpz_cmp_ui(r, 0) == 0) {
            retry++;
            continue;
        }
        
        // k^(-1)
        if (!mpz_invert(kinv, k, curve->n)) {
            retry++;
            continue;
        }
        
        // s = k^(-1)(e + dr) mod n
        mpz_mul(s, d, r);
        mpz_add(s, s, e);
        mpz_mul(s, kinv, s);
        mpz_mod(s, s, curve->n);
        
        if (mpz_cmp_ui(s, 0) == 0) {
            retry++;
            continue;
        }
        
        // 导出签名
        size_t count;
        mpz_export(signature->r, &count, 1, 1, 0, 0, r);
        mpz_export(signature->s, &count, 1, 1, 0, 0, s);
        
        result = 0;  // 成功
        break;
        
    } while (retry < max_retries);

cleanup:
    mpz_clear(d);
    mpz_clear(k);
    mpz_clear(r);
    mpz_clear(s);
    mpz_clear(e);
    mpz_clear(kinv);
    ec_clear_point(&kG);
    
    return result;
}

static void ec_point_add(ECPoint *result, const ECPoint *p1, const ECPoint *p2, const ECurve *curve) {
    if (p1->infinity) {
        mpz_set(result->x, p2->x);
        mpz_set(result->y, p2->y);
        result->infinity = p2->infinity;
        return;
    }
    if (p2->infinity) {
        mpz_set(result->x, p1->x);
        mpz_set(result->y, p1->y);
        result->infinity = p1->infinity;
        return;
    }

    mpz_t lambda, temp1, temp2;
    mpz_init(lambda);
    mpz_init(temp1);
    mpz_init(temp2);

    // 如果是同一点
    if (mpz_cmp(p1->x, p2->x) == 0 && mpz_cmp(p1->y, p2->y) == 0) {
        // 计算 λ = (3x₁² + a)/(2y₁)
        mpz_mul(temp1, p1->x, p1->x);
        mpz_mod(temp1, temp1, curve->p);
        mpz_mul_ui(temp1, temp1, 3);
        mpz_add(temp1, temp1, curve->a);
        mpz_mod(temp1, temp1, curve->p);

        mpz_mul_ui(temp2, p1->y, 2);
        mpz_invert(temp2, temp2, curve->p);

        mpz_mul(lambda, temp1, temp2);
        mpz_mod(lambda, lambda, curve->p);
    } else {
        // 计算 λ = (y₂-y₁)/(x₂-x₁)
        mpz_sub(temp1, p2->y, p1->y);
        mpz_sub(temp2, p2->x, p1->x);
        mpz_invert(temp2, temp2, curve->p);
        mpz_mul(lambda, temp1, temp2);
        mpz_mod(lambda, lambda, curve->p);
    }

    // x₃ = λ² - x₁ - x₂
    mpz_mul(result->x, lambda, lambda);
    mpz_sub(result->x, result->x, p1->x);
    mpz_sub(result->x, result->x, p2->x);
    mpz_mod(result->x, result->x, curve->p);

    // y₃ = λ(x₁ - x₃) - y₁
    mpz_sub(temp1, p1->x, result->x);
    mpz_mul(result->y, lambda, temp1);
    mpz_sub(result->y, result->y, p1->y);
    mpz_mod(result->y, result->y, curve->p);

    result->infinity = 0;

    mpz_clear(lambda);
    mpz_clear(temp1);
    mpz_clear(temp2);
}

int ecdsa_verify(ECurve *curve, const uint8_t *public_key, size_t public_key_len,
                 const uint8_t *hash, size_t hash_len,
                 const ECDSASignature *signature) {
    if (!curve || !public_key || !hash || !signature ||
        public_key_len < 65 || hash_len < 32) {
        return -1;
    }

    ECPoint Q;
    mpz_t r, s, e, w, u1, u2;
    int ret = -1;
    
    ec_init_point(&Q);
    mpz_init(r);
    mpz_init(s);
    mpz_init(e);
    mpz_init(w);
    mpz_init(u1);
    mpz_init(u2);
    
    // 导入公钥
    if (ecdh_deserialize_pubkey(curve, &Q, public_key, public_key_len) != 0) {
        goto cleanup;
    }
    
    // 导入签名值r,s
    mpz_import(r, 32, 1, 1, 0, 0, signature->r);
    mpz_import(s, 32, 1, 1, 0, 0, signature->s);
    
    // 检查r,s是否在[1,n-1]范围内
    if (mpz_cmp_ui(r, 1) < 0 || mpz_cmp(r, curve->n) >= 0 ||
        mpz_cmp_ui(s, 1) < 0 || mpz_cmp(s, curve->n) >= 0) {
        goto cleanup;
    }
    
    // 导入消息哈希
    mpz_import(e, hash_len, 1, 1, 0, 0, hash);
    
    // w = s^(-1) mod n
    if (!mpz_invert(w, s, curve->n)) {
        goto cleanup;
    }
    
    // u1 = ew mod n
    mpz_mul(u1, e, w);
    mpz_mod(u1, u1, curve->n);
    
    // u2 = rw mod n
    mpz_mul(u2, r, w);
    mpz_mod(u2, u2, curve->n);
    
    // 计算 u1G + u2Q
    ECPoint R1, R2, R;
    ec_init_point(&R1);
    ec_init_point(&R2);
    ec_init_point(&R);
    
    ec_point_mul(&R1, &curve->G, u1, curve);
    ec_point_mul(&R2, &Q, u2, curve);
    ec_point_add(&R, &R1, &R2, curve);
    
    if (R.infinity) {
        goto cleanup_points;
    }
    
    // 验证 R.x mod n == r
    mpz_mod(R.x, R.x, curve->n);
    ret = (mpz_cmp(R.x, r) == 0) ? 0 : -1;
    
cleanup_points:
    ec_clear_point(&R);
    ec_clear_point(&R1);
    ec_clear_point(&R2);
    
cleanup:
    ec_clear_point(&Q);
    mpz_clear(r);
    mpz_clear(s);
    mpz_clear(e);
    mpz_clear(w);
    mpz_clear(u1);
    mpz_clear(u2);
    
    return ret;
}
