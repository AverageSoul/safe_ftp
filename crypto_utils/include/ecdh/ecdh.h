#ifndef ECDH_H
#define ECDH_H

#include <gmp.h>
#include <stdint.h>

// 椭圆曲线上点的结构定义
typedef struct {
  mpz_t x;
  mpz_t y;
  int infinity;
} ECPoint;

// 椭圆曲线参数的结构定义
typedef struct {
  mpz_t p;   // 模数
  mpz_t a;   // 曲线参数a
  mpz_t b;   // 曲线参数b
  ECPoint G; // 基点
  mpz_t n;   // 阶
} ECurve;

void ec_init_point(ECPoint *point);
void ec_clear_point(ECPoint *point);
void ec_init_curve(ECurve *curve);
void ec_clear_curve(ECurve *curve);
void ec_point_mul(ECPoint *result, const ECPoint *p, const mpz_t k,
                  const ECurve *curve);
void generate_keypair(mpz_t private_key, ECPoint *public_key,
                      const ECurve *curve);
void compute_shared_secret(mpz_t shared_secret, const ECPoint *others_public,
                           const mpz_t my_private, const ECurve *curve);

#endif
