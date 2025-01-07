#include <stdio.h>
#include "ecdh.h"

int main() {
    // 初始化曲线参数 (这里使用secp256k1的参数作为示例)
    ECurve curve;
    ec_init_curve(&curve);
    
    // 设置曲线参数
    mpz_set_str(curve.p, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16);
    mpz_set_ui(curve.a, 0);
    mpz_set_ui(curve.b, 7);
    mpz_set_str(curve.n, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);
    
    // 设置基点G
    mpz_set_str(curve.G.x, "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16);
    mpz_set_str(curve.G.y, "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16);
    curve.G.infinity = 0;

    // Alice的密钥对
    mpz_t alice_private;
    ECPoint alice_public;
    mpz_init(alice_private);
    ec_init_point(&alice_public);
    generate_keypair(alice_private, &alice_public, &curve);

    // Bob的密钥对
    mpz_t bob_private;
    ECPoint bob_public;
    mpz_init(bob_private);
    ec_init_point(&bob_public);
    generate_keypair(bob_private, &bob_public, &curve);

    // 计算共享密钥
    mpz_t alice_shared, bob_shared;
    mpz_init(alice_shared);
    mpz_init(bob_shared);

    compute_shared_secret(alice_shared, &bob_public, alice_private, &curve);
    compute_shared_secret(bob_shared, &alice_public, bob_private, &curve);

    // 验证共享密钥是否相同
    if (mpz_cmp(alice_shared, bob_shared) == 0) {
        printf("ECDH key exchange successful!\n");
        gmp_printf("Shared secret: %Zx\n", alice_shared);
    } else {
        printf("ECDH key exchange failed!\n");
    }

    mpz_clear(alice_private);
    mpz_clear(bob_private);
    mpz_clear(alice_shared);
    mpz_clear(bob_shared);
    ec_clear_point(&alice_public);
    ec_clear_point(&bob_public);
    ec_clear_curve(&curve);

    return 0;
}
