#include <stdio.h>
#include <assert.h>
#include <string.h>
#include "ecdh_protocol.h"
#include "ecdsa.h"
#include "sha256.h"

static void dump_hex(const char* label, const uint8_t* data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

void test_file_signature() {
    printf("\n测试文件签名和验证...\n");
    
    // 初始化曲线
    ECurve curve;
    assert(ecdh_init_context(&curve) == 0);
    
    // 生成签名密钥对
    uint8_t sign_public[PUBKEY_SERIALIZED_LEN];
    uint8_t sign_private[32];
    assert(ecdsa_generate_keypair(&curve, sign_public, sizeof(sign_public),
                                 sign_private, sizeof(sign_private)) == 0);
    
    printf("生成的签名密钥对：\n");
    dump_hex("公钥", sign_public, sizeof(sign_public));
    dump_hex("私钥", sign_private, sizeof(sign_private));
    
    // 修改文件路径
    const char *filename = "tests/test_data/test.txt";
    uint8_t file_hash[SHA256_DIGEST_SIZE];
    
    // 验证文件是否存在
    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        printf("Error: Cannot open test file: %s\n", filename);
        assert(0);
    }
    fclose(fp);
    
    // 计算文件哈希
    assert(sha256_file(filename, file_hash) == 0);
    printf("\n文件哈希值：\n");
    dump_hex("SHA256", file_hash, SHA256_DIGEST_SIZE);
    
    // 对文件哈希进行签名
    ECDSASignature signature;
    assert(ecdsa_sign(&curve, sign_private, sizeof(sign_private),
                      file_hash, sizeof(file_hash),
                      &signature) == 0);
    
    printf("\n生成的签名：\n");
    dump_hex("R", signature.r, sizeof(signature.r));
    dump_hex("S", signature.s, sizeof(signature.s));
    
    // 验证签名
    assert(ecdsa_verify(&curve, sign_public, sizeof(sign_public),
                        file_hash, sizeof(file_hash),
                        &signature) == 0);
    
    // 测试签名验证失败的情况
    printf("\n测试签名验证失败情况...\n");
    
    // 1. 如果修改文件哈希
    file_hash[0] ^= 1;
    assert(ecdsa_verify(&curve, sign_public, sizeof(sign_public),
                        file_hash, sizeof(file_hash),
                        &signature) != 0);
    printf("修改哈希后验证失败 - 测试通过\n");
    
    // 2. 如果修改签名
    file_hash[0] ^= 1;  // 恢复原始哈希
    signature.r[0] ^= 1;
    assert(ecdsa_verify(&curve, sign_public, sizeof(sign_public),
                        file_hash, sizeof(file_hash),
                        &signature) != 0);
    printf("修改签名后验证失败 - 测试通过\n");
    
    printf("\n签名测试全部通过！\n");
    ecdh_free_context(&curve);
}

void test_ecdsa_with_ecdh() {
    printf("\n测试ECDSA和ECDH组合使用...\n");
    
    ECurve curve;
    assert(ecdh_init_context(&curve) == 0);
    
    // Alice生成用于密钥协商的ECDH密钥对
    uint8_t alice_ecdh_public[PUBKEY_SERIALIZED_LEN];
    uint8_t alice_ecdh_private[32];
    assert(ecdh_generate_keypair(&curve, alice_ecdh_public, sizeof(alice_ecdh_public),
                                alice_ecdh_private, sizeof(alice_ecdh_private)) == 0);
    
    // Alice生成用于签名的ECDSA密钥对
    uint8_t alice_sign_public[PUBKEY_SERIALIZED_LEN];
    uint8_t alice_sign_private[32];
    assert(ecdsa_generate_keypair(&curve, alice_sign_public, sizeof(alice_sign_public),
                                 alice_sign_private, sizeof(alice_sign_private)) == 0);
    
    // Bob生成ECDH密钥对
    uint8_t bob_ecdh_public[PUBKEY_SERIALIZED_LEN];
    uint8_t bob_ecdh_private[32];
    assert(ecdh_generate_keypair(&curve, bob_ecdh_public, sizeof(bob_ecdh_public),
                                bob_ecdh_private, sizeof(bob_ecdh_private)) == 0);
    
    // 计算共享密钥
    uint8_t alice_secret[SHARED_SECRET_LEN];
    uint8_t bob_secret[SHARED_SECRET_LEN];
    
    assert(ecdh_compute_secret(&curve, bob_ecdh_public, sizeof(bob_ecdh_public),
                              alice_ecdh_private, sizeof(alice_ecdh_private),
                              alice_secret, sizeof(alice_secret)) == 0);
    
    assert(ecdh_compute_secret(&curve, alice_ecdh_public, sizeof(alice_ecdh_public),
                              bob_ecdh_private, sizeof(bob_ecdh_private),
                              bob_secret, sizeof(bob_secret)) == 0);
    
    // 对共享密钥进行签名
    ECDSASignature signature;
    assert(ecdsa_sign(&curve, alice_sign_private, sizeof(alice_sign_private),
                      alice_secret, sizeof(alice_secret),
                      &signature) == 0);
    
    // Bob验证签名和共享密钥
    assert(ecdsa_verify(&curve, alice_sign_public, sizeof(alice_sign_public),
                        bob_secret, sizeof(bob_secret),
                        &signature) == 0);
    
    printf("ECDSA和ECDH组合测试通过！\n");
    ecdh_free_context(&curve);
}

int main() {
    printf("开始ECDSA测试...\n\n");
    
    test_file_signature();
    test_ecdsa_with_ecdh();
    
    printf("\n所有测试通过！\n");
    return 0;
}