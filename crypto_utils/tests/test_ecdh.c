#include <stdio.h>
#include <assert.h>
#include <string.h>
#include "ecdh_protocol.h"
#include "sha256.h"

static void dump_hex(const char* label, const uint8_t* data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

void test_keypair_generation_and_formats() {
    printf("测试密钥生成和格式转换...\n");
    
    ECurve curve;
    uint8_t public_key[PUBKEY_SERIALIZED_LEN];
    uint8_t private_key[32];
    uint8_t compressed_key[PUBKEY_COMPRESSED_LEN];
    
    assert(ecdh_init_context(&curve) == ECDH_SUCCESS);
    
    // 生成密钥对
    assert(ecdh_generate_keypair(&curve, public_key, sizeof(public_key),
                                private_key, sizeof(private_key)) == ECDH_SUCCESS);
    
    // 验证公钥格式
    assert(public_key[0] == 0x04);
    
    // 测试公钥压缩
    ECPoint pubkey;
    ec_init_point(&pubkey);
    assert(ecdh_deserialize_pubkey(&curve, &pubkey, public_key, sizeof(public_key)) == ECDH_SUCCESS);
    assert(ecdh_serialize_pubkey_compressed(&pubkey, compressed_key, sizeof(compressed_key)) == ECDH_SUCCESS);
    
    // 验证压缩格式
    assert(compressed_key[0] == 0x02 || compressed_key[0] == 0x03);
    assert(sizeof(compressed_key) == 33);
    
    dump_hex("未压缩公钥", public_key, sizeof(public_key));
    dump_hex("压缩公钥", compressed_key, sizeof(compressed_key));
    dump_hex("私钥", private_key, sizeof(private_key));
    
    ec_clear_point(&pubkey);
    printf("密钥格式测试通过！\n");
    ecdh_free_context(&curve);
}

void test_key_exchange_with_hashing() {
    printf("\n测试带哈希处理的密钥交换...\n");
    
    ECurve curve;
    assert(ecdh_init_context(&curve) == ECDH_SUCCESS);
    
    // Alice的密钥对
    uint8_t alice_public[PUBKEY_SERIALIZED_LEN];
    uint8_t alice_private[32];
    uint8_t alice_public_compressed[PUBKEY_COMPRESSED_LEN];
    assert(ecdh_generate_keypair(&curve, alice_public, sizeof(alice_public),
                                alice_private, sizeof(alice_private)) == ECDH_SUCCESS);
    
    // Bob的密钥对
    uint8_t bob_public[PUBKEY_SERIALIZED_LEN];
    uint8_t bob_private[32];
    uint8_t bob_public_compressed[PUBKEY_COMPRESSED_LEN];
    assert(ecdh_generate_keypair(&curve, bob_public, sizeof(bob_public),
                                bob_private, sizeof(bob_private)) == ECDH_SUCCESS);
    
    // 转换为压缩格式
    ECPoint pubkey;
    ec_init_point(&pubkey);
    assert(ecdh_deserialize_pubkey(&curve, &pubkey, alice_public, sizeof(alice_public)) == ECDH_SUCCESS);
    assert(ecdh_serialize_pubkey_compressed(&pubkey, alice_public_compressed, sizeof(alice_public_compressed)) == ECDH_SUCCESS);
    
    assert(ecdh_deserialize_pubkey(&curve, &pubkey, bob_public, sizeof(bob_public)) == ECDH_SUCCESS);
    assert(ecdh_serialize_pubkey_compressed(&pubkey, bob_public_compressed, sizeof(bob_public_compressed)) == ECDH_SUCCESS);
    
    // 计算共享密钥
    uint8_t alice_secret[SHARED_SECRET_LEN];
    uint8_t bob_secret[SHARED_SECRET_LEN];
    
    assert(ecdh_compute_secret(&curve, 
                              bob_public, sizeof(bob_public),
                              alice_private, sizeof(alice_private),
                              alice_secret, sizeof(alice_secret)) == ECDH_SUCCESS);
    
    assert(ecdh_compute_secret(&curve, 
                              alice_public, sizeof(alice_public),
                              bob_private, sizeof(bob_private),
                              bob_secret, sizeof(bob_secret)) == ECDH_SUCCESS);
    
    // 对共享密钥进行哈希处理
    uint8_t alice_hashed_secret[SHA256_DIGEST_SIZE];
    uint8_t bob_hashed_secret[SHA256_DIGEST_SIZE];
    
    sha256_hash(alice_secret, sizeof(alice_secret), alice_hashed_secret);
    sha256_hash(bob_secret, sizeof(bob_secret), bob_hashed_secret);
    
    // 验证共享密钥相同
    assert(memcmp(alice_secret, bob_secret, SHARED_SECRET_LEN) == 0);
    assert(memcmp(alice_hashed_secret, bob_hashed_secret, SHA256_DIGEST_SIZE) == 0);
    
    dump_hex("Alice的原始共享密钥", alice_secret, sizeof(alice_secret));
    dump_hex("Alice的哈希共享密钥", alice_hashed_secret, sizeof(alice_hashed_secret));
    dump_hex("Bob的原始共享密钥", bob_secret, sizeof(bob_secret));
    dump_hex("Bob的哈希共享密钥", bob_hashed_secret, sizeof(bob_hashed_secret));
    
    ec_clear_point(&pubkey);
    printf("带哈希处理的密钥交换测试通过！\n");
    ecdh_free_context(&curve);
}

void test_error_handling() {
    printf("\n测试错误处理...\n");
    
    ECurve curve;
    uint8_t public_key[PUBKEY_SERIALIZED_LEN];
    uint8_t private_key[32];
    uint8_t shared_secret[SHARED_SECRET_LEN];
    
    // 测试空参数
    assert(ecdh_init_context(NULL) == ECDH_ERROR_INVALID_PARAM);
    
    // 测试缓冲区大小检查
    assert(ecdh_generate_keypair(&curve, public_key, 10,  // 公钥缓冲区太小
                                private_key, sizeof(private_key)) == ECDH_ERROR_INVALID_PARAM);
    
    // 测试无效的公钥格式
    public_key[0] = 0x00;  // 无效的格式标识符
    assert(ecdh_compute_secret(&curve, public_key, sizeof(public_key),
                              private_key, sizeof(private_key),
                              shared_secret, sizeof(shared_secret)) == ECDH_ERROR_SERIALIZE_FAILED);
    
    printf("错误处理测试通过！\n");
}

void test_file_hashing() {
    printf("\n测试文件哈希...\n");
    
    const char *test_file = "tests/test_data/test.txt"; 
    uint8_t file_hash[SHA256_DIGEST_SIZE];
    
    // 对测试文件进行哈希
    if (sha256_file(test_file, file_hash) != 0) {
        printf("Error: Cannot open test file: %s\n", test_file);
        assert(0);
    }
    
    // 打印文件哈希值
    printf("文件 '%s' 的SHA256哈希值:\n", test_file);
    dump_hex("", file_hash, SHA256_DIGEST_SIZE);
    
    // 读取文件内容并进行内存哈希，验证结果是否相同
    FILE *fp = fopen(test_file, "rb");
    assert(fp != NULL);
    
    // 获取文件大小
    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    // 读取文件内容
    uint8_t *buffer = malloc(file_size);
    assert(buffer != NULL);
    assert(fread(buffer, 1, file_size, fp) == file_size);
    fclose(fp);
    
    // 计算内存中内容的哈希值
    uint8_t mem_hash[SHA256_DIGEST_SIZE];
    sha256_hash(buffer, file_size, mem_hash);
    
    // 验证两种方式得到的哈希值相同
    assert(memcmp(file_hash, mem_hash, SHA256_DIGEST_SIZE) == 0);
    printf("文件哈希测试通过！\n");
    
    free(buffer);
}

int main() {
    printf("开始ECDH协议测试...\n\n");
    
    test_keypair_generation_and_formats();
    test_key_exchange_with_hashing();
    test_error_handling();
    test_file_hashing();    // 添加文件哈希测试
    
    printf("\n所有测试通过！\n");
    return 0;
}
