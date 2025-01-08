#include "aes.h"
#include "benchmark.h"

#define BENCHS 10
#define ROUNDS 100000

// Print bytes in hexadecimal format
void print_bytes(const unsigned char *data, size_t size)
{
    for (size_t i = 0; i < size; i++)
    {
        printf("%02X ", data[i]);
    }
    printf("\n");
}


// Correctness test function
void test_aes_correctness()
{
    // Fixed example key  0x00012001710198aeda79171460153594  
    unsigned char key[AES_KEY_SIZE] = {0x00, 0x01, 0x20, 0x01, 0x71, 0x01, 0x98, 0xae, 
    0xda, 0x79, 0x17, 0x14, 0x60, 0x15, 0x35, 0x94};
    // unsigned char key[AES_KEY_SIZE] = {0x2A, 0x1B, 0xB8, 0x91, 0xF6, 0xF7, 0x64, 0xCD, 
    // 0x82, 0x93, 0xD0, 0xC9, 0xCE, 0xEF, 0xFC, 0x85};
    // Fixed example plaintext 0x0001000101a198afda78173486153566 
    // unsigned char plaintext[AES_BLOCK_SIZE] = {0x00, 0x01, 0x00, 0x01, 0x01, 0xa1, 0x98, 0xaf,
    // 0xda, 0x78, 0x17, 0x34, 0x86, 0x15, 0x35, 0x66};
    unsigned char plaintext[AES_BLOCK_SIZE] = {0x00, 0x01, 0x00, 0x01, 0x01, 0xa1, 0x98, 0xaf,
    0xda, 0x78, 0x17, 0x34, 0x86, 0x15, 0x35, 0x66};

    // Corresponding ciphertext 0x6cdd596b8f5642cbd23b47981a65422a
    unsigned char correctResult[AES_BLOCK_SIZE] = {0x6c, 0xdd, 0x59, 0x6b, 0x8f, 0x56, 0x42, 0xcb,
     0xd2, 0x3b, 0x47, 0x98, 0x1a, 0x65, 0x42, 0x2a};

    unsigned char ciphertext[AES_BLOCK_SIZE];
    unsigned char decrypted[AES_BLOCK_SIZE];

    unsigned char encSubKeys[11][16];
    unsigned char decSubKeys[11][16];

    // Generate encryption subkeys
    if (aes_make_enc_subkeys(key, encSubKeys) != 0)
    {
        printf("Failed to generate encryption subkeys.\n");
        return;
    }
    // Generate decryption subkeys
    if (aes_make_dec_subkeys(key, decSubKeys) != 0)
    {
        printf("Failed to generate decryption subkeys.\n");
        return;
    }

    printf("Original plaintext: ");
    print_bytes(plaintext, AES_BLOCK_SIZE);

    printf("Correct ciphertext: ");
    print_bytes(correctResult, AES_BLOCK_SIZE);

    // Encrypt
    aes_encrypt_block(plaintext, encSubKeys, ciphertext);
    printf("Encrypted ciphertext: ");
    print_bytes(ciphertext, AES_BLOCK_SIZE);

    // Decrypt
    aes_decrypt_block(ciphertext, decSubKeys, decrypted);
    printf("Decrypted plaintext: ");
    print_bytes(decrypted, AES_BLOCK_SIZE);

    // Verify encryption result
    if ((memcmp(ciphertext, correctResult, AES_BLOCK_SIZE) == 0) && (memcmp(plaintext, decrypted, AES_BLOCK_SIZE) == 0))
    {
        printf(">> Correctness test passed.\n\n");
    }
    else
    {
        printf(">> Correctness test failed.\n\n");
    }
}

// Performance test function
void test_aes_performance()
{
    srand((unsigned int)time(NULL));
    // random key
    unsigned char key[AES_KEY_SIZE];
    for (int i = 0; i < AES_KEY_SIZE; i++) {
        key[i] = rand() & 0xFF;
    }
    // random plaintext
    unsigned char plaintext[AES_BLOCK_SIZE];
    for (int i = 0; i < AES_BLOCK_SIZE; i++) {
        plaintext[i] = rand() & 0xFF;
    }

    unsigned char ciphertext[AES_BLOCK_SIZE];
    unsigned char decrypted[AES_BLOCK_SIZE];
    
    unsigned char encSubKeys[11][16];
    unsigned char decSubKeys[11][16];

    // Generate encryption subkeys
    if (aes_make_enc_subkeys(key, encSubKeys) != 0)
    {
        printf("Failed to generate encryption subkeys.\n");
        return;
    }
    // Generate decryption subkeys
    if (aes_make_dec_subkeys(key, decSubKeys) != 0)
    {
        printf("Failed to generate decryption subkeys.\n");
        return;
    }

    // Perform performance test
    BPS_BENCH_START("AES encryption", BENCHS);
    BPS_BENCH_ITEM(aes_encrypt_block(plaintext, encSubKeys, ciphertext), ROUNDS);
    BPS_BENCH_FINAL(AES_BLOCK_BITS);

    BPS_BENCH_START("AES decryption", BENCHS);
    BPS_BENCH_ITEM(aes_decrypt_block(ciphertext, decSubKeys, decrypted), ROUNDS);
    BPS_BENCH_FINAL(AES_BLOCK_BITS);
}

void test_aes_cfb()
{
    printf(">> Testing AES-CFB mode...\n");

    unsigned char key[AES_KEY_SIZE] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };
    unsigned char iv[AES_BLOCK_SIZE] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    
    unsigned char plaintext[] = "Hello, CFB mode of AES!";
    size_t plaintext_len = strlen((char*)plaintext);
    
    unsigned char ciphertext[100];
    unsigned char decrypted[100];

    printf("Original plaintext: %s\n", plaintext);
    printf("Plaintext in hex: ");
    print_bytes(plaintext, plaintext_len);

    if (aes_cfb_encrypt(plaintext, plaintext_len, key, iv, ciphertext) != 0) {
        printf("CFB encryption failed!\n");
        return;
    }

    printf("Ciphertext in hex: ");
    print_bytes(ciphertext, plaintext_len);

    if (aes_cfb_decrypt(ciphertext, plaintext_len, key, iv, decrypted) != 0) {
        printf("CFB decryption failed!\n");
        return;
    }

    decrypted[plaintext_len] = '\0'; 
    printf("Decrypted text: %s\n", decrypted);
    printf("Decrypted in hex: ");
    print_bytes(decrypted, plaintext_len);

    if (memcmp(plaintext, decrypted, plaintext_len) == 0) {
        printf(">> CFB test passed.\n\n");
    } else {
        printf(">> CFB test failed!\n\n");
    }
}

int main()
{
    // Perform correctness test
    printf(">> Performing correctness test...\n");
    test_aes_correctness();

    // Perform performance test
    printf(">> Performing performance test...\n");
    test_aes_performance();

    // Add CFB mode test
    test_aes_cfb();
    
    return 0;
}


