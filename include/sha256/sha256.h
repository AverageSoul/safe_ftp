#ifndef SHA256_H
#define SHA256_H

#include <stdint.h>
#include <stddef.h>

#define SHA256_BLOCK_SIZE 64
#define SHA256_DIGEST_SIZE 32

typedef struct {
    uint32_t state[8];
    uint64_t count;
    uint8_t buffer[SHA256_BLOCK_SIZE];
} SHA256_CTX;

void sha256_init(SHA256_CTX *ctx);
void sha256_update(SHA256_CTX *ctx, const void *data, size_t len);
void sha256_final(SHA256_CTX *ctx, uint8_t *digest);

void sha256_hash(const void *data, size_t len, uint8_t *digest);
int sha256_file(const char *filename, uint8_t *digest);

#endif
