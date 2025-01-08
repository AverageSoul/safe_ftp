#include "sha256.h"
#include <stdio.h>
#include <string.h>

#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define EP1(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define SIG0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ ((x) >> 3))
#define SIG1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ ((x) >> 10))

static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    // ...existing code... (其余常量)
};

static void sha256_transform(SHA256_CTX *ctx, const uint8_t *data) {
  uint32_t a, b, c, d, e, f, g, h, t1, t2, m[64];
  int i;

  // 准备消息调度
  for (i = 0; i < 16; i++) {
    m[i] = (data[i * 4] << 24) | (data[i * 4 + 1] << 16) |
           (data[i * 4 + 2] << 8) | (data[i * 4 + 3]);
  }
  for (; i < 64; i++) {
    m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];
  }

  a = ctx->state[0];
  b = ctx->state[1];
  c = ctx->state[2];
  d = ctx->state[3];
  e = ctx->state[4];
  f = ctx->state[5];
  g = ctx->state[6];
  h = ctx->state[7];

  // 主循环
  for (i = 0; i < 64; i++) {
    t1 = h + EP1(e) + CH(e, f, g) + K[i] + m[i];
    t2 = EP0(a) + MAJ(a, b, c);
    h = g;
    g = f;
    f = e;
    e = d + t1;
    d = c;
    c = b;
    b = a;
    a = t1 + t2;
  }

  ctx->state[0] += a;
  ctx->state[1] += b;
  ctx->state[2] += c;
  ctx->state[3] += d;
  ctx->state[4] += e;
  ctx->state[5] += f;
  ctx->state[6] += g;
  ctx->state[7] += h;
}

void sha256_init(SHA256_CTX *ctx) {
  ctx->state[0] = 0x6a09e667;
  ctx->state[1] = 0xbb67ae85;
  ctx->state[2] = 0x3c6ef372;
  ctx->state[3] = 0xa54ff53a;
  ctx->state[4] = 0x510e527f;
  ctx->state[5] = 0x9b05688c;
  ctx->state[6] = 0x1f83d9ab;
  ctx->state[7] = 0x5be0cd19;
  ctx->count = 0;
}

void sha256_update(SHA256_CTX *ctx, const void *data, size_t len) {
  const uint8_t *input = (const uint8_t *)data;
  size_t bufsize = ctx->count % SHA256_BLOCK_SIZE;

  ctx->count += len;

  if (bufsize > 0) {
    size_t need = SHA256_BLOCK_SIZE - bufsize;
    if (len < need) {
      memcpy(ctx->buffer + bufsize, input, len);
      return;
    }
    memcpy(ctx->buffer + bufsize, input, need);
    sha256_transform(ctx, ctx->buffer);
    input += need;
    len -= need;
  }

  while (len >= SHA256_BLOCK_SIZE) {
    sha256_transform(ctx, input);
    input += SHA256_BLOCK_SIZE;
    len -= SHA256_BLOCK_SIZE;
  }

  if (len > 0) {
    memcpy(ctx->buffer, input, len);
  }
}

void sha256_final(SHA256_CTX *ctx, uint8_t *digest) {
  uint32_t i;
  uint64_t total_bits;
  size_t pad_len;
  uint8_t padding[SHA256_BLOCK_SIZE];

  total_bits = ctx->count * 8;
  pad_len = SHA256_BLOCK_SIZE - ((ctx->count % SHA256_BLOCK_SIZE) + 8);
  if (pad_len <= 0)
    pad_len += SHA256_BLOCK_SIZE;

  memset(padding, 0, pad_len);
  padding[0] = 0x80;

  for (i = 0; i < 8; i++)
    padding[pad_len + i] = (total_bits >> ((7 - i) * 8)) & 0xff;

  sha256_update(ctx, padding, pad_len + 8);

  for (i = 0; i < 8; i++) {
    digest[i * 4] = (ctx->state[i] >> 24) & 0xff;
    digest[i * 4 + 1] = (ctx->state[i] >> 16) & 0xff;
    digest[i * 4 + 2] = (ctx->state[i] >> 8) & 0xff;
    digest[i * 4 + 3] = ctx->state[i] & 0xff;
  }
}

void sha256_hash(const void *data, size_t len, uint8_t *digest) {
  SHA256_CTX ctx;
  sha256_init(&ctx);
  sha256_update(&ctx, data, len);
  sha256_final(&ctx, digest);
}

int sha256_file(const char *filename, uint8_t *digest) {
  FILE *fp;
  SHA256_CTX ctx;
  uint8_t buffer[4096];
  size_t bytes;

  fp = fopen(filename, "rb");
  if (!fp)
    return -1;

  sha256_init(&ctx);
  while ((bytes = fread(buffer, 1, sizeof(buffer), fp)) > 0) {
    sha256_update(&ctx, buffer, bytes);
  }
  sha256_final(&ctx, digest);

  fclose(fp);
  return 0;
}
