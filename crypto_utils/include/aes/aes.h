#ifndef AES_H
#define AES_H

#ifdef __cplusplus
extern "C" {
#endif

#define AES_BLOCK_BITS 128 /* bits of AES algoithm block */
#define AES_BLOCK_SIZE 16  /* bytes of AES algoithm block */
#define AES_KEY_SIZE 16    /* bytes of AES algoithm double key */
#define AES_EXPANDED_KEY_SIZE                                                  \
  176 /* bytes of expanded AES key for 128-bit key */
#define AES_EXPANDED_KEY_BLOCK                                                 \
  11 /* blocks of expanded AES key for 128-bit key */

/**
 * @brief Generate encryption subkeys
 * @param[in] key original key
 * @param[out] subKeys generated encryption subkeys
 * @return 0 OK
 * @return 1 Failed
 */
int aes_make_enc_subkeys(const unsigned char key[16],
                         unsigned char subKeys[11][16]);

/**
 * @brief Generate decryption subkeys
 * @param[in] key original key
 * @param[out] subKeys generated decryption subkeys
 * @return 0 OK
 * @return 1 Failed
 */
int aes_make_dec_subkeys(const unsigned char key[16],
                         unsigned char subKeys[11][16]);

/**
 * @brief AES encrypt single block
 * @param[in] input plaintext, [length = AES_BLOCK_SIZE]
 * @param[in] subKeys subKeys
 * @param[out] output ciphertext, [length = AES_BLOCK_SIZE]
 */
void aes_encrypt_block(const unsigned char *input,
                       unsigned char subKeys[11][16], unsigned char *output);

/**
 * @brief AES decrypt single block
 * @param[in] input ciphertext, [length = AES_BLOCK_SIZE]
 * @param[in] subKeys subKeys
 * @param[out] output plaintext, [length = AES_BLOCK_SIZE]
 */
void aes_decrypt_block(const unsigned char *input,
                       unsigned char subKeys[11][16], unsigned char *output);

#ifdef __cplusplus
}
#endif

#include "table.h"
#include <stdint.h>

// 定义一个联合体，用于按不同的方式访问数据
typedef union {
  uint64_t d;   // 按 64 位访问数据
  uint8_t b[8]; // 按字节访问数据
} uni;

// 轮常量
static const uint8_t RCON[11] = {0x8d, 0x01, 0x02, 0x04, 0x08, 0x10,
                                 0x20, 0x40, 0x80, 0x1b, 0x36};

// 列混淆矩阵
static const uint8_t MIX_COLUMNS[4][4] = {{0x02, 0x03, 0x01, 0x01},
                                          {0x01, 0x02, 0x03, 0x01},
                                          {0x01, 0x01, 0x02, 0x03},
                                          {0x03, 0x01, 0x01, 0x02}};

// 逆列混淆矩阵
static const uint8_t INV_MIX_COLUMNS[4][4] = {{0x0e, 0x0b, 0x0d, 0x09},
                                              {0x09, 0x0e, 0x0b, 0x0d},
                                              {0x0d, 0x09, 0x0e, 0x0b},
                                              {0x0b, 0x0d, 0x09, 0x0e}};

// 将列表示形式的 state 转换回行表示形式
static void convert_to_row_representation(unsigned int state[4],
                                          unsigned char output[4][4]) {
  int i, j;

  for (i = 0; i < 4; i++) {
    output[0][i] = (state[i] >> 24) & 0xFF;
    output[1][i] = (state[i] >> 16) & 0xFF;
    output[2][i] = (state[i] >> 8) & 0xFF;
    output[3][i] = state[i] & 0xFF;
  }
}
static void convert_to_column_representation(unsigned char input[4][4],
                                             unsigned int state[4]) {
  int i, j;

  for (i = 0; i < 4; i++) {
    state[i] = ((unsigned int)input[0][i] << 24) |
               ((unsigned int)input[1][i] << 16) |
               ((unsigned int)input[2][i] << 8) | ((unsigned int)input[3][i]);
  }
}

static void add_round_key(uint64_t *state, const uint64_t *roundKey) {
  state[0] ^= roundKey[0];
  state[1] ^= roundKey[1];
}

static void sub_bytes(unsigned char state[4][4]) {
  int i, j;
  for (i = 0; i < 4; i++) {
    for (j = 0; j < 4; j++) {
      state[i][j] = S_BOX[state[i][j]];
    }
  }
}

static void inv_sub_bytes(unsigned char state[4][4]) {
  int i, j;
  for (i = 0; i < 4; i++) {
    for (j = 0; j < 4; j++) {
      state[i][j] = INV_S_BOX[state[i][j]];
    }
  }
}

static void shift_rows(unsigned char state[4][4]) {
  // 移位方法1
  unsigned char temp[4];

  for (int i = 0; i < 4; ++i) {
    temp[0] = state[0][i];
    temp[1] = state[1][i];
    temp[2] = state[2][i];
    temp[3] = state[3][i];
    state[0][i] = temp[(i + 0) % 4];
    state[1][i] = temp[(i + 1) % 4];
    state[2][i] = temp[(i + 2) % 4];
    state[3][i] = temp[(i + 3) % 4];
  }
}
// 逆行移位函数
static void inv_shift_rows(unsigned char state[4][4]) {
  // 逆移位方法1
  unsigned char temp[4];

  for (int i = 0; i < 4; ++i) {
    temp[0] = state[0][i];
    temp[1] = state[1][i];
    temp[2] = state[2][i];
    temp[3] = state[3][i];
    state[0][i] = temp[(4 - i) % 4];
    state[1][i] = temp[(5 - i) % 4];
    state[2][i] = temp[(6 - i) % 4];
    state[3][i] = temp[(7 - i) % 4];
  }
}

static void XtimeLong(uint64_t *w) {
  uint64_t a, b;

  a = *w;
  b = a & (uint64_t)(0x8080808080808080);
  a ^= b;
  b -= b >> 7;
  b &= (uint64_t)(0x1B1B1B1B1B1B1B1B);
  b ^= a << 1;
  *w = b;
}

// 学习开源代码之后用的列混淆函数
static void mix_columns(uint64_t *state) {
  uni s1, s;
  for (int c = 0; c < 2; c++) {
    s1.d = state[c];
    s.d = s1.d;
    s.d ^= ((s.d & (uint64_t)(0xFFFF0000FFFF0000)) >> 16) |
           ((s.d & (uint64_t)(0x0000FFFF0000FFFF)) << 16);
    s.d ^= ((s.d & (uint64_t)(0xFF00FF00FF00FF00)) >> 8) |
           ((s.d & (uint64_t)(0x00FF00FF00FF00FF)) << 8);
    s.d ^= s1.d;
    XtimeLong(&s1.d);
    s.d ^= s1.d;
    s.b[0] ^= s1.b[1];
    s.b[1] ^= s1.b[2];
    s.b[2] ^= s1.b[3];
    s.b[3] ^= s1.b[0];
    s.b[4] ^= s1.b[5];
    s.b[5] ^= s1.b[6];
    s.b[6] ^= s1.b[7];
    s.b[7] ^= s1.b[4];
    state[c] = s.d;
  }
}

static void inv_mix_columns(uint64_t *state) {
  uni s1, s;
  int c;

  for (c = 0; c < 2; c++) {
    s1.d = state[c];
    s.d = s1.d;
    s.d ^= ((s.d & (uint64_t)(0xFFFF0000FFFF0000)) >> 16) |
           ((s.d & (uint64_t)(0x0000FFFF0000FFFF)) << 16);
    s.d ^= ((s.d & (uint64_t)(0xFF00FF00FF00FF00)) >> 8) |
           ((s.d & (uint64_t)(0x00FF00FF00FF00FF)) << 8);
    s.d ^= s1.d;
    XtimeLong(&s1.d);
    s.d ^= s1.d;
    s.b[0] ^= s1.b[1];
    s.b[1] ^= s1.b[2];
    s.b[2] ^= s1.b[3];
    s.b[3] ^= s1.b[0];
    s.b[4] ^= s1.b[5];
    s.b[5] ^= s1.b[6];
    s.b[6] ^= s1.b[7];
    s.b[7] ^= s1.b[4];
    XtimeLong(&s1.d);
    s1.d ^= ((s1.d & (uint64_t)(0xFFFF0000FFFF0000)) >> 16) |
            ((s1.d & (uint64_t)(0x0000FFFF0000FFFF)) << 16);
    s.d ^= s1.d;
    XtimeLong(&s1.d);
    s1.d ^= ((s1.d & (uint64_t)(0xFF00FF00FF00FF00)) >> 8) |
            ((s1.d & (uint64_t)(0x00FF00FF00FF00FF)) << 8);
    s.d ^= s1.d;
    state[c] = s.d;
  }
}

static void RotWord(uint32_t *x) {
  unsigned char *w0;
  unsigned char tmp;

  w0 = (unsigned char *)x;
  tmp = w0[0];
  w0[0] = w0[1];
  w0[1] = w0[2];
  w0[2] = w0[3];
  w0[3] = tmp;
}

static void convert_uint_to_uchar(const unsigned int temp[4],
                                  unsigned char temp1[4][4]) {
  int i, j;

  for (i = 0; i < 4; i++) {
    for (j = 0; j < 4; j++) {
      temp1[i][j] = (temp[i] >> (24 - 8 * j)) & 0xFF;
    }
  }
}
#endif // AES_H
