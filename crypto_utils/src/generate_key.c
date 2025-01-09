#include "ecdh.h"
#include "ecdh_protocol.h"
#include "ecdsa.h"
#include <fcntl.h>
#include <gmp.h>
#include <stdio.h>
#include <string.h>

static void dump_hex(char *dest, const uint8_t *data, size_t len) {
  char tmp[3];
  for (size_t i = 0; i < len; i++) {
    sprintf(tmp, "%02x", data[i]);
    strcat(dest, tmp);
  }
  strcat(dest, "\n");
}
int main(int argc, char *argv[]) {
  ECurve curve;
  uint8_t public[PUBKEY_SERIALIZED_LEN];
  uint8_t private[32];
  ecdsa_init_context(&curve);
  ecdsa_generate_keypair(&curve, public, sizeof(public), private,
                         sizeof(private));

  char pub_out[PUBKEY_SERIALIZED_LEN * 2] = "";
  char pri_out[32 * 2] = "";
  dump_hex(pub_out, public, PUBKEY_SERIALIZED_LEN);
  dump_hex(pri_out, private, 32);
  printf("%s\n%s", pub_out, pri_out);
  char filename[100];
  sprintf(filename, "%s.pub", argv[1]);
  FILE *fd = fopen(argv[1], "w");
  fwrite(pri_out, 1, 32 * 2, fd);
  FILE *fd_1 = fopen(filename, "w");
  fwrite(pub_out, 1, PUBKEY_SERIALIZED_LEN * 2, fd_1);
}
