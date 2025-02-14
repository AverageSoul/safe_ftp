#include "ftserve.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#include "aes/aes.h"
#include "aes/aes_cfb.h"
#include "ecdh/ecdh.h"
#include "ecdh/ecdh_protocol.h"
#include "ecdsa/ecdsa.h"
#include "sha256/sha256.h"
#include <sys/types.h>
#include <time.h>
const char root_path[] = "./uploads/";
uint8_t server_private_key[32];
const char private_key_path[] = "./server_private_key";
int main(int argc, char *argv[]) {
  int sock_listen, sock_control, port, pid;

  if (argc != 2) {
    printf("usage: ./ftserve port\n");
    exit(0);
  }

  port = atoi(argv[1]);

  // create socket
  if ((sock_listen = socket_create(port)) < 0) {
    perror("Error creating socket");
    exit(1);
  }

  if (read_hex_file_to_bytes(private_key_path, server_private_key,
                             sizeof(server_private_key)) == -1) {
    perror("Error reading server private key");
    exit(1);
  }
  while (1) { // wait for client request

    // create new socket for control connection
    if ((sock_control = socket_accept(sock_listen)) < 0)
      break;

    // create child process to do actual file transfer
    if ((pid = fork()) < 0) {
      perror("Error forking child process");
    } else if (pid == 0) {
      close(sock_listen);
      ftserve_process(sock_control);
      close(sock_control);
      exit(0);
    }

    close(sock_control);
  }

  close(sock_listen);

  return 0;
}

/**
 * Send file specified in filename over data connection, sending
 * control message over control connection
 * Handles case of null or invalid filename
 */
// TODO: Encrypt
void ftserve_retr(int sock_control, int sock_data, char *filename,
                  uint8_t *user_pub) {
  FILE *fd = NULL;
  unsigned char data[MAXSIZE];
  unsigned char cipher[MAXSIZE];
  unsigned char key[AES_KEY_SIZE];
  unsigned char iv[AES_KEY_SIZE];
  size_t num_read;
  char filepath[MAXSIZE + 10];
  strcpy(filepath, root_path);

  if (strchr(filename, '/')) {
    send_response(sock_control, 550);
    return;
  }
  strncat(filepath, filename, 512);

  fd = fopen(filepath, "r");
  uint8_t file_hash[SHA256_DIGEST_SIZE];
  sha256_file(filepath, file_hash);
  ECurve curve;
  ecdsa_init_context(&curve);
  ECDSASignature file_sign;
  ecdsa_sign(&curve, server_private_key, sizeof(server_private_key), file_hash,
             sizeof(file_hash), &file_sign);

  if (!fd) {
    // send error code (550 Requested action not taken)
    send_response(sock_control, 550);

  } else {
    // send okay (150 File status okay)
    send_response(sock_control, 150);

    mpz_t shared;
    if (server_exchange_key(&shared, sock_control, user_pub)) {
      return;
    }

    split_mpz_t(shared, key, iv);
    printf("key: ");
    print_bytes(key, AES_KEY_SIZE);
    puts("");
    printf("iv: ");
    print_bytes(iv, AES_KEY_SIZE);
    puts("");

    aes_cfb_encrypt(file_hash, sizeof(file_hash), key, iv, cipher);
    send(sock_data, cipher, sizeof(file_hash), 0);
    memcpy(iv, cipher, AES_BLOCK_SIZE);
    memcpy(data, &file_sign, sizeof(file_sign));
    aes_cfb_encrypt(data, sizeof(file_sign), key, iv, cipher);
    memcpy(iv, cipher, AES_BLOCK_SIZE);
    send(sock_data, cipher, sizeof(file_sign), 0);
    printf("file hash: ");
    print_bytes(file_hash, sizeof(file_hash));
    printf("file sign: ");
    print_bytes(file_sign.r, sizeof(file_sign.r));
    print_bytes(file_sign.s, sizeof(file_sign.s));

    do {
      num_read = fread(data, 1, MAXSIZE, fd);

      if (num_read < 0) {
        printf("error in fread()\n");
      }

      aes_cfb_encrypt(data, num_read, key, iv, cipher);
      memcpy(iv, cipher, AES_BLOCK_SIZE);

      if (!num_read)
        break;
      printf("cipher: ");
      print_bytes(cipher, num_read);
      puts("");
      // send block
      if (send(sock_data, cipher, num_read, 0) < 0)
        perror("error sending file\n");

    } while (num_read > 0);

    // send message: 226: closing conn, file transfer successful
    send_response(sock_control, 226);

    fclose(fd);
  }
  ecdh_free_context(&curve);
}

/**
 * Receive file specified in filename over data connection, sending
 * control message over control connection
 */

// TODO: Check the sign
void ftserve_put(int sock_control, int sock_data, char *filename,
                 uint8_t *user_pub) {
  FILE *fd = NULL;
  unsigned char data[MAXSIZE];
  unsigned char cipher[MAXSIZE];
  char filepath[MAXSIZE + 10];
  unsigned char key[AES_KEY_SIZE];
  unsigned char iv[AES_KEY_SIZE];
  strcpy(filepath, root_path);

  int size;

  if (strchr(filename, '/')) {
    send_response(sock_control, 550);
    return;
  }
  strncat(filepath, filename, 512);
  mpz_t shared;
  server_exchange_key(&shared, sock_control, user_pub);
  split_mpz_t(shared, key, iv);

  fd = fopen(filename, "w");

  if (!fd) {
    // send error code (550 Requested action not taken)
    send_response(sock_control, 550);
  } else {
    // send okay (150 File status okay)
    send_response(sock_control, 150);

    ECurve curve;
    ecdsa_init_context(&curve);
    uint8_t recv_file_hash[SHA256_DIGEST_SIZE];

    recv(sock_data, cipher, sizeof(recv_file_hash), 0);
    aes_cfb_decrypt(cipher, sizeof(recv_file_hash), key, iv, recv_file_hash);
    memcpy(iv, cipher, AES_BLOCK_SIZE);

    ECDSASignature file_sign;
    recv(sock_data, cipher, sizeof(file_sign), 0);
    aes_cfb_decrypt(cipher, sizeof(file_sign), key, iv, data);
    memcpy(iv, cipher, AES_BLOCK_SIZE);
    memcpy(&file_sign, data, sizeof(file_sign));

    printf("received file hash: ");
    print_bytes(recv_file_hash, sizeof(recv_file_hash));
    puts("\n");
    printf("file sign: ");
    print_bytes(file_sign.r, sizeof(file_sign.r));
    print_bytes(file_sign.s, sizeof(file_sign.s));

    while ((size = recv(sock_data, cipher, MAXSIZE, 0)) > 0) {

      aes_cfb_decrypt(cipher, size, key, iv, data);
      memcpy(iv, cipher, AES_BLOCK_SIZE);
      fwrite(data, 1, size, fd);
    }
    printf("calc file hash: ");
    uint8_t file_hash[SHA256_DIGEST_SIZE];
    sha256_file(filepath, file_hash);
    if (memcmp(file_hash, recv_file_hash, SHA256_DIGEST_SIZE)) {
      printf("file hash doesn't match\n");
      remove(filepath);
      return;
    }
    print_bytes(file_hash, sizeof(file_hash));
    if (ecdsa_verify(&curve, user_pub, PUBKEY_SERIALIZED_LEN, recv_file_hash,
                     sizeof(recv_file_hash), &file_sign)) {
      printf("file sign verification failed\n");
      remove(filepath);
      return;
    }
    printf("file sign verification succeed\n");

    // send message: 226: closing conn, file transfer successful
    send_response(sock_control, 226);
    ecdh_free_context(&curve);
    fclose(fd);
  }
}
/**
 * Send list of files in current directory
 * over data connection
 * Return -1 on error, 0 on success
 */
int ftserve_list(int sock_data, int sock_control) {
  DIR *dir;
  struct dirent *entry;
  struct stat file_stat;
  char data[MAXSIZE];
  char filepath[PATH_MAX];

  // Open the allowed directory
  if ((dir = opendir(root_path)) == NULL) {
    perror("opendir");
    send_response(sock_control, 550); // Requested action not taken
    return -1;
  }

  // Send starting response
  send_response(sock_control, 150); // File status okay

  // Read directory entries
  while ((entry = readdir(dir)) != NULL) {
    snprintf(filepath, sizeof(filepath), "%s/%s", root_path, entry->d_name);

    // Get file stats
    if (stat(filepath, &file_stat) == -1) {
      perror("stat");
      continue;
    }

    // Skip directories
    if (S_ISDIR(file_stat.st_mode)) {
      continue;
    }

    // Format file information
    snprintf(data, sizeof(data), "%s\t%ldbytes\n", entry->d_name,
             file_stat.st_size);

    // Send file information to client
    if (send(sock_data, data, strlen(data), 0) < 0) {
      perror("send");
      closedir(dir);
      return -1;
    }
  }

  // Close directory
  closedir(dir);

  // Send completion response
  send_response(sock_control,
                226); // Closing connection, file transfer successful

  return 0;
}

/**
 * Open data connection to client
 * Returns: socket for data connection
 * or -1 on error
 */
int ftserve_start_data_conn(int sock_control) {
  char buf[1024];
  int wait, sock_data;

  // Wait for go-ahead on control conn
  if (recv(sock_control, &wait, sizeof wait, 0) < 0) {
    perror("Error while waiting");
    return -1;
  }

  // Get client address
  struct sockaddr_in client_addr;
  socklen_t len = sizeof client_addr;
  getpeername(sock_control, (struct sockaddr *)&client_addr, &len);
  inet_ntop(AF_INET, &client_addr.sin_addr, buf, sizeof(buf));

  // Initiate data connection with client
  if ((sock_data = socket_connect(CLIENT_PORT_ID, buf)) < 0)
    return -1;

  return sock_data;
}

/**
 * Authenticate a user's credentials
 * Return 1 if authenticated, 0 if not
 */
int ftserve_check_user(char *user, char *pass) {
  char username[MAXSIZE];
  char password[MAXSIZE];
  char *pch;
  char buf[MAXSIZE];
  char *line = NULL;
  size_t num_read;
  size_t len = 0;
  FILE *fd;
  int auth = 0;

  fd = fopen(".auth", "r");
  if (fd == NULL) {
    perror("file not found");
    exit(1);
  }

  while ((num_read = getline(&line, &len, fd)) != -1) {
    memset(buf, 0, MAXSIZE);
    strcpy(buf, line);

    pch = strtok(buf, " ");
    strcpy(username, pch);

    if (pch != NULL) {
      pch = strtok(NULL, " ");
      strcpy(password, pch);
    }

    // remove end of line and whitespace
    trimstr(password, (int)strlen(password));

    if ((strcmp(user, username) == 0) && (strcmp(pass, password) == 0)) {
      auth = 1;
      break;
    }
  }
  free(line);
  fclose(fd);
  return auth;
}
void generate_random_256bit(mpz_t result) {
  gmp_randstate_t state;
  gmp_randinit_default(state);
  gmp_randseed_ui(state, time(NULL)); // 使用当前时间作为随机种子
  mpz_urandomb(result, state, 256);   // 生成256位随机数
  gmp_randclear(state);
}
/**
 * Log in connected client
 */

int ftserve_login(int sock_control, uint8_t *user_pub) {
  char buf[MAXSIZE];
  char user[MAXSIZE / 2];
  char keypath[MAXSIZE];
  ECDSASignature signature;
  memset(user, 0, MAXSIZE / 2);
  memset(buf, 0, MAXSIZE);

  // Wait to recieve username
  if ((recv_data(sock_control, buf, sizeof(buf))) == -1) {
    perror("recv error\n");
    exit(1);
  }

  int i = 5;
  int n = 0;
  while (buf[i] != 0)
    user[n++] = buf[i++];

  // tell client we're ready to send rnd
  send_response(sock_control, 331);

  mpz_t rnd;
  mpz_init(rnd);
  generate_random_256bit(rnd);
  size_t count = 32;
  unsigned char rnd_buffer[32];
  mpz_export(rnd_buffer, &count, 1, 1, 0, 0, rnd);

  printf("server sending rnd: ");
  print_bytes(rnd_buffer, 32);
  puts("");
  if (send(sock_control, rnd_buffer, count, 0) < 0) {
    perror("Error sending random number");
  }

  // Wait to receieve sign
  memset(buf, 0, MAXSIZE);
  if ((recv_data(sock_control, buf, sizeof(buf))) == -1) {
    perror("recv error\n");
    exit(1);
  }

  memcpy(&signature, buf + 5, sizeof(signature));

  printf("server received signature: ");
  print_bytes(signature.r, sizeof(signature.r));
  puts("");
  print_bytes(signature.s, sizeof(signature.s));
  puts("");

  uint8_t public_key[PUBKEY_SERIALIZED_LEN];
  sprintf(keypath, "./users/%s.pub", user);
  if (read_hex_file_to_bytes(keypath, public_key, sizeof(public_key)) == -1)
    return -1;

  memcpy(user_pub, public_key, PUBKEY_SERIALIZED_LEN);
  ECurve curve;
  ecdsa_init_context(&curve);

  if (ecdsa_verify(&curve, public_key, sizeof(public_key), rnd_buffer,
                   sizeof(rnd_buffer), &signature))
    return -1;
  return 1;
}

/**
 * Wait for command from client and
 * send response
 * Returns response code
 */
int ftserve_recv_cmd(int sock_control, char *cmd, char *arg) {
  int rc = 200;
  char buffer[MAXSIZE];

  memset(buffer, 0, MAXSIZE);
  memset(cmd, 0, 5);
  memset(arg, 0, MAXSIZE);

  // Wait to recieve command
  if ((recv_data(sock_control, buffer, sizeof(buffer))) == -1) {
    perror("recv error\n");
    return -1;
  }

  strncpy(cmd, buffer, 4);
  char *tmp = buffer + 5;
  strcpy(arg, tmp);

  if (strcmp(cmd, "QUIT") == 0) {
    rc = 221;
  } else if ((strcmp(cmd, "USER") == 0) || (strcmp(cmd, "PASS") == 0) ||
             (strcmp(cmd, "LIST") == 0) || (strcmp(cmd, "RETR") == 0) ||
             (strcmp(cmd, "STOR") == 0)) {
    rc = 200;
  } else { // invalid command
    rc = 502;
  }

  send_response(sock_control, rc);
  return rc;
}

int server_exchange_key(mpz_t *shared, int sock_control, uint8_t *user_pub) {
  ECurve curve;
  ecdh_init_context(&curve);
  // Alice的密钥对
  mpz_t alice_private;
  ECPoint alice_public;
  mpz_init(alice_private);
  ec_init_point(&alice_public);

  generate_keypair(alice_private, &alice_public, &curve);

  // 计算共享密钥
  mpz_t alice_shared;
  mpz_init(alice_shared);
  ECPoint bob_public;
  ec_init_point(&bob_public);

  uint8_t public[65];
  size_t length = sizeof(public);
  ECDSASignature pub_sign;
  printf("receiving public...\n");
  if (recv(sock_control, public, length, 0) < 0) {
    close(sock_control);
    perror("exchange key: recv key error\n");
    return -1;
  }
  if (recv(sock_control, &pub_sign, sizeof(pub_sign), 0) < 0) {

    close(sock_control);
    perror("exchange key: recv key sign error\n");
    return -1;
  }
  if (ecdsa_verify(&curve, user_pub, PUBKEY_SERIALIZED_LEN, public,
                   PUBKEY_SERIALIZED_LEN, &pub_sign)) {

    send_response(sock_control, 1001);
    perror("exchange key: public key sign verification failed\n");
    return -1;
  }
  send_response(sock_control, 1000);
  ecdh_deserialize_pubkey(&curve, &bob_public, public, sizeof(public));
  gmp_printf("received client public: %Zx %Zx\n", bob_public.x, bob_public.y);

  ecdh_serialize_pubkey(&alice_public, public, sizeof(public));

  ecdsa_sign(&curve, server_private_key, 32, public, sizeof(public), &pub_sign);
  if (send(sock_control, public, length, 0) < 0) {
    close(sock_control);
    printf("exchange key: send public failed\n");
    return -1;
  }
  if (send(sock_control, &pub_sign, sizeof(pub_sign), 0) < 0) {
    close(sock_control);
    printf("exchange key: send public sign failed\n");
    return -1;
  }

  printf("computing shared secret...\n");
  compute_shared_secret(alice_shared, &bob_public, alice_private, &curve);
  printf("key exchanged successfully\n");

  // 验证共享密钥是否相同
  gmp_printf("Shared secret: %Zx\n", alice_shared);
  mpz_set(*shared, alice_shared);

  ecdh_free_context(&curve);
  ec_clear_point(&alice_public);
  ec_clear_point(&bob_public);

  return 0;
}
/**
 * Child process handles connection to client
 */
void ftserve_process(int sock_control) {
  int sock_data;
  char cmd[5];
  char arg[MAXSIZE];
  uint8_t user_pub[PUBKEY_SERIALIZED_LEN];

  // Send welcome message
  send_response(sock_control, 220);

  // Authenticate user
  if (ftserve_login(sock_control, user_pub) == 1) {
    send_response(sock_control, 230);
  } else {
    send_response(sock_control, 430);
    exit(0);
  }

  // TODO: Sign

  while (1) {
    // Wait for command
    int rc = ftserve_recv_cmd(sock_control, cmd, arg);

    if ((rc < 0) || (rc == 221)) {
      break;
    }

    if (rc == 200) {
      // Open data connection with client
      if ((sock_data = ftserve_start_data_conn(sock_control)) < 0) {
        close(sock_control);
        exit(1);
      }

      // Execute command
      if (strcmp(cmd, "LIST") == 0) { // Do list
        ftserve_list(sock_data, sock_control);
      } else if (strcmp(cmd, "RETR") == 0) { // Do get <filename>
        ftserve_retr(sock_control, sock_data, arg, user_pub);
      } else if (strcmp(cmd, "STOR") == 0) { // Do put <filename>
        ftserve_put(sock_control, sock_data, arg, user_pub);
      }

      // Close data connection
      close(sock_data);
    }
  }
}
