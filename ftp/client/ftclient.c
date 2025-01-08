#include "ftclient.h"
#include "aes/aes.h"
#include "aes/aes_cfb.h"
#include "ecdh/ecdh.h"
#include "ecdh/ecdh_protocol.h"
#include "ecdsa/ecdsa.h"
#include "sha256/sha256.h"
#include <stdio.h>

int sock_control;

/**
 * Receive a response from server
 * Returns -1 on error, return code on success
 */
int read_reply() {
  int retcode = 0;
  if (recv(sock_control, &retcode, sizeof retcode, 0) < 0) {
    perror("client: error reading message from server\n");
    return -1;
  }
  return ntohl(retcode);
}

/**
 * Print response message
 */
void print_reply(int rc) {
  switch (rc) {
  case 220:
    printf("220 Welcome, server ready.\n");
    break;
  case 221:
    printf("221 Goodbye!\n");
    break;
  case 226:
    printf("226 Closing data connection. Requested file action successful.\n");
    break;
  case 550:
    printf("550 Requested action not taken. File unavailable.\n");
    break;
  }
}

/**
 * Parse command in cstruct
 */
int ftclient_read_command(char *buf, int size, struct command *cstruct) {
  memset(cstruct->code, 0, sizeof(cstruct->code));
  memset(cstruct->arg, 0, sizeof(cstruct->arg));

  printf("ftclient> "); // prompt for input
  fflush(stdout);

  // wait for user to enter a command
  read_input(buf, size);

  char *arg = NULL;
  arg = strtok(buf, " ");
  arg = strtok(NULL, " ");

  if (arg != NULL) {
    // store the argument if there is one
    strncpy(cstruct->arg, arg, strlen(arg));
  }

  // buf = command
  if (strcmp(buf, "list") == 0) {
    strcpy(cstruct->code, "LIST");
  } else if (strcmp(buf, "get") == 0) {
    strcpy(cstruct->code, "RETR");
  } else if (strcmp(buf, "put") == 0) {
    strcpy(cstruct->code, "STOR");
  } else if (strcmp(buf, "quit") == 0) {
    strcpy(cstruct->code, "QUIT");
  } else { // invalid
    return -1;
  }

  // store code in beginning of buffer
  memset(buf, 0, 400);
  strcpy(buf, cstruct->code);

  // if there's an arg, append it to the buffer
  if (arg != NULL) {
    strcat(buf, " ");
    strncat(buf, cstruct->arg, strlen(cstruct->arg));
  }

  return 0;
}

/**
 * Do get <filename> command
 */
int ftclient_get(int data_sock, int sock_control, char *arg) {
  unsigned char data[MAXSIZE];
  unsigned char cipher[MAXSIZE];
  unsigned char key[AES_KEY_SIZE];
  unsigned char iv[AES_KEY_SIZE];
  int size;

  mpz_t shared;
  client_exchange_key(&shared);
  FILE *fd = fopen(arg, "w");

  split_mpz_t(shared, key, iv);
  while ((size = recv(data_sock, cipher, MAXSIZE, 0)) > 0) {
    aes_cfb_decrypt(cipher, size, key, iv, data);
    printf("received cipher: ");
    print_bytes(cipher, size);
    puts("");
    printf("key: ");
    print_bytes(key, AES_KEY_SIZE);
    puts("");
    printf("iv: ");
    print_bytes(iv, AES_KEY_SIZE);
    puts("");
    printf("data: ");
    print_bytes(data, size);
    puts("");
    fwrite(data, 1, size, fd);
  }

  if (size < 0) {
    perror("error\n");
  }

  fclose(fd);
  return 0;
}

/**
 * Open data connection
 */
int ftclient_open_conn(int sock_con) {
  int sock_listen = socket_create(CLIENT_PORT_ID);

  // send an ACK on control conn
  int ack = 1;
  if ((send(sock_con, (char *)&ack, sizeof(ack), 0)) < 0) {
    printf("client: ack write error :%d\n", errno);
    exit(1);
  }

  int sock_conn = socket_accept(sock_listen);
  close(sock_listen);
  return sock_conn;
}

/**
 * Do list commmand
 */
int ftclient_list(int sock_data, int sock_con) {
  size_t num_recvd;  // number of bytes received with recv()
  char buf[MAXSIZE]; // hold a filename received from server
  int tmp = 0;

  // Wait for server starting message
  if (recv(sock_con, &tmp, sizeof tmp, 0) < 0) {
    perror("client: error reading message from server\n");
    return -1;
  }

  memset(buf, 0, sizeof(buf));
  while ((num_recvd = recv(sock_data, buf, MAXSIZE, 0)) > 0) {
    printf("%s", buf);
    memset(buf, 0, sizeof(buf));
  }

  if (num_recvd < 0) {
    perror("error");
  }

  // Wait for server done message
  if (recv(sock_con, &tmp, sizeof tmp, 0) < 0) {
    perror("client: error reading message from server\n");
    return -1;
  }
  return 0;
}

/**
 * Input: cmd struct with an a code and an arg
 * Concats code + arg into a string and sends to server
 */
int ftclient_send_cmd(struct command *cmd) {
  char buffer[MAXSIZE];
  int rc;

  sprintf(buffer, "%s %s", cmd->code, cmd->arg);

  // Send command string to server
  rc = send(sock_control, buffer, (int)strlen(buffer), 0);
  if (rc < 0) {
    perror("Error sending command to server");
    return -1;
  }

  return 0;
}

/**
 * Get login details from user and
 * send to server for authentication
 */
void ftclient_login() {
  struct command cmd;
  char user[256];
  memset(user, 0, 256);

  // Get username from user
  printf("Name: ");
  fflush(stdout);
  read_input(user, 256);

  // Send USER command to server
  strcpy(cmd.code, "USER");
  strcpy(cmd.arg, user);
  ftclient_send_cmd(&cmd);

  // Wait for go-ahead to send password
  int wait;
  recv(sock_control, &wait, sizeof wait, 0);

  // Get password from user
  fflush(stdout);
  char *pass = getpass("Password: ");

  // Send PASS command to server
  strcpy(cmd.code, "PASS");
  strcpy(cmd.arg, pass);
  ftclient_send_cmd(&cmd);

  // wait for response
  int retcode = read_reply();
  switch (retcode) {
  case 430:
    printf("Invalid username/password.\n");
    exit(0);
  case 230:
    printf("Successful login.\n");
    break;
  default:
    perror("error reading message from server");
    exit(1);
    break;
  }
}
/**
 * Do put <filename> command
 */
// TODO: Sign the file
int ftclient_put(int data_sock, int sock_control, char *arg) {
  char data[MAXSIZE];
  int size;
  FILE *fd = fopen(arg, "r");

  if (!fd) {
    perror("Error opening file");
    return -1;
  }

  while ((size = fread(data, 1, MAXSIZE, fd)) > 0) {
    if (send(data_sock, data, size, 0) < 0) {
      perror("Error sending file");
      fclose(fd);
      return -1;
    }
  }

  fclose(fd);
  return 0;
}

int client_exchange_key(mpz_t *shared) {
  printf("key exchange begins\n");
  ECurve curve;
  init_curve(&curve);
  printf("curve inited successfully\n");
  // Bob的密钥对
  mpz_t bob_private;
  ECPoint bob_public;
  mpz_init(bob_private);
  ec_init_point(&bob_public);
  generate_keypair(bob_private, &bob_public, &curve);

  mpz_t bob_shared;
  mpz_init(bob_shared);

  printf("keypair generated successfully\n");
  ECPoint alice_public;
  ec_init_point(&alice_public);

  printf("sending public...\n");
  gmp_printf("client public: %Zx %Zx\n", bob_public.x, bob_public.y);
  uint8_t public[PUBKEY_SERIALIZED_LEN];
  size_t length = sizeof(public);

  ecdh_serialize_pubkey(&bob_public, public, sizeof(public));
  if (send(sock_control, public, length, 0) < 0) {
    close(sock_control);
    printf("exchange key: send public failed\n");
    exit(1);
  }
  printf("receiving public...\n");
  if (recv(sock_control, public, length, 0) < 0) {
    perror("exchange key: recv key error\n");
    return -1;
  }

  ecdh_deserialize_pubkey(&curve, &alice_public, public, sizeof(public));
  gmp_printf("server public: %Zx %Zx\n", alice_public.x, alice_public.y);
  compute_shared_secret(bob_shared, &alice_public, bob_private, &curve);
  printf("secret shared successfully\n");
  gmp_printf("Shared secret: %Zx\n", bob_shared);
  mpz_set(*shared, bob_shared);

  return 0;
}

int main(int argc, char *argv[]) {
  int data_sock, retcode, s;
  char buffer[MAXSIZE];
  struct command cmd;
  struct addrinfo hints, *res, *rp;

  if (argc != 3) {
    printf("usage: ./ftclient hostname port\n");
    exit(0);
  }

  char *host = argv[1];
  char *port = argv[2];

  // Get matching addresses
  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  s = getaddrinfo(host, port, &hints, &res);
  if (s != 0) {
    printf("getaddrinfo() error %s", gai_strerror(s));
    exit(1);
  }

  // Find an address to connect to & connect
  for (rp = res; rp != NULL; rp = rp->ai_next) {
    sock_control = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);

    if (sock_control < 0)
      continue;

    if (connect(sock_control, res->ai_addr, res->ai_addrlen) == 0) {
      break;
    } else {
      perror("connecting stream socket");
      exit(1);
    }
    close(sock_control);
  }
  freeaddrinfo(rp);

  // Get connection, welcome messages
  printf("Connected to %s.\n", host);
  print_reply(read_reply());

  /* Get name and password and send to server */
  /*
        ftclient_login();
  */

  // TODO: Sign
  while (1) { // loop until user types quit
    // Get a command from user
    if (ftclient_read_command(buffer, sizeof buffer, &cmd) < 0) {
      printf("Invalid command\n");
      continue; // loop back for another command
    }

    // Send command to server
    if (send(sock_control, buffer, (int)strlen(buffer), 0) < 0) {
      close(sock_control);
      exit(1);
    }

    retcode = read_reply();
    if (retcode == 221) {
      /* If command was quit, just exit */
      print_reply(221);
      break;
    }

    if (retcode == 502) {
      // If invalid command, show error message
      printf("%d Invalid command.\n", retcode);
    } else {
      // Command is valid (RC = 200), process command

      // open data connection
      if ((data_sock = ftclient_open_conn(sock_control)) < 0) {
        perror("Error opening socket for data connection");
        exit(1);
      }

      // execute command
      if (strcmp(cmd.code, "LIST") == 0) {
        ftclient_list(data_sock, sock_control);
      } else if (strcmp(cmd.code, "RETR") == 0) {
        // wait for reply (is file valid)
        if (read_reply() == 550) {
          print_reply(550);
          close(data_sock);
          continue;
        }
        ftclient_get(data_sock, sock_control, cmd.arg);
        print_reply(read_reply());
      } else if (strcmp(cmd.code, "STOR") == 0) {
        ftclient_put(data_sock, sock_control, cmd.arg);
        print_reply(read_reply());
      }
      close(data_sock);
    }

  } // loop back to get more user input

  // Close the socket (control connection)
  close(sock_control);
  return 0;
}
