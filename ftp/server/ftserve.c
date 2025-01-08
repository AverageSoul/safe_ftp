#include "ftserve.h"
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#include "ecdh/ecdh.h"
#include "ecdh/ecdh_protocol.h"
#include "ecdsa/ecdsa.h"
#include "sha256/sha256.h"
const char root_path[] = "./uploads/";
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
void ftserve_retr(int sock_control, int sock_data, char *filename) {
  FILE *fd = NULL;
  char data[MAXSIZE];
  size_t num_read;

  fd = fopen(filename, "r");

  if (!fd) {
    // send error code (550 Requested action not taken)
    send_response(sock_control, 550);

  } else {
    // send okay (150 File status okay)
    send_response(sock_control, 150);

    do {
      num_read = fread(data, 1, MAXSIZE, fd);

      if (num_read < 0) {
        printf("error in fread()\n");
      }

      // send block
      if (send(sock_data, data, num_read, 0) < 0)
        perror("error sending file\n");

    } while (num_read > 0);

    // send message: 226: closing conn, file transfer successful
    send_response(sock_control, 226);

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

/**
 * Log in connected client
 */
int ftserve_login(int sock_control) {
  char buf[MAXSIZE];
  char user[MAXSIZE];
  char pass[MAXSIZE];
  memset(user, 0, MAXSIZE);
  memset(pass, 0, MAXSIZE);
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

  // tell client we're ready for password
  send_response(sock_control, 331);

  // Wait to recieve password
  memset(buf, 0, MAXSIZE);
  if ((recv_data(sock_control, buf, sizeof(buf))) == -1) {
    perror("recv error\n");
    exit(1);
  }

  i = 5;
  n = 0;
  while (buf[i] != 0) {
    pass[n++] = buf[i++];
  }

  return (ftserve_check_user(user, pass));
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

/**
 * Child process handles connection to client
 */
void ftserve_process(int sock_control) {
  int sock_data;
  char cmd[5];
  char arg[MAXSIZE];

  // Send welcome message
  send_response(sock_control, 220);

  // Authenticate user
  /*
        if (ftserve_login(sock_control) == 1) {
                send_response(sock_control, 230);
        } else {
                send_response(sock_control, 430);
                exit(0);
        }
  */

  // TODO: Sign
  // TODO:: key exchange

  ECurve curve;
  ec_init_curve(&curve);

  // 设置曲线参数
  mpz_set_str(
      curve.p,
      "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16);
  mpz_set_ui(curve.a, 0);
  mpz_set_ui(curve.b, 7);
  mpz_set_str(
      curve.n,
      "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);

  // 设置基点G
  mpz_set_str(
      curve.G.x,
      "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16);
  mpz_set_str(
      curve.G.y,
      "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16);
  curve.G.infinity = 0;

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

  unsigned char buf[512];
  size_t length = 67; // TODO: calc this

  if (recv(sock_control, buf, length, 0) < 0) {
    perror("exchange key: recv key error\n");
    return;
  }

  deserialize_ecpoint(&bob_public, buf, length);

  // FIXME: receive failed
  gmp_printf("client public: %Zx %Zx\n", bob_public.x, bob_public.y);

  serialize_ecpoint(&alice_public, buf, &length);

  if (send(sock_control, buf, length, 0) < 0) {
    close(sock_control);
    printf("exchange key: send public failed\n");
    exit(1);
  }
  printf("computing shared secret...\n");
  compute_shared_secret(alice_shared, &bob_public, alice_private, &curve);
  printf("key exchanged successfully\n");

  // 验证共享密钥是否相同
  gmp_printf("Shared secret: %Zx\n", alice_shared);
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
        ftserve_retr(sock_control, sock_data, arg);
      } else if (strcmp(cmd, "STOR") == 0) { // Do put <filename>
        ftserve_put(sock_control, sock_data, arg);
      }

      // Close data connection
      close(sock_data);
    }
  }
}
/**
 * Receive file specified in filename over data connection, sending
 * control message over control connection
 */

// TODO: Decrypt
// TODO: Check the sign
void ftserve_put(int sock_control, int sock_data, char *filename) {
  FILE *fd = NULL;
  char data[MAXSIZE];
  char filepath[MAXSIZE + 10];
  strcpy(filepath, root_path);

  int size;

  if (strchr(filename, '/')) {
    send_response(sock_control, 550);
    return;
  }
  strncat(filepath, filename, 512);
  fd = fopen(filename, "w");

  if (!fd) {
    // send error code (550 Requested action not taken)
    send_response(sock_control, 550);
  } else {
    // send okay (150 File status okay)
    send_response(sock_control, 150);

    while ((size = recv(sock_data, data, MAXSIZE, 0)) > 0) {
      fwrite(data, 1, size, fd);
    }

    // send message: 226: closing conn, file transfer successful
    send_response(sock_control, 226);

    fclose(fd);
  }
}
