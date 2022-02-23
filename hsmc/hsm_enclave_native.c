/*
 * Copyright 2022 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

// This is a simple-as-possible, crash-on-any-failure local process that
// exposes HsmEnclave on a socket.  It accepts only a single client connection
// at once, binds to 127.0.0.1, and chooses its own port on startup.

#include <stdio.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "hsm_enclave.h"
#include "error.h"

unsigned char command_buf[256<<10];

#define FAIL_IF_ERR(x) do { \
  error_t err = (x); \
  if (err != err_SUCCESS) { \
    LOG_ERR(err); \
    exit(1); \
  } \
} while (0)

error_t read_all(int fd, unsigned char* buf, size_t sz) {
  size_t done = 0;
  while (sz > done) {
    int got = read(fd, buf+done, sz-done);
    if (got < 0) {
      perror("read");
      exit(1);
    }
    if (got == 0) {
      return ERR("EOF");
    }
    done += got;
  }
  return err_SUCCESS;
}

error_t write_all(int fd, unsigned char* buf, size_t sz) {
  size_t done = 0;
  while (sz > done) {
    int got = write(fd, buf+done, sz-done);
    if (got < 0) {
      perror("write");
      exit(1);
    }
    if (got == 0) {
      return ERR("EOF");
    }
    done += got;
  }
  return err_SUCCESS;
}

static void serve_to_socket(int fd) {
  hsm_enclave_t* os;
  FAIL_IF_ERR(hsm_enclave_new(&os));

  while (1) {
    unsigned char len_buf[4];
    FAIL_IF_ERR(read_all(fd, len_buf, sizeof(len_buf)));
    uint32_t buf_len =
        (((uint32_t)len_buf[0]) << 24) |
        (((uint32_t)len_buf[1]) << 16) |
        (((uint32_t)len_buf[2]) <<  8) |
        (((uint32_t)len_buf[3]) <<  0);
    if (buf_len == 0 || buf_len > sizeof(command_buf)) {
      fprintf(stderr, "invalid buf len %d\n", buf_len);
      exit(1);
    }
    FAIL_IF_ERR(read_all(fd, command_buf, buf_len));
    command_t* out = hsm_enclave_handle_command(os, command_buf, buf_len);
    buf_len = command_total_size(out);
    len_buf[0] = buf_len >> 24;
    len_buf[1] = buf_len >> 16;
    len_buf[2] = buf_len >>  8;
    len_buf[3] = buf_len >>  0;
    FAIL_IF_ERR(write_all(fd, len_buf, sizeof(len_buf)));
    FAIL_IF_ERR(write_all(fd, out, buf_len));
    command_free(out);
  }
}

int main(int argc, char** argv) {
  int server_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (server_fd <= 0) {
    perror("socket"); exit(1);
  }

  struct sockaddr_in addr;
  addr.sin_family = AF_INET;
  addr.sin_port = 0;
  addr.sin_addr.s_addr = inet_addr("127.0.0.1");
  memset(addr.sin_zero, 0, sizeof(addr.sin_zero));
  if (0 > bind(server_fd, (struct sockaddr*)&addr, sizeof(addr))) {
    perror("bind"); exit(1);
  }

  if (0 > listen(server_fd, 1)) {
    perror("listen"); exit(1);
  }

  struct sockaddr_in bound;
  socklen_t bound_len = sizeof(bound);
  if (0 > getsockname(server_fd, (struct sockaddr*)&bound, &bound_len)) {
    perror("getsockname"); exit(1);
  }
  printf("Listening on 127.0.0.1:%d\n", ntohs(bound.sin_port));
  fflush(stdout);  // Make sure Java gets that message, since it blocks on it.

  struct sockaddr_in client;
  socklen_t client_len = sizeof(client);
  int client_fd = accept(server_fd, (struct sockaddr*)&client, &client_len);
  if (0 > client_len) {
    perror("accept"); exit(1);
  }
  printf("Accepted from client port %d\n", ntohs(client.sin_port));
  serve_to_socket(client_fd);
  return 1;
}
