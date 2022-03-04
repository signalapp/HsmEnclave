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
#include <semaphore.h>
#include <pthread.h>

#include "hsm_enclave.h"
#include "error.h"

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

////////////////////////////////////////////////////////////////////////////////
// To better emulate the HSM, which queues its input/output, we queue our own
// input/output with a simple 4-element queue.
////////////////////////////////////////////////////////////////////////////////

typedef struct {
  uint32_t len;
  unsigned char* buf;
} queue_element_t;

// must be power of 2
#define QUEUE_SIZE 4

typedef struct {
  sem_t has_space;
  sem_t has_elements;
  pthread_mutex_t mu;
  queue_element_t elements[QUEUE_SIZE];
  uint32_t read;
  uint32_t write;
} queue_t;

void queue_init(queue_t* q) {
  sem_init(&q->has_space, 0, QUEUE_SIZE);
  sem_init(&q->has_elements, 0, 0);
  pthread_mutex_init(&q->mu, NULL);
  q->read = 0;
  q->write = 0;
}

void queue_push(queue_t* q, unsigned char* buf, uint32_t len) {
  sem_wait(&q->has_space);
  pthread_mutex_lock(&q->mu);
  queue_element_t* qe = q->elements + (q->write++ % QUEUE_SIZE);
  qe->len = len;
  qe->buf = buf;
  pthread_mutex_unlock(&q->mu);
  sem_post(&q->has_elements);
}

void queue_pop(queue_t* q, unsigned char** buf, uint32_t* len) {
  sem_wait(&q->has_elements);
  pthread_mutex_lock(&q->mu);
  queue_element_t* qe = q->elements + (q->read++ % QUEUE_SIZE);
  *len = qe->len;
  *buf = qe->buf;
  pthread_mutex_unlock(&q->mu);
  sem_post(&q->has_space);
}

typedef struct {
  queue_t* q;
  int fd;
} queue_and_fd_t;

////////////////////////////////////////////////////////////////////////////////
// We have a dedicated thread for reading buffers from the client, and a
// separate dedicated thread for writing buffers to the client.

// Base max size on nCipher hard limit.
#define MAX_BUF_SIZE 262100

static void* read_thread(void* queue_and_fd) {
  queue_and_fd_t* qf = (queue_and_fd_t*) queue_and_fd;

  while (1) {
    unsigned char len_buf[4];
    FAIL_IF_ERR(read_all(qf->fd, len_buf, sizeof(len_buf)));
    uint32_t buf_len =
        (((uint32_t)len_buf[0]) << 24) |
        (((uint32_t)len_buf[1]) << 16) |
        (((uint32_t)len_buf[2]) <<  8) |
        (((uint32_t)len_buf[3]) <<  0);
    if (buf_len == 0 || buf_len > MAX_BUF_SIZE) {
      fprintf(stderr, "invalid buf len %d\n", buf_len);
      exit(1);
    }
    unsigned char* buf = (unsigned char*) calloc(buf_len, sizeof(unsigned char));
    FAIL_IF_ERR(read_all(qf->fd, buf, buf_len));
    queue_push(qf->q, buf, buf_len);
  }
}

static void* write_thread(void* queue_and_fd) {
  queue_and_fd_t* qf = (queue_and_fd_t*) queue_and_fd;

  unsigned char len_buf[4];
  while (1) {
    uint32_t buf_len;
    unsigned char* buf;
    queue_pop(qf->q, &buf, &buf_len);
    len_buf[0] = buf_len >> 24;
    len_buf[1] = buf_len >> 16;
    len_buf[2] = buf_len >>  8;
    len_buf[3] = buf_len >>  0;
    FAIL_IF_ERR(write_all(qf->fd, len_buf, sizeof(len_buf)));
    FAIL_IF_ERR(write_all(qf->fd, buf, buf_len));
    command_free((command_t*) buf);
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

  // Set up read/write threads/queues

  queue_t read_queue;
  queue_init(&read_queue);
  queue_t write_queue;
  queue_init(&write_queue);

  queue_and_fd_t qf_read;
  qf_read.fd = client_fd;
  qf_read.q = &read_queue;

  queue_and_fd_t qf_write;
  qf_write.fd = client_fd;
  qf_write.q = &write_queue;

  pthread_t read_thread_id;
  if (0 != pthread_create(&read_thread_id, NULL, &read_thread, &qf_read)) {
    fprintf(stderr, "Failed to start read thread\n");
    exit(1);
  }
  pthread_t write_thread_id;
  if (0 != pthread_create(&write_thread_id, NULL, &write_thread, &qf_write)) {
    fprintf(stderr, "Failed to start read thread\n");
    exit(1);
  }

  hsm_enclave_t* os;
  FAIL_IF_ERR(hsm_enclave_new(&os));

  // Read from read_queue, process, write to write_queue.

  while (1) {
    unsigned char* buf;
    uint32_t buf_len;
    queue_pop(&read_queue, &buf, &buf_len);
    command_t* cmd = hsm_enclave_handle_command(os, buf, buf_len);
    queue_push(&write_queue, cmd, command_total_size(cmd));
    free(buf);
  }

  return 1;
}
