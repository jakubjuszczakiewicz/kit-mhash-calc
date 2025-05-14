/* Copyright (c) 2025 Krypto-IT Jakub Juszczakiewicz
 * All rights reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <semaphore.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include "version.h"

#define HASH_FUNCS_COUNT 11
#ifndef BUFFER_SIZE
#define BUFFER_SIZE (10 * 1024 * 1024)
#endif

typedef const EVP_MD *(*initiator_t)();

struct {
  unsigned int use_md5       : 1;
  unsigned int use_sha1      : 1;
  unsigned int use_sha224    : 1;
  unsigned int use_sha256    : 1;
  unsigned int use_sha384    : 1;
  unsigned int use_sha512    : 1;
  unsigned int use_sha3_224  : 1;
  unsigned int use_sha3_256  : 1;
  unsigned int use_sha3_384  : 1;
  unsigned int use_sha3_512  : 1;
  unsigned int use_ripemd160 : 1;
} config;
size_t config_count;

struct thread_config
{
  initiator_t initiator;
  size_t output_size;
  char * output_buffer;
  const char * name;
  EVP_MD_CTX * mdctx;
} thread_configs[HASH_FUNCS_COUNT];

char * buffer_1 = NULL;
size_t buffer_1_fill = 0;
sem_t buffer_1_sem;
sem_t buffer_1_sem_out;
sem_t buffer_1_sem_in;

char * buffer_2 = NULL;
size_t buffer_2_fill = 0;
sem_t buffer_2_sem;
sem_t buffer_2_sem_out;
sem_t buffer_2_sem_in;

pthread_t threads[HASH_FUNCS_COUNT + 2];

void init_thread_config(struct thread_config * output, initiator_t initiator,
    const char * name)
{
  output->initiator = initiator;
  output->output_size = EVP_MD_size(initiator());
  output->output_buffer = calloc(output->output_size, 1);
  output->name = name;
  output->mdctx = EVP_MD_CTX_new();
  EVP_DigestInit_ex(output->mdctx, output->initiator(), NULL);
}

void free_thread_config(struct thread_config * output)
{
  unsigned int output_size = output->output_size;
  EVP_DigestFinal_ex(output->mdctx, output->output_buffer, &output_size);
  EVP_MD_CTX_free(output->mdctx);

  fprintf(stderr, "%s: ", output->name);
  for (size_t j = 0; j < output->output_size; j++)
     fprintf(stderr, "%02hhx", output->output_buffer[j]);
  fprintf(stderr, "\n");

  free(output->output_buffer);
}

void free_thread_configs(size_t threads_count)
{
  for (size_t i = 0; i < threads_count; i++)
    free_thread_config(&thread_configs[i]);
}

void usage(const char * argv0)
{
  fprintf(stderr, "kit-mhash-calc %s\n", version_str);
  fprintf(stderr, "Usage: %s [--md5] [--sha1] [--sha224] [--sha256] ", argv0);
  fprintf(stderr, "[--sha384] [--sha512] [--sha3_224] [--sha3_256] ");
  fprintf(stderr, "[--sha3_384] [--sha3_512] [--ripemd160]\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "input: stdin\n");
  fprintf(stderr, "output: stdout (passthough)\n");
  fprintf(stderr, "result: stderr\n");
}

void parse_argc(int argc, char * argv[])
{
  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--md5") == 0) {
      config.use_md5 = 1;
      continue;
    }
    if (strcmp(argv[i], "--sha1") == 0) {
      config.use_sha1 = 1;
      continue;
    }
    if (strcmp(argv[i], "--sha224") == 0) {
      config.use_sha224 = 1;
      continue;
    }
    if (strcmp(argv[i], "--sha256") == 0) {
      config.use_sha256 = 1;
      continue;
    }
    if (strcmp(argv[i], "--sha384") == 0) {
      config.use_sha384 = 1;
      continue;
    }
    if (strcmp(argv[i], "--sha512") == 0) {
      config.use_sha512 = 1;
      continue;
    }
    if (strcmp(argv[i], "--sha3_224") == 0) {
      config.use_sha3_224 = 1;
      continue;
    }
    if (strcmp(argv[i], "--sha3_256") == 0) {
      config.use_sha3_256 = 1;
      continue;
    }
    if (strcmp(argv[i], "--sha3_384") == 0) {
      config.use_sha3_384 = 1;
      continue;
    }
    if (strcmp(argv[i], "--sha3_512") == 0) {
      config.use_sha3_512 = 1;
      continue;
    }
    if (strcmp(argv[i], "--ripemd160") == 0) {
      config.use_ripemd160 = 1;
      continue;
    }
    usage(argv[0]);
    if (strcmp(argv[i], "--help") == 0)
      exit(0);
    exit(1);
  }
}

size_t init_threads(void)
{
  size_t threads_count = 0;
  if (config.use_md5)
    init_thread_config(&thread_configs[threads_count++], EVP_md5, "MD5");

  if (config.use_sha1)
    init_thread_config(&thread_configs[threads_count++], EVP_sha1, "SHA1");

  if (config.use_sha224)
    init_thread_config(&thread_configs[threads_count++], EVP_sha224, "SHA224");
  if (config.use_sha256)
    init_thread_config(&thread_configs[threads_count++], EVP_sha256, "SHA256");
  if (config.use_sha384)
    init_thread_config(&thread_configs[threads_count++], EVP_sha384, "SHA384");
  if (config.use_sha512)
    init_thread_config(&thread_configs[threads_count++], EVP_sha512, "SHA512");

  if (config.use_sha3_224)
    init_thread_config(&thread_configs[threads_count++], EVP_sha3_224,
        "SHA3-224");
  if (config.use_sha3_256)
    init_thread_config(&thread_configs[threads_count++], EVP_sha3_256,
        "SHA3-256");
  if (config.use_sha3_384)
    init_thread_config(&thread_configs[threads_count++], EVP_sha3_384,
        "SHA3-384");
  if (config.use_sha3_512)
    init_thread_config(&thread_configs[threads_count++], EVP_sha3_512,
        "SHA3-512");

  if (config.use_ripemd160)
    init_thread_config(&thread_configs[threads_count++], EVP_ripemd160,
        "RIPEMD160");

  return threads_count;
}

int thread_subworker(char * buffer, size_t * buffer_fill, sem_t * sem,
    sem_t * sem_out, EVP_MD_CTX * mdctx)
{
  while(sem_wait(sem));

  size_t fill = *buffer_fill;

  if (fill > 0)
    EVP_DigestUpdate(mdctx, buffer, fill);

  while(sem_post(sem_out));

  return fill > 0;
}

void * thread_worker(void * data_void)
{
  struct thread_config * data = (struct thread_config *)data_void;

  while (thread_subworker(buffer_1, &buffer_1_fill, &buffer_1_sem,
        &buffer_1_sem_out, data->mdctx) &&
    thread_subworker(buffer_2, &buffer_2_fill, &buffer_2_sem,
        &buffer_2_sem_out, data->mdctx));

  return NULL;
}

int reader_subworker(char * buffer, size_t * buffer_fill, sem_t * buffer_sem_in,
    sem_t * buffer_sem, size_t threads_count)
{
  for (size_t i = 0; i < threads_count; i++)
    while (sem_wait(buffer_sem_in));

  ssize_t r = read(STDIN_FILENO, buffer, BUFFER_SIZE);
  if (r <= 0)
    *buffer_fill = 0;
  else
    *buffer_fill = r;

  for (size_t i = 0; i < threads_count; i++)
    while(sem_post(buffer_sem));

  return r > 0;
}

void * thread_worker_reader(void * data_void)
{
  size_t * threads_count = (size_t *)data_void;

  while (reader_subworker(buffer_1, &buffer_1_fill, &buffer_1_sem_in,
      &buffer_1_sem, *threads_count) &&
         reader_subworker(buffer_2, &buffer_2_fill, &buffer_2_sem_in,
      &buffer_2_sem, *threads_count));

  return NULL;
}

int writer_subworker(char * buffer, size_t * buffer_fill,
    sem_t * buffer_sem_out, sem_t * buffer_sem_in, size_t threads_count)
{
  for (size_t i = 0; i < threads_count; i++)
    while(sem_wait(buffer_sem_out));

  size_t for_write = *buffer_fill;
  char * buffer_ptr = buffer;

  while (for_write > 0) {
    ssize_t w = write(STDOUT_FILENO, buffer_ptr, for_write);
    if (w <= 0)
      break;
    buffer_ptr += w;
    for_write -= w;
  }

  int result = *buffer_fill > 0;

  for (size_t i = 0; i < threads_count; i++)
    while(sem_post(buffer_sem_in));

  return result;
}

void * thread_worker_writer(void * data_void)
{
  size_t * threads_count = (size_t *)data_void;

  while (writer_subworker(buffer_1, &buffer_1_fill, &buffer_1_sem_out,
      &buffer_1_sem_in, *threads_count) &&
         writer_subworker(buffer_2, &buffer_2_fill, &buffer_2_sem_out,
      &buffer_2_sem_in, *threads_count));

  return NULL;
}

void start_threads(size_t * threads_count)
{
  size_t i;
  for (i = 0; i < *threads_count; i++)
    pthread_create(&threads[i], NULL, thread_worker, &thread_configs[i]);

  pthread_create(&threads[i + 1], NULL, thread_worker_writer, threads_count);
  pthread_create(&threads[i + 2], NULL, thread_worker_reader, threads_count);
}

void join_threads(size_t threads_count)
{
  for (size_t i = 0; i < threads_count + 2; i++)
    pthread_join(threads[i], NULL);
}

int main(int argc, char * argv[])
{
  ERR_load_crypto_strings();
  OpenSSL_add_all_algorithms();

  parse_argc(argc, argv);
  config_count = init_threads();

  if (config_count == 0) {
    free_thread_configs(config_count);
    usage(argv[0]);
    return 2;
  }

  buffer_1 = malloc(BUFFER_SIZE);
  buffer_2 = malloc(BUFFER_SIZE);

  sem_init(&buffer_1_sem, 0, 0);
  sem_init(&buffer_1_sem_out, 0, 0);
  sem_init(&buffer_1_sem_in, 0, config_count);
  sem_init(&buffer_2_sem, 0, 0);
  sem_init(&buffer_2_sem_out, 0, 0);
  sem_init(&buffer_2_sem_in, 0, config_count);

  start_threads(&config_count);
  join_threads(config_count);

  sem_destroy(&buffer_1_sem);
  sem_destroy(&buffer_1_sem_out);
  sem_destroy(&buffer_1_sem_in);
  sem_destroy(&buffer_2_sem);
  sem_destroy(&buffer_2_sem_out);
  sem_destroy(&buffer_2_sem_in);

  free(buffer_1);
  free(buffer_2);
  free_thread_configs(config_count);

  EVP_cleanup();
  CRYPTO_cleanup_all_ex_data();
  ERR_free_strings();

  return 0;
}
