#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "lib/chacha20.h"
#include "lib/poly1305.h"

int main(int argc, char* argv[]) {
  if (argc < 5) {
    fprintf(stderr, "Usage: %s <key_file> <nonce> <input_file> <output_file>\n",
            argv[0]);
    return 1;
  }

  char* key_filename = argv[1];
  char* nonce_hex = argv[2];
  char* input_filename = argv[3];
  char* output_filename = argv[4];

  uint8_t key[32];
  uint8_t nonce[12];
  hex_to_bytes(nonce, nonce_hex, 24);

  FILE* kfp = fopen(key_filename, "rb");
  if (!kfp) {
    fprintf(stderr, "Cannot open key file: %s\n", key_filename);
    return 1;
  }

  fread(key, 1, 32, kfp);
  fclose(kfp);

  FILE* ifp = fopen(input_filename, "rb");
  if (!ifp) {
    fprintf(stderr, "Cannoot open input file: %s\n", input_filename);
    return 1;
  }

  FILE* ofp = fopen(output_filename, "wb");
  if (!ofp) {
    fprintf(stderr, "Cannot open output file: %s\n", output_filename);
    fclose(ifp);
    return 1;
  }

  fseek(ifp, 0, SEEK_END);
  size_t input_length = ftell(ifp);
  fseek(ifp, 0, SEEK_SET);

  uint8_t* input_data = NULL;
  if (input_length > 0) {
    input_data = malloc(input_length);
    if (!input_data) {
      fprintf(stderr, "Memory allocation failed\n");
      fclose(ifp);
      fclose(ofp);
      return 1;
    }
    fread(input_data, 1, input_length, ifp);
  }
  fclose(ifp);
  uint8_t* output_data = malloc(input_length);
  if (!output_data) {
    fprintf(stderr, "Memory allocation failed\n");
    free(input_data);
    fclose(ofp);
    return 1;
  }

  chacha20_encrypt(output_data, key, nonce, 1, input_data, input_length);
  fwrite(output_data, 1, input_length, ofp);
  fclose(ofp);
  free(output_data);
  free(input_data);
  return 0;
}