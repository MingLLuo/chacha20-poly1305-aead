#include <stdio.h>
#include <stdlib.h>

#include "lib/aead.h"
#include "lib/poly1305.h"

int main(int argc, char* argv[]) {
  if (argc < 6) {
    fprintf(stderr,
            "Usage: %s <key_file> <nonce> <aad_file> <plaintext_file> "
            "<ciphertext_file>\n",
            argv[0]);
    return 1;
  }

  uint8_t key[32];
  FILE* kfp = fopen(argv[1], "rb");
  if (!kfp) {
    fprintf(stderr, "Cannot open key file: %s\n", argv[1]);
    return 1;
  }
  fread(key, 1, 32, kfp);
  fclose(kfp);

  uint8_t nonce[12];
  hex_to_bytes(nonce, argv[2], 24);

  FILE* adfp = fopen(argv[3], "rb");
  if (!adfp) {
    fprintf(stderr, "Cannot open AD file: %s\n", argv[3]);
    return 1;
  }
  fseek(adfp, 0, SEEK_END);
  size_t aad_len = ftell(adfp);
  fseek(adfp, 0, SEEK_SET);
  uint8_t* aad = aad_len > 0 ? malloc(aad_len) : NULL;
  if (aad_len > 0) fread(aad, 1, aad_len, adfp);
  fclose(adfp);

  FILE* ptfp = fopen(argv[4], "rb");
  if (!ptfp) {
    fprintf(stderr, "Cannot open plaintext file: %s\n", argv[4]);
    free(aad);
    return 1;
  }
  fseek(ptfp, 0, SEEK_END);
  size_t pt_len = ftell(ptfp);
  fseek(ptfp, 0, SEEK_SET);
  uint8_t* plaintext = pt_len > 0 ? malloc(pt_len) : NULL;
  if (pt_len > 0) fread(plaintext, 1, pt_len, ptfp);
  fclose(ptfp);

  uint8_t* ciphertext = pt_len > 0 ? malloc(pt_len) : NULL;
  uint8_t tag[16];
  chacha20_aead_encrypt(ciphertext, aad, aad_len, plaintext, pt_len, key, nonce,
                        tag);

  FILE* ctfp = fopen(argv[5], "wb");
  if (!ctfp) {
    fprintf(stderr, "Cannot open ciphertext file: %s\n", argv[5]);
    free(aad);
    free(plaintext);
    free(ciphertext);
    return 1;
  }
  if (pt_len > 0) fwrite(ciphertext, 1, pt_len, ctfp);
  fclose(ctfp);

  char tag_hex[33];
  bytes_to_hex(tag_hex, tag, 16);
  printf("%s\n", tag_hex);

  free(aad);
  free(plaintext);
  free(ciphertext);
  return 0;
}
