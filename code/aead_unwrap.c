#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lib/aead.h"
#include "lib/poly1305.h"

int main(int argc, char* argv[]) {
  if (argc < 6) {
    fprintf(stderr,
            "Usage: %s <key_file> <nonce> <aad_file> <ciphertext_file> <tag>\n",
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

  uint8_t nonce[12], expected_tag[16];
  hex_to_bytes(nonce, argv[2], 24);
  if (strlen(argv[5]) != 32) {
    fprintf(stderr, "Tag must be 32 hex characters (16 bytes)\n");
    return 1;
  }
  hex_to_bytes(expected_tag, argv[5], 32);

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

  FILE* ctfp = fopen(argv[4], "rb");
  if (!ctfp) {
    fprintf(stderr, "Cannot open ciphertext file: %s\n", argv[4]);
    free(aad);
    return 1;
  }
  fseek(ctfp, 0, SEEK_END);
  size_t ct_len = ftell(ctfp);
  fseek(ctfp, 0, SEEK_SET);
  uint8_t* ciphertext = ct_len > 0 ? malloc(ct_len) : NULL;
  if (ct_len > 0) fread(ciphertext, 1, ct_len, ctfp);
  fclose(ctfp);

  uint8_t* plaintext = ct_len > 0 ? malloc(ct_len) : NULL;
  int valid = chacha20_aead_decrypt(plaintext, aad, aad_len, ciphertext, ct_len,
                                    key, nonce, expected_tag);

  if (!valid) {
    free(aad);
    free(ciphertext);
    free(plaintext);
    return 1;
  }

  if (ct_len > 0) fwrite(plaintext, 1, ct_len, stdout);

  free(aad);
  free(ciphertext);
  free(plaintext);
  return 0;
}
