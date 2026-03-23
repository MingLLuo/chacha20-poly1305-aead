#include "chacha20.h"

#define ROL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

void quarter_round(uint32_t* a, uint32_t* b, uint32_t* c, uint32_t* d) {
  *a += *b;
  *d ^= *a;
  *d = ROL32(*d, 16);
  *c += *d;
  *b ^= *c;
  *b = ROL32(*b, 12);
  *a += *b;
  *d ^= *a;
  *d = ROL32(*d, 8);
  *c += *d;
  *b ^= *c;
  *b = ROL32(*b, 7);
}

static void Qround(uint32_t state[16], int a, int b, int c, int d) {
  quarter_round(&state[a], &state[b], &state[c], &state[d]);
}

void chacha20_block(uint8_t output[64], const uint8_t key[32], uint32_t counter,
                    const uint8_t nonce[12]) {
  uint32_t state[16] = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574};
  memcpy(&state[4], key, 32);
  state[12] = counter;
  memcpy(&state[13], nonce, 12);

  uint32_t initial_state[16];
  memcpy(initial_state, state, sizeof(state));

  for (int i = 0; i < 10; i++) {
    Qround(state, 0, 4, 8, 12);
    Qround(state, 1, 5, 9, 13);
    Qround(state, 2, 6, 10, 14);
    Qround(state, 3, 7, 11, 15);
    Qround(state, 0, 5, 10, 15);
    Qround(state, 1, 6, 11, 12);
    Qround(state, 2, 7, 8, 13);
    Qround(state, 3, 4, 9, 14);
  }

  for (int i = 0; i < 16; i++) {
    state[i] += initial_state[i];
  }
  memcpy(output, state, 64);
}

void chacha20_encrypt(uint8_t* ciphertext, const uint8_t key[32],
                      const uint8_t nonce[12], uint32_t counter,
                      const uint8_t* plaintext, size_t length) {
  uint8_t keystream[64];
  size_t num_blocks = (length + 63) / 64;

  for (size_t j = 0; j < num_blocks; j++) {
    size_t block_len =
        (j == num_blocks - 1 && length % 64 != 0) ? (length % 64) : 64;
    chacha20_block(keystream, key, counter + j, nonce);
    for (size_t i = 0; i < block_len; i++) {
      ciphertext[j * 64 + i] = plaintext[j * 64 + i] ^ keystream[i];
    }
  }
}