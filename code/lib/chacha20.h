#ifndef CHACHA20_H
#define CHACHA20_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>
void quarter_round(uint32_t* a, uint32_t* b, uint32_t* c, uint32_t* d);
void chacha20_block(uint8_t output[64], const uint8_t key[32], uint32_t counter,
                    const uint8_t nonce[12]);
void chacha20_encrypt(uint8_t* ciphertext, const uint8_t key[32],
                      const uint8_t nonce[12], uint32_t counter,
                      const uint8_t* plaintext, size_t length);

#endif