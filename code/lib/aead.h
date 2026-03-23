#ifndef AEAD_H
#define AEAD_H

#include <stddef.h>
#include <stdint.h>

void poly1305_key_gen(uint8_t otk[32], const uint8_t key[32],
                      const uint8_t nonce[12]);

void chacha20_aead_encrypt(uint8_t* ciphertext, const uint8_t* aad,
                            size_t aad_len, const uint8_t* plaintext,
                            size_t pt_len, const uint8_t key[32],
                            const uint8_t nonce[12], uint8_t tag[16]);

int chacha20_aead_decrypt(uint8_t* plaintext, const uint8_t* aad,
                          size_t aad_len, const uint8_t* ciphertext,
                          size_t ct_len, const uint8_t key[32],
                          const uint8_t nonce[12],
                          const uint8_t expected_tag[16]);

#endif
