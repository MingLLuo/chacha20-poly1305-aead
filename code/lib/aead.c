#include "aead.h"

#include <stdlib.h>
#include <string.h>

#include "chacha20.h"
#include "poly1305.h"

static size_t pad16(size_t len) { return (16 - (len % 16)) % 16; }

void poly1305_key_gen(uint8_t otk[32], const uint8_t key[32],
                      const uint8_t nonce[12]) {
  uint8_t block[64];
  chacha20_block(block, key, 0, nonce);
  memcpy(otk, block, 32);
}

static void compute_aead_tag(uint8_t tag[16], const uint8_t* aad,
                             size_t aad_len, const uint8_t* ciphertext,
                             size_t ct_len, const uint8_t otk[32]) {
  size_t aad_pad = pad16(aad_len);
  size_t ct_pad = pad16(ct_len);
  size_t mac_data_len = aad_len + aad_pad + ct_len + ct_pad + 16;

  uint8_t* mac_data = malloc(mac_data_len * sizeof(uint8_t));
  size_t offset = 0;

  // aad | pad16(aad)
  if (aad_len > 0) memcpy(mac_data + offset, aad, aad_len);
  offset += aad_len + aad_pad;

  // ciphertext | pad16(ciphertext)
  if (ct_len > 0) memcpy(mac_data + offset, ciphertext, ct_len);
  offset += ct_len + ct_pad;

  // num_to_8_le_bytes(aad.length) | num_to_8_le_bytes(ciphertext.length)
  for (int i = 0; i < 8; i++)
    mac_data[offset + i] = (aad_len >> (8 * i)) & 0xff;
  for (int i = 0; i < 8; i++)
    mac_data[offset + 8 + i] = (ct_len >> (8 * i)) & 0xff;

  poly1305(tag, mac_data, mac_data_len, otk);
  free(mac_data);
}

void chacha20_aead_encrypt(uint8_t* ciphertext, const uint8_t* aad,
                           size_t aad_len, const uint8_t* plaintext,
                           size_t pt_len, const uint8_t key[32],
                           const uint8_t nonce[12], uint8_t tag[16]) {
  uint8_t otk[32];
  poly1305_key_gen(otk, key, nonce);
  chacha20_encrypt(ciphertext, key, nonce, 1, plaintext, pt_len);
  compute_aead_tag(tag, aad, aad_len, ciphertext, pt_len, otk);
}

int chacha20_aead_decrypt(uint8_t* plaintext, const uint8_t* aad,
                          size_t aad_len, const uint8_t* ciphertext,
                          size_t ct_len, const uint8_t key[32],
                          const uint8_t nonce[12],
                          const uint8_t expected_tag[16]) {
  uint8_t otk[32], computed_tag[16];
  poly1305_key_gen(otk, key, nonce);
  compute_aead_tag(computed_tag, aad, aad_len, ciphertext, ct_len, otk);

  for (int i = 0; i < 16; i++)
    if (computed_tag[i] != expected_tag[i]) {
      return 0;
    }

  chacha20_encrypt(plaintext, key, nonce, 1, ciphertext, ct_len);
  return 1;
}
