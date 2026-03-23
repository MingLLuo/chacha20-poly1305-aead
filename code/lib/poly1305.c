#include "poly1305.h"

void le_bytes_to_num(mpz_t result, const uint8_t* bytes, size_t size) {
  mpz_set_ui(result, 0);
  for (size_t i = 0; i < size; i++) {
    mpz_mul_ui(result, result, 256);
    mpz_add_ui(result, result, bytes[size - 1 - i]);
  }
}

void num_to_le_bytes(uint8_t* result, const mpz_t src, size_t size) {
  mpz_t q, r;
  mpz_inits(q, r, NULL);
  mpz_set(q, src);
  for (size_t i = 0; i < size; i++) {
    mpz_fdiv_qr_ui(q, r, q, 256);
    result[i] = mpz_get_ui(r);
  }
  mpz_clears(q, r, NULL);
}

void hex_to_bytes(uint8_t* bytes, const char* hex, size_t hex_size) {
  for (size_t i = 0; i < hex_size / 2; i++) {
    unsigned int byte;
    sscanf(hex + 2 * i, "%2x", &byte);
    bytes[i] = (uint8_t)byte;
  }
}

void bytes_to_hex(char* hex, const uint8_t* bytes, size_t size) {
  for (size_t i = 0; i < size; i++) {
    sprintf(hex + 2 * i, "%02x", bytes[i]);
  }
  hex[size * 2] = '\0';
}

void clamp(uint8_t r[16]) {
  r[3] &= 15;
  r[7] &= 15;
  r[11] &= 15;
  r[15] &= 15;
  r[4] &= 252;
  r[8] &= 252;
  r[12] &= 252;
}

void poly1305(uint8_t mac[16], const uint8_t* message, size_t message_size,
              const uint8_t key[32]) {
  mpz_t a, p, r_num, s_num, n;
  mpz_inits(a, p, r_num, s_num, n, NULL);
  mpz_set_ui(a, 0);
  mpz_ui_pow_ui(p, 2, 130);
  mpz_sub_ui(p, p, 5);

  uint8_t r[16];
  memcpy(r, key, 16);
  clamp(r);
  le_bytes_to_num(r_num, r, 16);

  uint8_t s[16];
  memcpy(s, key + 16, 16);
  le_bytes_to_num(s_num, s, 16);

  size_t offset = 0;
  while (offset < message_size) {
    size_t block_size =
        (message_size - offset > 16) ? 16 : (message_size - offset);
    uint8_t tmp[17];
    memset(tmp, 0, 17);
    memcpy(tmp, message + offset, block_size);
    tmp[block_size] = 1;
    le_bytes_to_num(n, tmp, block_size + 1);
    mpz_add(a, a, n);
    mpz_mul(a, r_num, a);
    mpz_mod(a, a, p);
    offset += block_size;
  }
  mpz_add(a, a, s_num);

  num_to_le_bytes(mac, a, 16);
  mpz_clears(a, p, r_num, s_num, n, NULL);
}
