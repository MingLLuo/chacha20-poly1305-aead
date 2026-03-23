#ifndef POLY1305_H
#define POLY1305_H

#include <gmp.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

void hex_to_bytes(uint8_t* bytes, const char* hex, size_t hex_size);
void bytes_to_hex(char* hex, const uint8_t* bytes, size_t size);
void le_bytes_to_num(mpz_t result, const uint8_t* bytes, size_t size);
void num_to_le_bytes(uint8_t* result, const mpz_t src, size_t size);
void clamp(uint8_t r[16]);
void poly1305(uint8_t mac[16], const uint8_t* message, size_t message_size,
              const uint8_t key[32]);

#endif