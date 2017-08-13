#ifndef AES_H
#define AES_H

#include <stdint.h>

void aes_encrypt(uint8_t *out, uint8_t const *in, uint8_t const *key);
void aes_decrypt(uint8_t *out, uint8_t const *in, uint8_t const *key);

#endif // AES_H
