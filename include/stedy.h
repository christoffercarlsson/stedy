#ifndef STEDY_H
#define STEDY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void stedy_blake2b512(const uint8_t *message, const size_t message_size,
                      uint8_t *digest);

void stedy_blake2b512_init(uint8_t *state, const uint8_t *key,
                           const size_t key_size);

void stedy_blake2b512_update(uint8_t *state, const uint8_t *message,
                             const size_t message_size);

void stedy_blake2b512_final(const uint8_t *state, uint8_t *digest);

bool stedy_blake2b512_final_verify(const uint8_t *state, const uint8_t *code);

size_t stedy_blake2b512_state_size();

#ifdef __cplusplus
}
#endif

#endif
