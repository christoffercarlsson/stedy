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

void stedy_blake2s256(const uint8_t *message, const size_t message_size,
                      uint8_t *digest);

void stedy_blake2s256_init(uint8_t *state, const uint8_t *key,
                           const size_t key_size);

void stedy_blake2s256_update(uint8_t *state, const uint8_t *message,
                             const size_t message_size);

void stedy_blake2s256_final(const uint8_t *state, uint8_t *digest);

bool stedy_blake2s256_final_verify(const uint8_t *state, const uint8_t *code);

size_t stedy_blake2s256_state_size();

void stedy_chacha20poly1305_encrypt(const uint8_t *key, const uint8_t *nonce,
                                    const uint8_t *aad, const size_t aad_size,
                                    uint8_t *message, const size_t message_size,
                                    uint8_t *tag);

bool stedy_chacha20poly1305_decrypt(const uint8_t *key, const uint8_t *nonce,
                                    const uint8_t *aad, const size_t aad_size,
                                    uint8_t *message, const size_t message_size,
                                    const uint8_t *tag);

void stedy_chacha20poly1305_generate_key(const uint8_t *seed, uint8_t *key);

bool stedy_chacha20poly1305_increment_nonce(uint8_t *nonce);

void stedy_xchacha20poly1305_encrypt(const uint8_t *key, const uint8_t *nonce,
                                     const uint8_t *aad, const size_t aad_size,
                                     uint8_t *message,
                                     const size_t message_size, uint8_t *tag);

bool stedy_xchacha20poly1305_decrypt(const uint8_t *key, const uint8_t *nonce,
                                     const uint8_t *aad, const size_t aad_size,
                                     uint8_t *message,
                                     const size_t message_size,
                                     const uint8_t *tag);

void stedy_xchacha20poly1305_generate_key(const uint8_t *seed, uint8_t *key);

bool stedy_xchacha20poly1305_increment_nonce(uint8_t *nonce);

void stedy_xchacha20poly1305_generate_nonce(const uint8_t *seed,
                                            uint8_t *nonce);

void stedy_ed25519_generate_key_pair(const uint8_t *seed, uint8_t *private_key,
                                     uint8_t *public_key);

void stedy_ed25519_public_key(const uint8_t *private_key, uint8_t *public_key);

void stedy_ed25519_sign(const uint8_t *private_key, const uint8_t *message,
                        const size_t message_size, uint8_t *signature);

bool stedy_ed25519_verify(const uint8_t *message, const size_t message_size,
                          const uint8_t *public_key, const uint8_t *signature);

#ifdef __cplusplus
}
#endif

#endif
