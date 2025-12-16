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

void stedy_hkdf_sha256(const uint8_t *ikm, const size_t ikm_size,
                       const uint8_t *salt, const size_t salt_size,
                       const uint8_t *info, const size_t info_size,
                       uint8_t *okm, const size_t okm_size);

void stedy_hkdf_sha512(const uint8_t *ikm, const size_t ikm_size,
                       const uint8_t *salt, const size_t salt_size,
                       const uint8_t *info, const size_t info_size,
                       uint8_t *okm, const size_t okm_size);

void stedy_hmac_sha1(const uint8_t *key, const size_t key_size,
                     const uint8_t *message, const size_t message_size,
                     uint8_t *code);

bool stedy_hmac_sha1_verify(const uint8_t *key, const size_t key_size,
                            const uint8_t *message, const size_t message_size,
                            const uint8_t *code);

void stedy_hmac_sha1_init(uint8_t *state, const uint8_t *key,
                          const size_t key_size);

void stedy_hmac_sha1_update(uint8_t *state, const uint8_t *message,
                            const size_t message_size);

void stedy_hmac_sha1_final(const uint8_t *state, uint8_t *code);

bool stedy_hmac_sha1_final_verify(const uint8_t *state, const uint8_t *code);

size_t stedy_hmac_sha1_state_size();

void stedy_hmac_sha256(const uint8_t *key, const size_t key_size,
                       const uint8_t *message, const size_t message_size,
                       uint8_t *code);

bool stedy_hmac_sha256_verify(const uint8_t *key, const size_t key_size,
                              const uint8_t *message, const size_t message_size,
                              const uint8_t *code);

void stedy_hmac_sha256_init(uint8_t *state, const uint8_t *key,
                            const size_t key_size);

void stedy_hmac_sha256_update(uint8_t *state, const uint8_t *message,
                              const size_t message_size);

void stedy_hmac_sha256_final(const uint8_t *state, uint8_t *code);

bool stedy_hmac_sha256_final_verify(const uint8_t *state, const uint8_t *code);

size_t stedy_hmac_sha256_state_size();

void stedy_hmac_sha512(const uint8_t *key, const size_t key_size,
                       const uint8_t *message, const size_t message_size,
                       uint8_t *code);

bool stedy_hmac_sha512_verify(const uint8_t *key, const size_t key_size,
                              const uint8_t *message, const size_t message_size,
                              const uint8_t *code);

void stedy_hmac_sha512_init(uint8_t *state, const uint8_t *key,
                            const size_t key_size);

void stedy_hmac_sha512_update(uint8_t *state, const uint8_t *message,
                              const size_t message_size);

void stedy_hmac_sha512_final(const uint8_t *state, uint8_t *code);

bool stedy_hmac_sha512_final_verify(const uint8_t *state, const uint8_t *code);

size_t stedy_hmac_sha512_state_size();

size_t stedy_pad(uint8_t *unpadded, const size_t unpadded_size,
                 const size_t block_size);

size_t stedy_unpad(const uint8_t *padded, const size_t padded_size,
                   const size_t block_size);

void stedy_pbkdf2_hmac_sha256(const uint8_t *password,
                              const size_t password_size, const uint8_t *salt,
                              const size_t salt_size, const size_t iterations,
                              uint8_t *output, const size_t output_size);

void stedy_pbkdf2_hmac_sha512(const uint8_t *password,
                              const size_t password_size, const uint8_t *salt,
                              const size_t salt_size, const size_t iterations,
                              uint8_t *output, const size_t output_size);

void stedy_rng_init(uint8_t *state, const uint8_t *seed);

void stedy_rng_fill(uint8_t *state, uint8_t *bytes, const size_t size);

uint32_t stedy_rng_next_u32(uint8_t *state);

uint64_t stedy_rng_next_u64(uint8_t *state);

size_t stedy_rng_state_size();

void stedy_sha256(const uint8_t *message, const size_t message_size,
                  uint8_t *digest);

void stedy_sha256_init(uint8_t *state);

void stedy_sha256_update(uint8_t *state, const uint8_t *message,
                         const size_t message_size);

void stedy_sha256_final(const uint8_t *state, uint8_t *digest);

size_t stedy_sha256_state_size();

void stedy_sha512(const uint8_t *message, const size_t message_size,
                  uint8_t *digest);

void stedy_sha512_init(uint8_t *state);

void stedy_sha512_update(uint8_t *state, const uint8_t *message,
                         const size_t message_size);

void stedy_sha512_final(const uint8_t *state, uint8_t *digest);

size_t stedy_sha512_state_size();

#ifdef __cplusplus
}
#endif

#endif
