#ifndef STEDY_H
#define STEDY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct alignas(8) stedy_blake2b512_state {
  uint8_t opaque[216];
} stedy_blake2b512_state;

void stedy_blake2b512(const uint8_t *message, const size_t message_size,
                      uint8_t *digest);

void stedy_blake2b512_init(stedy_blake2b512_state *state, const uint8_t *key,
                           const size_t key_size);

void stedy_blake2b512_update(stedy_blake2b512_state *state,
                             const uint8_t *message, const size_t message_size);

void stedy_blake2b512_final(const stedy_blake2b512_state *state,
                            uint8_t *digest);

bool stedy_blake2b512_final_verify(const stedy_blake2b512_state *state,
                                   const uint8_t *code);

typedef struct alignas(8) stedy_blake2s256_state {
  uint8_t opaque[112];
} stedy_blake2s256_state;

void stedy_blake2s256(const uint8_t *message, const size_t message_size,
                      uint8_t *digest);

void stedy_blake2s256_init(stedy_blake2s256_state *state, const uint8_t *key,
                           const size_t key_size);

void stedy_blake2s256_update(stedy_blake2s256_state *state,
                             const uint8_t *message, const size_t message_size);

void stedy_blake2s256_final(const stedy_blake2s256_state *state,
                            uint8_t *digest);

bool stedy_blake2s256_final_verify(const stedy_blake2s256_state *state,
                                   const uint8_t *code);

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

typedef struct alignas(8) stedy_hmac_sha1_state {
  uint8_t opaque[192];
} stedy_hmac_sha1_state;

void stedy_hmac_sha1(const uint8_t *key, const size_t key_size,
                     const uint8_t *message, const size_t message_size,
                     uint8_t *code);

bool stedy_hmac_sha1_verify(const uint8_t *key, const size_t key_size,
                            const uint8_t *message, const size_t message_size,
                            const uint8_t *code);

void stedy_hmac_sha1_init(stedy_hmac_sha1_state *state, const uint8_t *key,
                          const size_t key_size);

void stedy_hmac_sha1_update(stedy_hmac_sha1_state *state,
                            const uint8_t *message, const size_t message_size);

void stedy_hmac_sha1_final(const stedy_hmac_sha1_state *state, uint8_t *code);

bool stedy_hmac_sha1_final_verify(const stedy_hmac_sha1_state *state,
                                  const uint8_t *code);

typedef struct alignas(8) stedy_hmac_sha256_state {
  uint8_t opaque[224];
} stedy_hmac_sha256_state;

void stedy_hmac_sha256(const uint8_t *key, const size_t key_size,
                       const uint8_t *message, const size_t message_size,
                       uint8_t *code);

bool stedy_hmac_sha256_verify(const uint8_t *key, const size_t key_size,
                              const uint8_t *message, const size_t message_size,
                              const uint8_t *code);

void stedy_hmac_sha256_init(stedy_hmac_sha256_state *state, const uint8_t *key,
                            const size_t key_size);

void stedy_hmac_sha256_update(stedy_hmac_sha256_state *state,
                              const uint8_t *message,
                              const size_t message_size);

void stedy_hmac_sha256_final(const stedy_hmac_sha256_state *state,
                             uint8_t *code);

bool stedy_hmac_sha256_final_verify(const stedy_hmac_sha256_state *state,
                                    const uint8_t *code);

typedef struct alignas(8) stedy_hmac_sha512_state {
  uint8_t opaque[416];
} stedy_hmac_sha512_state;

void stedy_hmac_sha512(const uint8_t *key, const size_t key_size,
                       const uint8_t *message, const size_t message_size,
                       uint8_t *code);

bool stedy_hmac_sha512_verify(const uint8_t *key, const size_t key_size,
                              const uint8_t *message, const size_t message_size,
                              const uint8_t *code);

void stedy_hmac_sha512_init(stedy_hmac_sha512_state *state, const uint8_t *key,
                            const size_t key_size);

void stedy_hmac_sha512_update(stedy_hmac_sha512_state *state,
                              const uint8_t *message,
                              const size_t message_size);

void stedy_hmac_sha512_final(const stedy_hmac_sha512_state *state,
                             uint8_t *code);

bool stedy_hmac_sha512_final_verify(const stedy_hmac_sha512_state *state,
                                    const uint8_t *code);

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

typedef struct alignas(4) stedy_rng_state {
  uint8_t opaque[132];
} stedy_rng_state;

void stedy_rng_init(stedy_rng_state *state, const uint8_t *seed);

void stedy_rng_fill(stedy_rng_state *state, uint8_t *bytes, const size_t size);

uint32_t stedy_rng_next_u32(stedy_rng_state *state);

uint64_t stedy_rng_next_u64(stedy_rng_state *state);

typedef struct alignas(8) stedy_sha256_state {
  uint8_t opaque[112];
} stedy_sha256_state;

void stedy_sha256(const uint8_t *message, const size_t message_size,
                  uint8_t *digest);

void stedy_sha256_init(stedy_sha256_state *state);

void stedy_sha256_update(stedy_sha256_state *state, const uint8_t *message,
                         const size_t message_size);

void stedy_sha256_final(const stedy_sha256_state *state, uint8_t *digest);

typedef struct alignas(8) stedy_sha512_state {
  uint8_t opaque[208];
} stedy_sha512_state;

void stedy_sha512(const uint8_t *message, const size_t message_size,
                  uint8_t *digest);

void stedy_sha512_init(stedy_sha512_state *state);

void stedy_sha512_update(stedy_sha512_state *state, const uint8_t *message,
                         const size_t message_size);

void stedy_sha512_final(const stedy_sha512_state *state, uint8_t *digest);

void stedy_x25519_generate_key_pair(const uint8_t *seed, uint8_t *private_key,
                                    uint8_t *public_key);

void stedy_x25519_key_exchange(const uint8_t *private_key,
                               const uint8_t *public_key,
                               uint8_t *shared_secret);

void stedy_x25519_public_key(const uint8_t *private_key, uint8_t *public_key);

bool stedy_verify(const uint8_t *a, const uint8_t *b, size_t size);

void stedy_wipe(uint8_t *data, size_t size);

#ifdef __cplusplus
}
#endif

#endif
