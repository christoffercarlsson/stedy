.PHONY: clean docs wycheproof

CRATE := $(shell awk -F'"' '/^\[package\]/ { p = 1 } p && /^name = / { print $$2; exit }' Cargo.toml | tr - _)

WYCHEPROOF_REF := main
WYCHEPROOF_URL := https://raw.githubusercontent.com/C2SP/wycheproof/$(WYCHEPROOF_REF)
WYCHEPROOF_DIR := tests/wycheproof/vectors
WYCHEPROOF_FILES := \
	aegis128L \
	aegis256 \
	aes_gcm \
	chacha20_poly1305 \
	ecdh_secp256r1_ecpoint \
	ecdh_secp384r1_ecpoint \
	ecdh_secp521r1_ecpoint \
	ecdsa_secp256r1_sha256_p1363 \
	ecdsa_secp384r1_sha384_p1363 \
	ecdsa_secp521r1_sha512_p1363 \
	ed25519 \
	ed448 \
	hkdf_sha1 \
	hkdf_sha256 \
	hkdf_sha384 \
	hkdf_sha512 \
	hmac_sha1 \
	hmac_sha256 \
	hmac_sha384 \
	hmac_sha3_224 \
	hmac_sha3_256 \
	hmac_sha3_384 \
	hmac_sha3_512 \
	hmac_sha512 \
	mldsa_44_sign_noseed \
	mldsa_44_sign_seed \
	mldsa_44_verify \
	mldsa_65_sign_noseed \
	mldsa_65_sign_seed \
	mldsa_65_verify \
	mldsa_87_sign_noseed \
	mldsa_87_sign_seed \
	mldsa_87_verify \
	mlkem_1024 \
	mlkem_1024_encaps \
	mlkem_1024_keygen_seed \
	mlkem_1024_semi_expanded_decaps \
	mlkem_512 \
	mlkem_512_encaps \
	mlkem_512_keygen_seed \
	mlkem_512_semi_expanded_decaps \
	mlkem_768 \
	mlkem_768_encaps \
	mlkem_768_keygen_seed \
	mlkem_768_semi_expanded_decaps \
	pbkdf2_hmacsha1 \
	pbkdf2_hmacsha256 \
	pbkdf2_hmacsha384 \
	pbkdf2_hmacsha512 \
	siphash_1_3 \
	siphash_2_4 \
	siphash_4_8 \
	siphashx_2_4 \
	siphashx_4_8 \
	x25519 \
	x448 \
	xchacha20_poly1305

clean:
	@cargo clean --quiet

docs:
	@RUSTDOCFLAGS="--cfg docsrs" cargo +nightly doc --quiet --features docs
	@echo "$${CARGO_TARGET_DIR:-target}/doc/$(CRATE)/index.html"

wycheproof:
	@mkdir -p $(WYCHEPROOF_DIR)
	@curl -fsSL -o $(WYCHEPROOF_DIR)/LICENSE $(WYCHEPROOF_URL)/LICENSE
	@for file in $(WYCHEPROOF_FILES); do \
		curl -fsSL \
			-o $(WYCHEPROOF_DIR)/$${file}_test.json \
			$(WYCHEPROOF_URL)/testvectors_v1/$${file}_test.json \
			|| exit 1; \
	done
	@echo "$(WYCHEPROOF_DIR): $(words $(WYCHEPROOF_FILES)) files from C2SP/wycheproof@$(WYCHEPROOF_REF)"
