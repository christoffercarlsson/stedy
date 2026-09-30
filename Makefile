.PHONY: clean docs

CRATE := $(shell awk -F'"' '/^\[package\]/ { p = 1 } p && /^name = / { print $$2; exit }' Cargo.toml | tr - _)

clean:
	@cargo clean --quiet

docs:
	@RUSTDOCFLAGS="--cfg docsrs" cargo +nightly doc --quiet --features docs
	@echo "$${CARGO_TARGET_DIR:-target}/doc/$(CRATE)/index.html"
