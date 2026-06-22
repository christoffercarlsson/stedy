.PHONY: clean docs

clean:
	@cargo clean --quiet

docs:
	@RUSTDOCFLAGS="--cfg docsrs" cargo +nightly doc --quiet --features docs --open
