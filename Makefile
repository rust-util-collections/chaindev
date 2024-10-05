all: fmt lint

lint: fmt
	cargo clippy

test:
	cargo test -- --test-threads=1
	cargo test --release -- --test-threads=1

fmt:
	cargo fmt

fmtall:
	bash tools/fmt.sh

clean:
	cargo clean

cleanall: clean
	git stash
	git clean -fdx

update:
	rustup update stable
	cargo update --verbose

doc:
	cargo doc --all-features --open

ci:
	cargo check
	cargo test -- --test-threads=1
