all: fmt lint

lint: fmt
	cargo clippy
	cargo clippy --tests

test:
	cargo test -- --test-threads=1
	cargo test --release -- --test-threads=1 --nocapture

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
	cargo update --verbose

doc:
	cargo doc --all-features --open

ci:
	cargo check
	cargo test -- --test-threads=1
