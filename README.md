[![Rust](https://github.com/rust-util-collections/chaindev/actions/workflows/rust.yml/badge.svg)](https://github.com/rust-util-collections/chaindev/actions/workflows/rust.yml)
[![Latest Version](https://img.shields.io/crates/v/chaindev.svg)](https://crates.io/crates/chaindev)
[![Rust Documentation](https://img.shields.io/badge/api-rustdoc-blue.svg)](https://docs.rs/chaindev)
![GitHub top language](https://img.shields.io/github/languages/top/rust-util-collections/chaindev)
[![Minimum rustc version](https://img.shields.io/badge/rustc-1.81+-lightgray.svg)](https://github.com/rust-random/rand#rust-version-requirements)

# chaindev

Powerful development and testing utils for blockchain developers.

- [Beacon(ETH2) based chains](src/beacon_based)
    - `feature = [ "beacon_based" ]`, default
- [Tendermint/CometBFT based chains](src/tendermint_based)
    - `feature = [ "tendermint_based" ]`
    - **WARNING**: less maintained, new features may be missing!

### ENV VARs

- `$CHAIN_DEV_EGG_REPO`: where to clone the `EGG` package
    - Default to 'https://github.com/NBnet/EGG'
