# vrf-rs
[![](https://img.shields.io/crates/v/vrf.svg)](https://crates.io/crates/vrf) [![](https://docs.rs/vrf/badge.svg)](https://docs.rs/vrf) [![](https://github.com/witnet/vrf-rs/actions/workflows/rust.yml/badge.svg)](https://github.com/witnet/vrf-rs/actions/workflows/rust.yml)

`vrf-client-starknet-rs` is a fork of vrf-rs, an open source implementation of Verifiable Random Functions (VRFs). This particular fork supports the verification function implemented in [VRF StarkNet](https://github.com/0xNonCents/VRF-StarkNet). In the future this project will interact with StarkNet to make random number calculations and proofs.

The VRF spec is described in [VRF-draft-05](https://tools.ietf.org/pdf/draft-irtf-cfrg-vrf-05). We use a modified `SECP256K1_SHA256_TAI` with keccak rather than sha256 since sha256 is not available in cairo with such large inputs.

The library can be built using `cargo` and the examples can be executed with:

```bash
cargo build
cargo run --example basic
```
Until this project has the capabilities to interect with StarkNet itself it can be viewed as a script that take inputs from the blockchain and spits out a result to be put manually back onto the blockchain.

## License

`vrf-client-starknet-rs` is published under the [MIT license][license].
