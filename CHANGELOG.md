# Changelog

All notable changes to this project will be documented in this file.

---
## [0.6.2] - 2022-03-16
### Added
- Build for Android and iOS
- [FFI] Add a ABE split header function
- Use `cbindgen` to generate .h from Rust-FFI-functions
### Changed
### Fixed
### Removed

---


---
## [0.6.1] - 2022-03-15
### Added
### Changed
- FFI made caches use int handle ids rather than pointers
### Fixed
- FFI made caches thread safe
### Removed

---


---
## [0.6.0] - 2022-03-11
### Added
- FFI hybrid encryption using a cache to speed up encryption/decryption (x4 on encryption, x2 on decryption)
- FFI tests
- benchmarks and profiling- see `bench.rs` for details

Run benchmarks:

```sh
cargo run --release --features ffi --bin bench_abe_gpsw
```
### Changed
### Fixed
### Removed

---


---
## [0.5.0] - 2022-03-09
### Added
### Changed
- [wasm-bindgen]: make optional uid and block_number in decrypt_block function
### Fixed
### Removed
- Useless logs

---
## [0.4.1] - 2022-03-08
### Added
- Add wasm-bindgen bindings for javascript use
### Changed
### Fixed
### Removed

---
## [0.4.0] - 2022-02-21
### Added
### Changed
- Updated crypto_base to 0.5.1 which introduces a breaking change to hybrid MetaData

### Fixed
- hybrid crypto: allow empty resource UIDs
### Removed

---
## [0.3.0] - 2022-02-04
### Added
FFI to be able to interface with other languages
### Changed
- Re-organized crate in two main modules
  - crypto ony in `core`
  - cosmian and FFI in `interfaces`
-> see the build instructions
Improved hybrid crypto

### Fixed
### Removed

---
## [0.2.4] - 2022-01-13
### Added
- Asymmetric public key trait
### Changed
### Fixed
### Removed

---
## [0.2.3] - 2022-01-06
### Added
### Changed
- Demo doc improvements
- Really Stay on edition 2018
### Fixed
### Removed

---
## [0.2.2] - 2022-01-04
### Added
### Changed
- Stay on edition 2018
### Fixed
### Removed

---
## [0.2.1] - 2022-01-02
### Added
### Changed
- Updated edition to 2021
- Clarified demo and made it more visible
### Fixed
- Documentation on hierarchical axes
### Removed

---
## [0.2.0] - 2021-12-22
### Added
### Changed
- Update crate version du to last interface changes: introducing `thiserror`
### Fixed
- Regression in trait `AsBytes` function `from_bytes` for deserializing generic objects
### Removed

---
## [0.1.4] - 2021-12-20
### Added
### Changed
- Error handling: use `thiserror` instead of `eyre`, allowing users to match on enum errors
### Fixed
### Removed

---
## [0.1.3] - 2021-12-06
### Added
- Add access policy comparison (trait `PartialEq`) with ABE attributes commutativity
### Changed
### Fixed
- Bug in hierarchical axis, order DOES matter now
### Removed

---
## [0.1.2] - 2021-12-03
### Added
- Add CHANGELOG and LICENSE files
### Changed
- Complete readme
### Fixed
### Removed

---
## [0.1.1] - 2021-11-26
### Added
- Readme
### Changed
### Fixed
### Removed

---
## [0.1.0] - 2021-11-25
### Added
- Implementation of Key-Policy Attribute-Based Encryption (*KP-ABE*):
  - **Title**: Attribute-Based Encryption for Fine-Grained Access Control of Encrypted Data
  - **Authors**: Vipul Goyal, Omkant Pandey, Amit Sahai, Brent Waters
  - **eprint**: https://eprint.iacr.org/2006/309.pdf
### Changed
### Fixed
### Removed
---
