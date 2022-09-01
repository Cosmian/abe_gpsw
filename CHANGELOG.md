# Changelog

All notable changes to this project will be documented in this file.

---
## [2.0.0] - 2023-08-25
### Added
### Changed
- Update ABEPolicy to v1.0
### Fixed
### Removed
---

---
## [1.1.2] - 2022-08-24
### Added
### Changed
- Update CryptoBase to v2.1
### Fixed
### Removed
---

---
## [1.1.1] - 2022-07-18
### Added
### Changed
### Fixed
- Returns in FFI functions (before exiting) the required pre-allocated out buffer size when buffer is too small
### Removed
---

---
## [1.1.0] - 2022-07-06
### Added
### Changed
- Use `abe_policy` library.
### Fixed
### Removed
- Remove `policy.rs` from the library
---

---
## [1.0.0] - 2022-07-01
### Added
### Changed
- Bump the cosmian_crypto_base version
### Fixed
- Remove an out of memory overflow in `try_from_bytes`
### Removed
---

---
## [0.8.0] - 2022-06-23
### Added
- [pyo3] ABE key delegation
- [pyo3 + JS/bindgen + FFI] Add attributes rotation mechanism
### Changed
- In struct `Policy`:
  * `last_attribute` becomes `last_attribute_value`
  * `max_attribute` becomes `max_attribute_value`
- Add to Python Notebook Delegation mechanism
### Fixed
### Removed
---

---
## [0.7.0] - 2022-06-16
### Added
- [pyo3] Add Rust bindings for Python thanks to pyo3
### Changed
- API changes:
    * in statics.rs: `encrypt_hybrid_header`: meta_data becomes optional
    * in trait core/gpsw/mod.rs `AsBytes`:
      - `from_bytes` becomes `try_from_bytes`
      - `as_bytes` becomes `try_into_bytes`
- Python notebook updated with new Python fast-FFI ABE module
### Fixed
### Removed
- Github CI due to storage and time limitations
---

---
## [0.6.11] - 2022-06-07
### Added
- [JS/WASM + FFI] Add ABE keys generation JS bindings
### Changed
### Fixed
### Removed
---

---
## [0.6.10] - 2022-06-01
### Added
- header size bench
### Changed
### Fixed
### Removed
---

---
## [0.6.9] - 2022-05-23
### Added
### Changed
- bumped crypto base version to 1.2.1
### Fixed
### Removed
---

---
## [0.6.7] - 2022-05-17
### Added
- In ABE-AES hybrid encryption, use encrypted `Metadata` to protect and recover UID value
### Changed
### Fixed
### Removed
---

---
## [0.6.6] - 2022-05-12
### Added
- Add ABE hybrid encryption for wasm-bindgen (JS)
- Add `as_bytes` and `from_bytes` for `EncryptedHeader`
- Add an ABE attributes parser for encryption: for example: "Security Level::level 1 , Department::HR" resulting in a list of 2 attributes
### Changed
- Refactor tests for ABE wasm-bindgen: verify encryption and decryption with native implementation
### Fixed
### Removed
---

---
## [0.6.5] - 2022-04-06
### Added
### Changed
- Improve wasm-bindgen ABE decryption using cache (gain of 30%)
- Make sure that wrong encryption-attributes give an explicit error (`AttributeNotFound` error)
### Fixed
### Removed
---

---
## [0.6.4] - 2022-03-31
### Added
- Add function to verify if access policy is compliant with a given ABE policy
- Improve performance of ABE encryption/decryption in wasi-webassembly using a cache for public key deserialization
- Attribute parser for example this string "Security Level::level 1"
### Changed
- Replace in code access policy (of the user decryption key) with boolean expression (given as string)
- Consolidate access policy parser: operators are `&&` or `||` and handle spaces in boolean expressions
### Fixed
- Typo in Jupyter notebook
### Removed
---

---
## [0.6.3] - 2022-03-16
### Added
- Access policy parser for boolean expression: Example: parse a string access policy under this format "(Department::HR | Department::RnD) & Level::level_2" and returns the corresponding `AccessPolicy`
- Add ABE GPSW for python use through wasm32-wasi target
### Changed
### Fixed
### Removed
---

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
