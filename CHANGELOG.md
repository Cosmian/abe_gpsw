# Changelog

All notable changes to this project will be documented in this file.

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