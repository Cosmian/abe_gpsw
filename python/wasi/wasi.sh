#!/bin/sh

set -eEu

WIT=abe.wit

prerequisites() {
  cargo install cargo-witgen --version 0.4.0
  cargo install --git https://github.com/bytecodealliance/wit-bindgen wit-bindgen-cli --rev '2c4ec937cab8c23131d644d2fcaf4705a08f9b01'
  rustup target add wasm32-wasi
  # yum install virtualenv
  virtualenv env
  source env/bin/activate
  pip install -r python/wasi/requirements.txt
}
# prerequisites

# First, generate WIT file
cargo witgen generate -o $WIT -- --features wit --lib

# Generate EXPORT Rust bindings from WIT file
wit-bindgen rust-wasm -e $WIT --out-dir src/interfaces/wasi/

# Generate WASM using EXPORT bindings
cargo build --features wasi_impl --release --target wasm32-wasi
cp target/wasm32-wasi/release/abe_gpsw.wasm python/wasi/

# Generate IMPORT Rust bindings from WIT file
wit-bindgen wasmtime-py -i $WIT --out-dir ./python/wasi/
source env/bin/activate
python ./python/wasi/abe.py
