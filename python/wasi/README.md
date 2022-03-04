# Using ABE WebAssembly in Jupyter notebook

## First step: prepare an ABE interface -> crate `generate_wit`

The `*.wit` format's goal is to provide a generic interface. From this interface, thanks to the crate `wit-bindgen`, different languages bindings can be generated: for Python, Javascript, C, Rust, etc.

Since, we aim to provide multiple ABE-bindings, we stick to one clean `wit` interface. To simplify the `wit` file generation, we can use the `witgen` crate (thanks to Benjamin C.). This crate provides a `proc-macro` that can be used everywhere we want to export functions or structs to `wit` file. Then call something like `cargo witgen generate -o abe.wit`.

## Second step: build the WASI WASM -> crate `wasmlib`

Once we have the `abe.wit` file, let us use `wit-bindgen` to generate Rust-bindings which provide a ABE trait to be implemented. Once done, call `cargo build --release --target wasm32-wasi` to build the final WebAssembly file.

## Third step: using Python

To play with Jupyter Notebook, let us generate the Python-bindings with `wit-bindgen`. This command can be used `wit-bindgen wasmtime-py -i ../abe.wit --out-dir ./`
Finally, use these bindings to gently use our ABE WASM file.

## Run the notebook

```bash
jupyter notebook --ip 0.0.0.0 abe.ipynb
```

# Token history

87965475201fe9de52873ea5329472934cb3ac536e1659b8
ee69db21daca65ac90b0a0d02e2426e968ee51dba634a33d
