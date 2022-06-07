pub mod generate_gpsw_keys;
pub mod hybrid_gpsw_aes_decryption;
pub mod hybrid_gpsw_aes_encryption;

#[cfg(test)]
mod tests;

use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
    fn alert(s: &str);
}
