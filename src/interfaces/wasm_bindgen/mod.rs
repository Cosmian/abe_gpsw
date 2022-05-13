pub mod hybrid_gpsw_aes_decryption;
pub mod hybrid_gpsw_aes_encryption;

use js_sys::Uint8Array;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
    fn alert(s: &str);
}

fn bytes_to_js_array(bytes: &[u8]) -> Uint8Array {
    let js_array = Uint8Array::new_with_length(bytes.len() as u32);
    js_array.copy_from(bytes);
    js_array
}
