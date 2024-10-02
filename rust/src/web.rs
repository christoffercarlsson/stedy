use rand_core::{CryptoRng, Error as RandCoreError, RngCore};

use js_sys::wasm_bindgen::{prelude::wasm_bindgen, JsCast, JsValue};
use js_sys::{global, wasm_bindgen, Uint8Array};

const GET_RANDOM_VALUES_VIEW_SIZE: usize = 256;

#[wasm_bindgen]
extern "C" {
    type Global;
    type WebCrypto;
    #[wasm_bindgen(method, getter)]
    fn crypto(this: &Global) -> WebCrypto;
    #[wasm_bindgen(method, js_name = getRandomValues, catch)]
    fn get_random_values(this: &WebCrypto, view: &Uint8Array) -> Result<(), JsValue>;
}

pub struct WebRng;

impl CryptoRng for WebRng {}

impl RngCore for WebRng {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0; 4];
        self.fill_bytes(&mut bytes);
        u32::from_le_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0; 8];
        self.fill_bytes(&mut bytes);
        u64::from_le_bytes(bytes)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let global: Global = global().unchecked_into();
        let crypto = global.crypto();
        let view = Uint8Array::new_with_length(GET_RANDOM_VALUES_VIEW_SIZE as u32);
        for chunk in dest.chunks_mut(GET_RANDOM_VALUES_VIEW_SIZE) {
            let v = view.subarray(0, chunk.len() as u32);
            if crypto.get_random_values(&v).is_ok() {
                v.copy_to(chunk);
            }
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), RandCoreError> {
        self.fill_bytes(dest);
        Ok(())
    }
}
