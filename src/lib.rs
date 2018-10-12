extern crate cfg_if;
extern crate wasm_bindgen;
extern crate scrypt;
extern crate chacha20_poly1305_aead;
extern crate js_sys;


mod utils;

use cfg_if::cfg_if;
use wasm_bindgen::prelude::*;
use js_sys::Uint8Array;
use chacha20_poly1305_aead::{encrypt as chacha_encrypt, decrypt as chacha_decrypt};
use scrypt::{scrypt as real_scrypt};
use std::error::Error;
use scrypt::ScryptParams;

cfg_if! {
    // When the `wee_alloc` feature is enabled, use `wee_alloc` as the global
    // allocator.
    if #[cfg(feature = "wee_alloc")] {
        extern crate wee_alloc;
        #[global_allocator]
        static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;
    }
}


#[wasm_bindgen]
pub fn scrypt(password: &[u8], salt: &[u8], log_n: u8, r: u32, p: u32) -> Result<Vec<u8>, JsValue> {
    let mut output = Vec::new();
    let params = ScryptParams::new(log_n,r,p).map_err(|e| e.description().to_owned())?;
    real_scrypt(password, salt, &params, &mut output).map_err(|e| e.description().to_owned())?;
    Ok(output)
}

#[wasm_bindgen]
pub struct EncryptionResult {
    auth_tag: [u8; 16],
    ciphertext: Vec<u8>,
}

#[wasm_bindgen]
pub fn encrypt(key: &[u8], nonce: &[u8], aad: &[u8], mut input: &[u8]) -> Result<EncryptionResult, JsValue> {
    let mut output = Vec::with_capacity(input.len());
    let res = chacha_encrypt(key, nonce, aad, &mut input, &mut output).map_err(|e| e.description().to_owned())?;
    Ok(EncryptionResult {
        auth_tag: res,
        ciphertext: output,
    })
}

#[wasm_bindgen]
pub fn decrypt(key: &[u8], nonce: &[u8], aad: &[u8], mut input: &[u8], tag: &[u8]) -> Result<Vec<u8>, JsValue> {
    let mut output = Vec::with_capacity(input.len());
    chacha_decrypt(key, nonce, aad, input, tag, &mut output).map_err(|e| format!("{:?}", e))?;
    Ok(output)
}
