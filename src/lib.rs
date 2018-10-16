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
use scrypt::scrypt as real_scrypt;
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
pub fn scrypt_simple(password: &[u8], salt: &[u8], output_len: u8) -> Result<Vec<u8>, JsValue> {
    scrypt(password, salt, 15, 8, 1, output_len)
}

#[wasm_bindgen]
pub fn scrypt(password: &[u8], salt: &[u8], log_n: u8, r: u32, p: u32, output_len: u8) -> Result<Vec<u8>, JsValue> {
    utils::set_panic_hook();
    let mut output: Vec<u8> = (0..output_len).collect();
    let params = ScryptParams::new(log_n, r, p).map_err(|e| e.description().to_owned())?;
    real_scrypt(password, salt, &params, &mut output).map_err(|e| e.description().to_owned())?;
    Ok(output)
}

#[wasm_bindgen]
pub struct EncryptionResult {
    auth_tag: Vec<u8>,
    ciphertext: Vec<u8>,
}

#[wasm_bindgen]
impl EncryptionResult {
    #[wasm_bindgen]
    pub fn get_auth_tag(&self) -> Vec<u8> {
        self.auth_tag.clone()
    }
    #[wasm_bindgen]
    pub fn get_ciphertext(&self) -> Vec<u8> {
        self.ciphertext.clone()
    }
}

#[wasm_bindgen]
pub fn encrypt(key: &[u8], nonce: &[u8], aad: &[u8], mut input: &[u8]) -> Result<EncryptionResult, JsValue> {
    utils::set_panic_hook();
    let mut output = Vec::with_capacity(input.len());
    let res = chacha_encrypt(key, nonce, aad, &mut input, &mut output).map_err(|e| e.description().to_owned())?;
    let tag = res.to_vec();
    Ok(EncryptionResult {
        auth_tag: tag,
        ciphertext: output,
    })
}

#[wasm_bindgen]
pub fn decrypt(key: &[u8], nonce: &[u8], aad: &[u8], mut input: &[u8], tag: &[u8]) -> Result<Vec<u8>, JsValue> {
    utils::set_panic_hook();
    let mut output = Vec::with_capacity(input.len());
    chacha_decrypt(key, nonce, aad, input, tag, &mut output).map_err(|e| format!("{:?}", e))?;
    Ok(output)
}

#[wasm_bindgen]
pub fn to_uint8(text: &str) -> Vec<u8> {
    utils::set_panic_hook();
    text.into()
}

#[wasm_bindgen]
pub fn to_utf8(data: &[u8]) -> String {
    utils::set_panic_hook();
    String::from_utf8_lossy(data).into()
}