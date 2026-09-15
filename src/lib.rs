use cbc::cipher::block_padding::Pkcs7;
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use cbc::{Decryptor, Encryptor};
use camellia::{Camellia128, Camellia192, Camellia256};
use cmac::{Cmac, Mac as CmacMac};
use hmac::{Hmac, Mac as HmacMac, NewMac as HmacNewMac};
use serde::Deserialize;
use sha2::Sha256;
use std::os::raw::c_void;
use std::slice;

enum EncryptorType {
    // EncryptorUnknown = 0,
    EncryptorSymmetric = 1,
    // EncryptorAsymmetric = 2
}

type Camellia128Enc = Encryptor<Camellia128>;
type Camellia128Dec = Decryptor<Camellia128>;
type Camellia192Enc = Encryptor<Camellia192>;
type Camellia192Dec = Decryptor<Camellia192>;
type Camellia256Enc = Encryptor<Camellia256>;
type Camellia256Dec = Decryptor<Camellia256>;

type CmacCamellia128 = Cmac<Camellia128>;
type CmacCamellia192 = Cmac<Camellia192>;
type CmacCamellia256 = Cmac<Camellia256>;

type HmacSha256 = Hmac<Sha256>;

const BLOCK_LEN:    usize = 16; // Camellia block size is 128 bit for all key sizes
const CMAC_TAG_LEN: usize = 16; // CMAC tag = one Camellia block
const HMAC_TAG_LEN: usize = 32; // HMAC-SHA256 tag

// Key size is determined automatically from the length of the hex string:
//   32 hex chars = 16 bytes = 128 bit
//   48 hex chars = 24 bytes = 192 bit
//   64 hex chars = 32 bytes = 256 bit
enum KeySize {
    K128,
    K192,
    K256,
}

struct CamelliaKey {
    key:      Vec<u8>, // 16, 24 or 32 bytes depending on KeySize
    iv:       [u8; BLOCK_LEN],
    key_size: KeySize,
    cmac_key: Vec<u8>, // empty = disabled; length must match key length
    hmac_key: Vec<u8>, // empty = disabled; arbitrary length
}

#[derive(Deserialize)]
struct KeyParams {
    key:  String,
    #[serde(default)]
    iv:   Option<String>,
    #[serde(default)]
    cmac: Option<String>,
    #[serde(default)]
    hmac: Option<String>,
}

#[no_mangle]
pub extern "C" fn create_instance(_json_str: *const u8) -> *mut c_void {
    let c_str = unsafe { std::ffi::CStr::from_ptr(_json_str as *const std::ffi::c_char) };
    let json_data = c_str.to_str().unwrap_or("");

    let params = match serde_json::from_str::<KeyParams>(json_data) {
        Ok(p)  => p,
        Err(_) => return std::ptr::null_mut(),
    };

    // determine key size from hex string length
    let key_size = match params.key.len() {
        32 => KeySize::K128,
        48 => KeySize::K192,
        64 => KeySize::K256,
        _  => return std::ptr::null_mut(),
    };

    let key_bytes = match hex::decode(&params.key) {
        Ok(b)  => b,
        Err(_) => return std::ptr::null_mut(),
    };

    let mut instance = CamelliaKey {
        key:      key_bytes,
        iv:       [0u8; BLOCK_LEN],
        key_size,
        cmac_key: Vec::new(),
        hmac_key: Vec::new(),
    };

    if let Some(ref iv_hex) = params.iv {
        if iv_hex.len() != 32 {
            return std::ptr::null_mut();
        }
        let iv_bytes = match hex::decode(iv_hex) {
            Ok(b)  => b,
            Err(_) => return std::ptr::null_mut(),
        };
        instance.iv = iv_bytes.as_slice().try_into().unwrap();
    }

    if let Some(ref cmac_hex) = params.cmac {
        // cmac key length must match cipher key length
        if cmac_hex.len() != params.key.len() {
            return std::ptr::null_mut();
        }
        let cmac_bytes = match hex::decode(cmac_hex) {
            Ok(b)  => b,
            Err(_) => return std::ptr::null_mut(),
        };
        instance.cmac_key = cmac_bytes;
    }

    if let Some(ref hmac_hex) = params.hmac {
        let hmac_bytes = match hex::decode(hmac_hex) {
            Ok(b)  => b,
            Err(_) => return std::ptr::null_mut(),
        };
        instance.hmac_key = hmac_bytes;
    }

    Box::into_raw(Box::new(instance)) as *mut c_void
}

/// Compute CMAC tag over `data` dispatching on key size.
fn compute_cmac(key: &[u8], key_size: &KeySize, data: &[u8]) -> Option<[u8; CMAC_TAG_LEN]> {
    let tag_vec: Vec<u8> = match key_size {
        KeySize::K128 => {
            let mut mac = CmacCamellia128::new_from_slice(key).ok()?;
            mac.update(data);
            mac.finalize().into_bytes().to_vec()
        }
        KeySize::K192 => {
            let mut mac = CmacCamellia192::new_from_slice(key).ok()?;
            mac.update(data);
            mac.finalize().into_bytes().to_vec()
        }
        KeySize::K256 => {
            let mut mac = CmacCamellia256::new_from_slice(key).ok()?;
            mac.update(data);
            mac.finalize().into_bytes().to_vec()
        }
    };
    tag_vec.as_slice().try_into().ok()
}

/// Verify CMAC tag over `data` dispatching on key size.
fn verify_cmac(key: &[u8], key_size: &KeySize, data: &[u8], tag: &[u8]) -> bool {
    let ok = match key_size {
        KeySize::K128 => {
            let mut mac = match CmacCamellia128::new_from_slice(key) {
                Ok(m)  => m,
                Err(_) => return false,
            };
            mac.update(data);
            mac.verify_slice(tag).is_ok()
        }
        KeySize::K192 => {
            let mut mac = match CmacCamellia192::new_from_slice(key) {
                Ok(m)  => m,
                Err(_) => return false,
            };
            mac.update(data);
            mac.verify_slice(tag).is_ok()
        }
        KeySize::K256 => {
            let mut mac = match CmacCamellia256::new_from_slice(key) {
                Ok(m)  => m,
                Err(_) => return false,
            };
            mac.update(data);
            mac.verify_slice(tag).is_ok()
        }
    };
    ok
}

/// Buffer size requirements:
///   _size + 16                        (no MAC)
///   _size + 16 + CMAC_TAG_LEN        (cmac only)
///   _size + 16 + HMAC_TAG_LEN        (hmac only)
///   _size + 16 + CMAC_TAG_LEN + HMAC_TAG_LEN  (both)
///
/// Output layout: [ ciphertext ][ cmac (16, if enabled) ][ hmac (32, if enabled) ]
#[no_mangle]
pub extern "C" fn encrypt(_instance: *mut c_void, _buf: *mut u8, _size: u32) -> u32 {
    if _instance.is_null() {
        return 0;
    }

    let instance = unsafe { &mut *(_instance as *mut CamelliaKey) };
    let size = _size as usize;

    let tag_len = if !instance.cmac_key.is_empty() { CMAC_TAG_LEN } else { 0 }
                + if !instance.hmac_key.is_empty() { HMAC_TAG_LEN } else { 0 };

    let buf_ref: &mut [u8] = unsafe {
        slice::from_raw_parts_mut(_buf, size + BLOCK_LEN + tag_len)
    };

    let ct_len = match instance.key_size {
        KeySize::K128 => {
            let cipher = match Camellia128Enc::new_from_slices(&instance.key, &instance.iv) {
                Ok(c)  => c,
                Err(_) => return 0,
            };
            match cipher.encrypt_padded_mut::<Pkcs7>(buf_ref, size) {
                Ok(ct) => ct.len(),
                Err(e) => { eprintln!("encrypt error: {:?}", e); return 0; }
            }
        }
        KeySize::K192 => {
            let cipher = match Camellia192Enc::new_from_slices(&instance.key, &instance.iv) {
                Ok(c)  => c,
                Err(_) => return 0,
            };
            match cipher.encrypt_padded_mut::<Pkcs7>(buf_ref, size) {
                Ok(ct) => ct.len(),
                Err(e) => { eprintln!("encrypt error: {:?}", e); return 0; }
            }
        }
        KeySize::K256 => {
            let cipher = match Camellia256Enc::new_from_slices(&instance.key, &instance.iv) {
                Ok(c)  => c,
                Err(_) => return 0,
            };
            match cipher.encrypt_padded_mut::<Pkcs7>(buf_ref, size) {
                Ok(ct) => ct.len(),
                Err(e) => { eprintln!("encrypt error: {:?}", e); return 0; }
            }
        }
    };

    let mut written = ct_len;

    if !instance.cmac_key.is_empty() {
        let tag = match compute_cmac(&instance.cmac_key, &instance.key_size, &buf_ref[..ct_len]) {
            Some(t) => t,
            None    => return 0,
        };
        buf_ref[written..written + CMAC_TAG_LEN].copy_from_slice(&tag);
        written += CMAC_TAG_LEN;
    }

    if !instance.hmac_key.is_empty() {
        let mut mac = HmacSha256::new_from_slice(&instance.hmac_key).unwrap();
        mac.update(&buf_ref[..ct_len]);
        let tag = mac.finalize().into_bytes();
        buf_ref[written..written + HMAC_TAG_LEN].copy_from_slice(&tag);
        written += HMAC_TAG_LEN;
    }

    written as u32
}

#[no_mangle]
pub extern "C" fn decrypt(_instance: *mut c_void, _buf: *mut u8, _size: u32) -> u32 {
    if _instance.is_null() {
        return 0;
    }

    let instance = unsafe { &mut *(_instance as *mut CamelliaKey) };
    let size = _size as usize;

    let buf_ref: &mut [u8] = unsafe { slice::from_raw_parts_mut(_buf, size) };

    // determine ciphertext length by subtracting tag lengths from the end
    let mut ct_len = size;
    if !instance.cmac_key.is_empty() {
        if ct_len < CMAC_TAG_LEN { return 0; }
        ct_len -= CMAC_TAG_LEN;
    }
    if !instance.hmac_key.is_empty() {
        if ct_len < HMAC_TAG_LEN { return 0; }
        ct_len -= HMAC_TAG_LEN;
    }

    // verify cmac over ciphertext
    if !instance.cmac_key.is_empty() {
        let tag_start = ct_len;
        if !verify_cmac(
            &instance.cmac_key,
            &instance.key_size,
            &buf_ref[..ct_len],
            &buf_ref[tag_start..tag_start + CMAC_TAG_LEN],
        ) {
            return 0;
        }
    }

    // verify hmac over ciphertext
    if !instance.hmac_key.is_empty() {
        let hmac_start = ct_len + if !instance.cmac_key.is_empty() { CMAC_TAG_LEN } else { 0 };
        let mut mac = HmacSha256::new_from_slice(&instance.hmac_key).unwrap();
        mac.update(&buf_ref[..ct_len]);
        if mac.verify(&buf_ref[hmac_start..hmac_start + HMAC_TAG_LEN]).is_err() {
            return 0;
        }
    }

    let buf_ct: &mut [u8] = unsafe { slice::from_raw_parts_mut(_buf, ct_len) };

    let decrypted = match instance.key_size {
        KeySize::K128 => {
            let cipher = match Camellia128Dec::new_from_slices(&instance.key, &instance.iv) {
                Ok(c)  => c,
                Err(_) => return 0,
            };
            match cipher.decrypt_padded_mut::<Pkcs7>(buf_ct) {
                Ok(pt) => pt.len(),
                Err(e) => { eprintln!("decrypt error: {:?}", e); 0 }
            }
        }
        KeySize::K192 => {
            let cipher = match Camellia192Dec::new_from_slices(&instance.key, &instance.iv) {
                Ok(c)  => c,
                Err(_) => return 0,
            };
            match cipher.decrypt_padded_mut::<Pkcs7>(buf_ct) {
                Ok(pt) => pt.len(),
                Err(e) => { eprintln!("decrypt error: {:?}", e); 0 }
            }
        }
        KeySize::K256 => {
            let cipher = match Camellia256Dec::new_from_slices(&instance.key, &instance.iv) {
                Ok(c)  => c,
                Err(_) => return 0,
            };
            match cipher.decrypt_padded_mut::<Pkcs7>(buf_ct) {
                Ok(pt) => pt.len(),
                Err(e) => { eprintln!("decrypt error: {:?}", e); 0 }
            }
        }
    };

    decrypted as u32
}

#[no_mangle]
pub fn get_type() -> i32 {
    EncryptorType::EncryptorSymmetric as i32
}

#[no_mangle]
pub extern "C" fn destroy_instance(_instance: *mut c_void) {
    if _instance.is_null() {
        return;
    }
    unsafe {
        drop(Box::from_raw(_instance as *mut CamelliaKey));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    const IV_HEX:    &str = "00000000000000000000000000000000";
    const KEY128_HEX: &str = "00112233445566778899aabbccddeeff";
    const KEY192_HEX: &str = "00112233445566778899aabbccddeeff0011223344556677";
    const KEY256_HEX: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    // cmac keys same length as cipher keys
    const CMAC128_HEX: &str = "aabbccddeeff00112233445566778899";
    const CMAC192_HEX: &str = "aabbccddeeff00112233445566778899aabbccddee001122";
    const CMAC256_HEX: &str = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899";
    const HMAC_HEX:   &str = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899";

    fn make_instance(json: &str) -> *mut c_void {
        let s = CString::new(json).unwrap();
        create_instance(s.as_ptr() as *const u8)
    }

    fn roundtrip(json: &str, tag_len: usize) {
        let instance  = make_instance(json);
        assert!(!instance.is_null(), "instance is null for: {json}");

        let plaintext = b"hello camellia world";
        let buf_size  = plaintext.len() + BLOCK_LEN + tag_len;
        let mut buffer = vec![0u8; buf_size];
        buffer[..plaintext.len()].copy_from_slice(plaintext);

        let enc_len = encrypt(instance, buffer.as_mut_ptr(), plaintext.len() as u32);
        assert!(enc_len > 0, "encrypt returned 0");

        let dec_len = decrypt(instance, buffer.as_mut_ptr(), enc_len);
        assert_eq!(dec_len as usize, plaintext.len(), "decrypted size mismatch");
        assert_eq!(&buffer[..dec_len as usize], plaintext, "plaintext mismatch");

        destroy_instance(instance);
    }

    fn tamper_fails(json: &str, tag_len: usize) {
        let instance  = make_instance(json);
        assert!(!instance.is_null());

        let plaintext = b"hello";
        let buf_size  = plaintext.len() + BLOCK_LEN + tag_len;
        let mut buffer = vec![0u8; buf_size];
        buffer[..plaintext.len()].copy_from_slice(plaintext);

        let enc_len = encrypt(instance, buffer.as_mut_ptr(), plaintext.len() as u32);
        assert!(enc_len > 0);
        buffer[0] ^= 0xff;

        let dec_len = decrypt(instance, buffer.as_mut_ptr(), enc_len);
        assert_eq!(dec_len, 0, "tampered data must fail");

        destroy_instance(instance);
    }

    // --- create_instance ---

    #[test]
    fn test_create_128() {
        let i = make_instance(&format!(r#"{{"key":"{KEY128_HEX}","iv":"{IV_HEX}"}}"#));
        assert!(!i.is_null());
        destroy_instance(i);
    }

    #[test]
    fn test_create_192() {
        let i = make_instance(&format!(r#"{{"key":"{KEY192_HEX}","iv":"{IV_HEX}"}}"#));
        assert!(!i.is_null());
        destroy_instance(i);
    }

    #[test]
    fn test_create_256() {
        let i = make_instance(&format!(r#"{{"key":"{KEY256_HEX}","iv":"{IV_HEX}"}}"#));
        assert!(!i.is_null());
        destroy_instance(i);
    }

    #[test]
    fn test_create_invalid_key_len() {
        let i = make_instance(r#"{"key":"00112233","iv":"00000000000000000000000000000000"}"#);
        assert!(i.is_null());
    }

    #[test]
    fn test_create_cmac_wrong_len_fails() {
        // cmac key length must match cipher key length
        let i = make_instance(&format!(
            r#"{{"key":"{KEY128_HEX}","iv":"{IV_HEX}","cmac":"{CMAC256_HEX}"}}"#
        ));
        assert!(i.is_null(), "cmac key length mismatch must return null");
    }

    // --- roundtrip ---

    #[test]
    fn test_roundtrip_128_no_mac() {
        roundtrip(&format!(r#"{{"key":"{KEY128_HEX}","iv":"{IV_HEX}"}}"#), 0);
    }

    #[test]
    fn test_roundtrip_192_no_mac() {
        roundtrip(&format!(r#"{{"key":"{KEY192_HEX}","iv":"{IV_HEX}"}}"#), 0);
    }

    #[test]
    fn test_roundtrip_256_no_mac() {
        roundtrip(&format!(r#"{{"key":"{KEY256_HEX}","iv":"{IV_HEX}"}}"#), 0);
    }

    #[test]
    fn test_roundtrip_128_cmac() {
        roundtrip(
            &format!(r#"{{"key":"{KEY128_HEX}","iv":"{IV_HEX}","cmac":"{CMAC128_HEX}"}}"#),
            CMAC_TAG_LEN,
        );
    }

    #[test]
    fn test_roundtrip_192_cmac() {
        roundtrip(
            &format!(r#"{{"key":"{KEY192_HEX}","iv":"{IV_HEX}","cmac":"{CMAC192_HEX}"}}"#),
            CMAC_TAG_LEN,
        );
    }

    #[test]
    fn test_roundtrip_256_cmac() {
        roundtrip(
            &format!(r#"{{"key":"{KEY256_HEX}","iv":"{IV_HEX}","cmac":"{CMAC256_HEX}"}}"#),
            CMAC_TAG_LEN,
        );
    }

    #[test]
    fn test_roundtrip_128_hmac() {
        roundtrip(
            &format!(r#"{{"key":"{KEY128_HEX}","iv":"{IV_HEX}","hmac":"{HMAC_HEX}"}}"#),
            HMAC_TAG_LEN,
        );
    }

    #[test]
    fn test_roundtrip_128_both() {
        roundtrip(
            &format!(r#"{{"key":"{KEY128_HEX}","iv":"{IV_HEX}","cmac":"{CMAC128_HEX}","hmac":"{HMAC_HEX}"}}"#),
            CMAC_TAG_LEN + HMAC_TAG_LEN,
        );
    }

    #[test]
    fn test_roundtrip_256_both() {
        roundtrip(
            &format!(r#"{{"key":"{KEY256_HEX}","iv":"{IV_HEX}","cmac":"{CMAC256_HEX}","hmac":"{HMAC_HEX}"}}"#),
            CMAC_TAG_LEN + HMAC_TAG_LEN,
        );
    }

    // --- tamper ---

    #[test]
    fn test_tamper_128_cmac() {
        tamper_fails(
            &format!(r#"{{"key":"{KEY128_HEX}","iv":"{IV_HEX}","cmac":"{CMAC128_HEX}"}}"#),
            CMAC_TAG_LEN,
        );
    }

    #[test]
    fn test_tamper_256_hmac() {
        tamper_fails(
            &format!(r#"{{"key":"{KEY256_HEX}","iv":"{IV_HEX}","hmac":"{HMAC_HEX}"}}"#),
            HMAC_TAG_LEN,
        );
    }

    #[test]
    fn test_encrypt_null_instance() {
        let mut data = b"test".to_vec();
        assert_eq!(encrypt(std::ptr::null_mut(), data.as_mut_ptr(), data.len() as u32), 0);
    }

    #[test]
    fn test_get_type() {
        assert_eq!(get_type(), EncryptorType::EncryptorSymmetric as i32);
    }
}
