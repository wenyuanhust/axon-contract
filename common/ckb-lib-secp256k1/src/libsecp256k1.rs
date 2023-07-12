use crate::code_hashes::CODE_HASH_SECP256K1;
use ckb_std::dynamic_loading_c_impl::{CKBDLContext, Symbol};

/// function signature of validate_signature_uncompressed
type ValidateSignatureUncompressed = unsafe extern "C" fn(
    signature_buffer: *const u8,
    signature_size: u64,
    message_buffer: *const u8,
    message_size: u64,
    output: *mut u8,
    output_len: *mut u64,
) -> i32;

/// Symbol name
const VALIDATE_SIGNATURE: &[u8; 18] = b"validate_signature";

pub struct Pubkey([u8; 65]);

impl Pubkey {
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl Default for Pubkey {
    fn default() -> Self {
        let inner = [0u8; 65];
        Pubkey(inner)
    }
}

impl Into<[u8; 65]> for Pubkey {
    fn into(self) -> [u8; 65] {
        self.0
    }
}

pub struct LibCKBSecp256k1 {
    validate_signature: Symbol<ValidateSignatureUncompressed>,
}

impl LibCKBSecp256k1 {
    pub fn load<T>(context: &mut CKBDLContext<T>) -> Self {
        // load library
        let lib = context.load(&CODE_HASH_SECP256K1).expect("load secp256k1");

        // find symbols
        let validate_signature = unsafe { lib.get(VALIDATE_SIGNATURE).expect("load function") };
        LibCKBSecp256k1 { validate_signature }
    }

    pub fn verify_signature(&self, signature: &[u8], message: &[u8]) -> Result<Pubkey, i32> {
        let mut pubkey = Pubkey::default();
        let mut len: u64 = pubkey.0.len() as u64;
        if signature.len() != 65 {
            return Err(-11111);
        }
        if message.len() != 32 {
            return Err(-22222);
        }

        let validate_signature_f = &self.validate_signature;
        let error_code = unsafe {
            validate_signature_f(
                signature.as_ptr(),
                signature.len() as u64,
                message.as_ptr(),
                message.len() as u64,
                pubkey.0.as_mut_ptr(),
                &mut len as *mut u64,
            )
        };
        if error_code != 0 {
            return Err(error_code);
        }
        Ok(pubkey)
    }
}
