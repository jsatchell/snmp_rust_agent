use aes::cipher::{AsyncStreamCipher, KeyIvInit};
use rasn::types::IntegerType;
use rasn_snmp::v3::USMSecurityParameters;

type Aes128CfbEnc = cfb_mode::Encryptor<aes::Aes128>;
type Aes128CfbDec = cfb_mode::Decryptor<aes::Aes128>;

/// Calculate the Initial Value for the crypt.
/// If you get this wrong, the first block comes out wrong,
/// but it then recovers - this is a CFB feature
fn make_iv(usp: USMSecurityParameters) -> [u8; 16] {
    // Manager chooses salt, agent just uses it (except for traps, which we don't do)
    let mut iv: [u8; 16] = [0; 16];
    let boot_b_t = usp.authoritative_engine_boots.to_unsigned_bytes_be();
    let bootb: &[u8] = boot_b_t.0.as_ref();
    let time_b_t = usp.authoritative_engine_time.to_unsigned_bytes_be();
    let timeb: &[u8] = time_b_t.0.as_ref();
    let saltb = usp.privacy_parameters.clone();
    for i in 0..4 {
        iv[i] = bootb[3 - i]; // MSB first
        iv[i + 4] = timeb[3 - i];
    }
    for i in 0..8 {
        iv[i + 8] = saltb[i];
    }
    iv
}

/// Decrypt the data
pub fn decrypt(data: &mut [u8], usp: USMSecurityParameters, pkey: &[u8]) -> Vec<u8> {
    let iv = make_iv(usp);
    let key: &[u8] = &pkey[0..16];
    let dec: cfb_mode::Decryptor<aes::Aes128> = Aes128CfbDec::new_from_slices(key, &iv).unwrap();
    dec.decrypt(data);
    data.to_vec()
}

/// Encrypt the data
pub fn encrypt(data: &mut [u8], usp: USMSecurityParameters, pkey: &[u8]) -> Vec<u8> {
    let iv = make_iv(usp);
    let key: &[u8] = &pkey[0..16];
    Aes128CfbEnc::new_from_slices(key, &iv)
        .unwrap()
        .encrypt(data);
    data.to_vec()
}
