use std::vec;

use crypto::{
    aes,
    buffer::{BufferResult, ReadBuffer, WriteBuffer},
    symmetriccipher,
};
use hmac::{Hmac, Mac};
use sha2::Sha256;
type HmacSha256 = Hmac<Sha256>;

pub fn hmac_hash(input: &[u8]) -> [u8; 16] {
    let mut mac = HmacSha256::new_from_slice(input).expect("HMAC can take key of any size");
    let result = mac.finalize();
    let mut hash = vec![];
    let code_bytes = result.into_bytes();
    hash.extend_from_slice(&code_bytes);
    hash.split_off(16);
    hash.as_slice().try_into().unwrap()
}

#[test]
fn test_hmac_hash() {
    let hash = hmac_hash(&[1, 2, 3, 4]);
    // dbg!(hash);
    let expect = hex::decode("3e6294ffb2444b9a43c89b1d19ac5045").unwrap();
    // expect.split_off(16);
    // assert_eq!(hash, &expect.as_slice().try_into().unwrap());
    dbg!(hash, &expect);
}

pub fn aes_decrypt(
    encrypted_data: &[u8],
    key: &[u8],
    iv: &[u8],
) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
    let mut decryptor = aes::cbc_decryptor(
        aes::KeySize::KeySize128,
        key,
        iv,
        crypto::blockmodes::NoPadding,
    );

    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = crypto::buffer::RefReadBuffer::new(encrypted_data);
    let mut buffer = [0; 4096];
    let mut write_buffer = crypto::buffer::RefWriteBuffer::new(&mut buffer);

    loop {
        let result = decryptor
            .decrypt(&mut read_buffer, &mut write_buffer, true)
            .unwrap();
        final_result.extend(
            write_buffer
                .take_read_buffer()
                .take_remaining()
                .iter()
                .map(|&i| i),
        );
        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => {}
        }
    }

    Ok(final_result)
}

// TODO: test
pub fn aes_encrypt(
    data: &[u8],
    key: &[u8],
    iv: &[u8],
) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
    let mut decryptor = aes::cbc_encryptor(
        aes::KeySize::KeySize128,
        key,
        iv,
        crypto::blockmodes::NoPadding,
    );

    let mut data = data.to_vec();
    data.extend(b"A".repeat(data.len() % 16));
    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = crypto::buffer::RefReadBuffer::new(&data);
    let mut buffer = [0; 4096];
    let mut write_buffer = crypto::buffer::RefWriteBuffer::new(&mut buffer);

    loop {
        let result = decryptor
            .encrypt(&mut read_buffer, &mut write_buffer, true)
            .unwrap();
        final_result.extend(
            write_buffer
                .take_read_buffer()
                .take_remaining()
                .iter()
                .map(|&i| i),
        );
        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => {}
        }
    }

    Ok(final_result)
}
