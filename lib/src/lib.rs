use std::io::Read;
use std::fs::File;
use openssl::aes::AesKey;
use openssl::rand::rand_bytes;
use openssl::rsa::{Rsa, Padding};
use openssl::pkey::{Public, Private};
use openssl::symm::{decrypt_aead, encrypt_aead, Cipher, Crypter};

pub fn add(left: usize, right: usize) -> usize {
    left + right
}

pub fn get_rsa_public_key(filepath: &str) -> Rsa<Public> {
    let mut file: File = File::open(filepath).expect("The filepath should be a valid path");
    let mut file_contents: String = String::new();
    file.read_to_string(&mut file_contents);
    Rsa::public_key_from_pem(file_contents.as_bytes()).expect("The file should be a valid PEM-encoded RSA public key")
}

pub fn get_rsa_private_key(filepath: &str) -> Rsa<Private> {
    let mut file: File = File::open(filepath).expect("The filepath should be a valid path");
    let mut file_contents: String = String::new();
    file.read_to_string(&mut file_contents);
    Rsa::private_key_from_pem(file_contents.as_bytes()).expect("The file should be a valid PEM-encoded RSA private key")
}

pub fn encrypt_rsa(data: &[u8], key: &Rsa<Public>) -> Vec<u8> {
    let mut result: Vec<u8> = Vec::new();
    result.resize(key.size() as usize, 0);
    key.public_encrypt(data, result.as_mut_slice(), Padding::PKCS1).unwrap();
    result
}

pub fn decrypt_rsa(data: &[u8], key: &Rsa<Private>) -> Vec<u8> {
    let mut result: Vec<u8> = Vec::new();
    result.resize(key.size() as usize, 0);
    key.private_decrypt(data, result.as_mut_slice(), Padding::PKCS1).unwrap();
    result
}

// Encrypts with AES, returns 12 bytes of IV and the remainder is the encrypted ciphertext
pub fn encrypt_aes(data: &[u8], key: &[u8; 32], tag: &mut [u8; 16]) -> Vec<u8> {
    let cipher: Cipher = Cipher::aes_256_gcm();
    let mut iv: [u8; 12] = [0; 12];
    rand_bytes(&mut iv).unwrap();
    let mut encrypted: Vec<u8> = Vec::with_capacity(12);
    let mut ciphertext = encrypt_aead(cipher, key, Some(&iv), &[], data, tag).unwrap();
    encrypted.append(&mut iv.to_vec());
    encrypted.append(&mut tag.clone().to_vec());
    encrypted.append(&mut ciphertext);
    encrypted
}

pub fn decrypt_aes(data: &[u8], key: &[u8; 32], iv: [u8; 12], tag: &[u8; 16]) -> Vec<u8> {
    let cipher: Cipher = Cipher::aes_256_gcm();
    decrypt_aead(cipher, key, Some(&iv), &[], data, tag).unwrap()
}

pub fn read_and_decrypt_aes(data: &[u8], key: &[u8; 32]) -> Vec<u8> {
    let mut iv: [u8; 12] = [0; 12];
    let mut tag: [u8; 16] = [0; 16];
    for i in 0..12 {
        iv[i] = data[i];
    }
    for i in 12..28 {
        tag[i - 12] = data[i];
    }
    let ciphertext: &[u8] = data.split_at(28).1;
    decrypt_aes(ciphertext, key, iv, &tag)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
