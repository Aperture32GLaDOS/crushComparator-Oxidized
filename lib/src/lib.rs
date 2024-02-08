use core::panic;
use std::io::{Read, Write};
use std::fs::File;
use std::net::TcpStream;
use openssl::rand::rand_bytes;
use openssl::rsa::{Rsa, Padding};
use openssl::pkey::{Public, Private};
use openssl::symm::{decrypt_aead, encrypt_aead, Cipher};

#[derive(Debug)]
pub enum MessageType {
    NORMAL,
    DEBUG
}

impl MessageType {
    pub fn as_bytes(&self) -> [u8; 1] {
        match self {
            Self::NORMAL => [0],
            Self::DEBUG => [1]
        }
    }

    pub fn from_bytes(bytes: [u8; 1]) -> Self {
        match bytes {
            [0] => Self::NORMAL,
            [1] => Self::DEBUG,
            _ => panic!("Unexpected bytes in MessageType reading")
        }
    }
}

#[derive(Debug)]
struct MessageHeader {
    message_len: usize,
    message_type: MessageType
}

impl MessageHeader {
    fn new(message: &[u8], message_type: MessageType) -> MessageHeader {
        MessageHeader {message_len: message.len(), message_type}
    }

    fn as_bytes(&self) -> [u8; 9] {
        let mut bytes: [u8; 9] = [0; 9];
        let length_bytes = self.message_len.to_be_bytes();
        for i in 0..8 {
            bytes[i] = length_bytes[i];
        }
        bytes[8] = self.message_type.as_bytes()[0];
        return bytes;
    }

    fn from_bytes(bytes: &[u8]) -> Self {
        let mut length_bytes: [u8; 8] = [0; 8];
        let type_byte: [u8; 1] = [bytes[8]];
        for i in 0..8 {
            length_bytes[i] = bytes[i];
        }
        MessageHeader{message_len: usize::from_be_bytes(length_bytes), message_type: MessageType::from_bytes(type_byte)}
    }
}

pub fn add(left: usize, right: usize) -> usize {
    left + right
}

pub fn get_rsa_public_key(filepath: &str) -> Rsa<Public> {
    let mut file: File = File::open(filepath).expect("The filepath should be a valid path");
    let mut file_contents: String = String::new();
    file.read_to_string(&mut file_contents).unwrap();
    Rsa::public_key_from_pem(file_contents.as_bytes()).expect("The file should be a valid PEM-encoded RSA public key")
}

pub fn get_rsa_private_key(filepath: &str) -> Rsa<Private> {
    let mut file: File = File::open(filepath).expect("The filepath should be a valid path");
    let mut file_contents: String = String::new();
    file.read_to_string(&mut file_contents).unwrap();
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

// Encrypts with AES, returns 12 bytes of IV, 16 bytes of tag and the remainder is the encrypted ciphertext
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

// Given data returned from encrypt_aes, split into its component parts and decrypt it
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

// Splits a message into n equal parts
// Used for chunking large messages into smaller components
pub fn split_message(message: &[u8], chunk_size: usize) -> Vec<Vec<u8>> {
    let mut chunked_message: Vec<Vec<u8>> = Vec::new();
    for i in 0..((message.len() / chunk_size)){
        chunked_message.push(message.split_at(i * chunk_size).1.split_at(chunk_size).0.to_vec());
    }
    chunked_message.push(message.split_at(message.len() - message.len() % chunk_size).1.to_vec());
    chunked_message
}

// Sends a message of any size to a given tcp stream
pub fn send_message(message: &[u8], message_type: MessageType, tcp_stream: &mut TcpStream, key: &[u8; 32], tag: &mut [u8; 16]) {
    let message_header: MessageHeader = MessageHeader::new(message, message_type);
    let encrypted_message_header: Vec<u8> = encrypt_aes(&message_header.as_bytes(), key, tag);
    tcp_stream.write(encrypted_message_header.as_slice()).unwrap();
    let encrypted_message: Vec<u8> = encrypt_aes(message, key, tag);
    tcp_stream.write(encrypted_message.as_slice()).unwrap();
}

// Receives a message of any size from a tcp stream
pub fn receive_message(tcp_stream: &mut TcpStream, key: &[u8; 32]) -> Vec<u8> {
    let mut encrypted_message_header: [u8; 37] = [0; 37];
    tcp_stream.read(&mut encrypted_message_header).unwrap();
    let message_header_bytes: Vec<u8> = read_and_decrypt_aes(&encrypted_message_header, key);
    let header: MessageHeader = MessageHeader::from_bytes(message_header_bytes.as_slice());
    println!("{:?}", header);
    let mut encrypted_message: Vec<u8> = Vec::with_capacity(28 + header.message_len);
    encrypted_message.resize(28 + header.message_len, 0);
    tcp_stream.read(encrypted_message.as_mut_slice()).unwrap();
    let message: Vec<u8> = read_and_decrypt_aes(encrypted_message.as_slice(), key);
    message
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
