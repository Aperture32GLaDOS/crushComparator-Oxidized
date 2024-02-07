use std::net::TcpStream;
use std::io::Read;
use openssl::aes::AesKey;
use openssl::rsa::Rsa;
use openssl::pkey::Private;
use utils::{decrypt_rsa, read_and_decrypt_aes};

pub struct Client {
    tcp_stream: TcpStream,
    aes_key: [u8; 32]
}

impl Client{
    pub fn new(mut tcp_stream: TcpStream, key: &Rsa<Private>) -> Client {
        // TODO: Actually get AES key from client in a handshake
        let mut encrypted_aes: [u8; 256] = [0; 256];
        tcp_stream.read(&mut encrypted_aes).expect("256 bytes of RSA encrypted data");
        let aes_key_decrypted: Vec<u8> = decrypt_rsa(&encrypted_aes, key);
        let mut aes_key: [u8; 32] = [0; 32];
        for i in 0..32 {
            aes_key[i] = aes_key_decrypted[i];
        }
        println!("{:?}", aes_key);
        let mut new_client = Client {tcp_stream: tcp_stream, aes_key: aes_key};
        new_client.handle_new_messages();
        new_client
    }

    pub fn handle_new_messages(&mut self) {
        let mut encrypted_data: [u8; 33] = [0; 33];
        self.tcp_stream.read(&mut encrypted_data).unwrap();
        let decrypted: String = String::from_utf8(read_and_decrypt_aes(&encrypted_data, &self.aes_key)).unwrap();
        println!("{}", decrypted);
    }
}
