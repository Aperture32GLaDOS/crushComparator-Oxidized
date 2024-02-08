use std::net::TcpStream;
use std::io::Read;
use openssl::rsa::Rsa;
use openssl::pkey::Private;
use utils::decrypt_rsa;

pub struct Client {
    tcp_stream: TcpStream,
    aes_key: [u8; 32]
}

impl Client{
    pub fn new(mut tcp_stream: TcpStream, key: &Rsa<Private>) -> Client {
        let mut encrypted_aes: [u8; 256] = [0; 256];
        tcp_stream.read(&mut encrypted_aes).expect("256 bytes of RSA encrypted data");
        let aes_key_decrypted: Vec<u8> = decrypt_rsa(&encrypted_aes, key);
        let mut aes_key: [u8; 32] = [0; 32];
        for i in 0..32 {
            aes_key[i] = aes_key_decrypted[i];
        }
        let mut new_client = Client {tcp_stream, aes_key};
        new_client.handle_new_messages();
        new_client
    }

    pub fn handle_new_messages(&mut self) {
        println!("{:?}", utils::receive_message(&mut self.tcp_stream, &self.aes_key))
    }
}
