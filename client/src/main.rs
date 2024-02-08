use std::net::TcpStream;
use std::io::Write;
use utils::{get_rsa_public_key, encrypt_rsa, MessageType};
use openssl::rsa::Rsa;
use openssl::pkey::Public;
use openssl::rand::rand_bytes;

fn main() -> std::io::Result<()>{
    let server_public_key: Rsa<Public> = get_rsa_public_key("server.pub");
    let mut aes_key: [u8; 32] = [0; 32];
    let mut tag: [u8; 16] = [0; 16];
    rand_bytes(&mut aes_key)?;
    rand_bytes(&mut tag)?;
    let mut server_connection: TcpStream = TcpStream::connect("127.0.0.1:6666")?;
    let encrypted_aes_key: Vec<u8> = encrypt_rsa(&aes_key, &server_public_key);
    server_connection.write(&encrypted_aes_key).unwrap();
    let secret_message: &[u8] = "Hello".as_bytes();
    utils::send_message(secret_message, MessageType::NORMAL, &mut server_connection, &aes_key, &mut tag);
    Ok(())
}
