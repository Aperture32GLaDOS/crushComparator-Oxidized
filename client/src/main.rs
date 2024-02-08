use std::net::TcpStream;
use std::io::Write;
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::sleep;
use std::time::Duration;
use utils::{encrypt_rsa, get_rsa_public_key, receive_message, Message, MessageType};
use openssl::rsa::Rsa;
use openssl::pkey::Public;
use openssl::rand::rand_bytes;
mod peers;
use peers::*;

fn listen_to_server(server_socket: Arc<Mutex<TcpStream>>, server_key: [u8; 32]) {
    loop {
        {
            let mut server_socket_guarded: MutexGuard<TcpStream> = server_socket.lock().unwrap();
            println!("{:?}", receive_message(&mut server_socket_guarded, &server_key));
        }
        sleep(Duration::from_secs(2));
    }
}

fn main() -> std::io::Result<()>{
    let server_public_key: Rsa<Public> = get_rsa_public_key("server.pub");
    let mut aes_key: [u8; 32] = [0; 32];
    let mut tag: [u8; 16] = [0; 16];
    rand_bytes(&mut aes_key)?;
    rand_bytes(&mut tag)?;
    let mut server_connection: TcpStream = TcpStream::connect("127.0.0.1:6666")?;
    let encrypted_aes_key: Vec<u8> = encrypt_rsa(&aes_key, &server_public_key);
    server_connection.write(&encrypted_aes_key).unwrap();
    let mut message: Message = Message::new("Hello".as_bytes().to_vec(), MessageType::NORMAL);
    utils::send_message(message, &mut server_connection, &aes_key, &mut tag);
    message = Message::new("YO".as_bytes().to_vec(), MessageType::DEBUG);
    utils::send_message(message, &mut server_connection, &mut aes_key, &mut tag);
    Ok(())
}
