use std::net::TcpStream;
use std::io::Write;
use std::sync::{Arc, Mutex};
use openssl::rand::rand_bytes;
use openssl::rsa::Rsa;
use openssl::pkey::Public;
use utils::{encrypt_rsa, receive_message, send_message, Message};

pub enum Event {
    PeerAdded(Arc<Mutex<Peer>>),
    PeerRemoved(Arc<Mutex<Peer>>)
}

pub struct Peer {
    pub tcp_stream: TcpStream,
    pub aes_key: [u8; 32],
    pub public_key: Rsa<Public>,
    pub tag: [u8; 16]
}

impl Peer {
    pub fn new(address: String, public_key: Rsa<Public>) -> Self {
        let mut tcp_stream: TcpStream = TcpStream::connect(address).unwrap();
        let mut aes_key: [u8; 32] = [0; 32];
        rand_bytes(&mut aes_key).unwrap();
        let mut tag: [u8; 16] = [0; 16];
        rand_bytes(&mut tag).unwrap();
        tcp_stream.write(&encrypt_rsa(&aes_key, &public_key)).unwrap();
        Peer {tcp_stream, aes_key, public_key, tag}
    }

    pub fn get_message(&mut self) -> Option<Message> {
        receive_message(&mut self.tcp_stream, &self.aes_key)
    }

    pub fn send_message(&mut self, message: Message) {
        send_message(message, &mut self.tcp_stream, &self.aes_key, &mut self.tag).unwrap();
    }
}
