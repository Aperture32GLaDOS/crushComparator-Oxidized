use std::net::TcpStream;
use std::io::Read;
use std::collections::{VecDeque, HashMap};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::{self, sleep};
use std::time::Duration;
use openssl::rand::rand_bytes;
use openssl::rsa::Rsa;
use openssl::pkey::Private;
use utils::{decrypt_rsa, receive_message, send_message, Message};


pub enum Event {
    NewClient,
    ClientDisconnected(Arc<Mutex<Client>>)
}

pub struct Client {
    pub tcp_stream: TcpStream,
    pub aes_key: [u8; 32],
    pub tag: [u8; 16],
    pub events: Arc<Mutex<VecDeque<Event>>>,
    pub to_send: Arc<Mutex<VecDeque<Message>>>
}

impl Client{
    pub fn new(mut tcp_stream: TcpStream, key: &Rsa<Private>, events: Arc<Mutex<VecDeque<Event>>>, to_send: Arc<Mutex<VecDeque<Message>>>) -> Client {
        let mut encrypted_aes: [u8; 256] = [0; 256];
        let mut tag: [u8; 16] = [0; 16];
        rand_bytes(&mut tag);
        tcp_stream.read(&mut encrypted_aes).expect("256 bytes of RSA encrypted data");
        let aes_key_decrypted: Vec<u8> = decrypt_rsa(&encrypted_aes, key);
        let mut aes_key: [u8; 32] = [0; 32];
        for i in 0..32 {
            aes_key[i] = aes_key_decrypted[i];
        }
        events.lock().unwrap().push_back(Event::NewClient);
        let mut new_client = Client {tcp_stream, aes_key, tag, events, to_send};
        new_client
    }

    pub fn send_message(&mut self, message: Message) -> Result<(), String> {
        send_message(message, &mut self.tcp_stream, &mut self.aes_key, &mut self.tag)
    }

    pub fn receive_message(&mut self) -> Option<Message> {
        receive_message(&mut self.tcp_stream, &self.aes_key)
    }
}
