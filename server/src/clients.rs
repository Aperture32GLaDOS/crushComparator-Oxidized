// Copyright (C) 2024  Eshe
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

use std::net::TcpStream;
use std::io::Read;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use openssl::rand::rand_bytes;
use openssl::rsa::Rsa;
use openssl::pkey::{Public, Private};
use utils::{decrypt_rsa, receive_message, send_message, Message};


#[derive(Debug)]
pub enum Event {
    NewClient(Arc<Mutex<Client>>),
    ClientDisconnected(Arc<Mutex<Client>>)
}

#[derive(Debug)]
pub struct Client {
    pub tcp_stream: TcpStream,
    pub aes_key: [u8; 32],
    pub tag: [u8; 16],
    pub events: Arc<Mutex<VecDeque<Event>>>,
    pub to_send: Arc<Mutex<VecDeque<Message>>>,
    pub public_key: Option<Rsa<Public>>,
    pub server_address: Option<String>
}

impl Client{
    pub fn new(mut tcp_stream: TcpStream, key: &Rsa<Private>, events: Arc<Mutex<VecDeque<Event>>>, to_send: Arc<Mutex<VecDeque<Message>>>) -> Client {
        let mut encrypted_aes: [u8; 256] = [0; 256];
        let mut tag: [u8; 16] = [0; 16];
        rand_bytes(&mut tag).unwrap();
        tcp_stream.read(&mut encrypted_aes).expect("256 bytes of RSA encrypted data");
        let aes_key_decrypted: Vec<u8> = decrypt_rsa(&encrypted_aes, key);
        let mut aes_key: [u8; 32] = [0; 32];
        for i in 0..32 {
            aes_key[i] = aes_key_decrypted[i];
        }
        let new_client = Client {tcp_stream, aes_key, tag, events, to_send, public_key: None, server_address: None};
        new_client
    }

    pub fn send_message(&mut self, message: Message) -> Result<(), String> {
        send_message(message, &mut self.tcp_stream, &mut self.aes_key, &mut self.tag)
    }

    pub fn receive_message(&mut self) -> Option<Message> {
        receive_message(&mut self.tcp_stream, &self.aes_key)
    }
}
