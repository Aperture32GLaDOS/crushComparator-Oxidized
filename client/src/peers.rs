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
