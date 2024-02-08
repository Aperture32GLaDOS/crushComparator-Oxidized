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

use std::collections::VecDeque;
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream};
use std::io::{self, Read, Write};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::{self, sleep};
use std::time::Duration;
use utils::{decrypt_rsa, encrypt_rsa, get_rsa_public_key, receive_message, send_message, Message, MessageType};
use openssl::rsa::Rsa;
use openssl::pkey::{Public, Private};
use openssl::rand::rand_bytes;
mod peers;
use peers::*;

// The entrypoint for a thread which constantly waits for info from the main server
fn listen_to_server(server_socket: Arc<Mutex<TcpStream>>, server_key: [u8; 32], events: Arc<Mutex<VecDeque<Event>>>, all_peers: Arc<Mutex<Vec<Arc<Mutex<Peer>>>>>) {
    loop {
        sleep(Duration::from_millis(200));
        {
            let mut server_socket_guarded: MutexGuard<TcpStream> = server_socket.lock().unwrap();
            server_socket_guarded.set_read_timeout(Some(Duration::from_millis(500))).unwrap();
            let message: Message = match receive_message(&mut server_socket_guarded, &server_key) {
                Some(value) => value,
                None => {continue;}
            };
            match message.message_type {
                // If there is a new peer,
                MessageType::AddPeer => {
                    let message_content: String = String::from_utf8(message.content).unwrap();
                    println!("New peer being added at {}...", message_content.split_terminator(",").collect::<Vec<&str>>()[0]);
                    let new_peer: Peer = Peer::new(message_content.split_terminator(",").collect::<Vec<&str>>()[0].to_string(), Rsa::public_key_from_pem(message_content.split_terminator(",").collect::<Vec<&str>>()[1].as_bytes()).unwrap());
                    let mutex_peer: Arc<Mutex<Peer>> = Arc::new(Mutex::new(new_peer));
                    {
                        all_peers.lock().unwrap().push(mutex_peer.clone());
                    }
                    // Add the PeerAdded event to the event queue
                    events.lock().unwrap().push_back(Event::PeerAdded(mutex_peer));
                }
                MessageType::RemovePeer => {
                    let peers_guarded: MutexGuard<Vec<Arc<Mutex<Peer>>>> = all_peers.lock().unwrap();
                    let address: String = String::from_utf8(message.content).unwrap();
                    events.lock().unwrap().push_back(Event::PeerRemoved(peers_guarded.clone().into_iter().find(|x| x.lock().unwrap().tcp_stream.peer_addr().unwrap().to_string() == address).unwrap()));
                }
                _ => {}
            }
        }
    }
}

// The entrypoint for the thread which constantly listens for new peers to connect
fn listen_for_peers(port: String, all_peers: Arc<Mutex<Vec<Arc<Mutex<Peer>>>>>, events: Arc<Mutex<VecDeque<Event>>>, server_socket: Arc<Mutex<TcpStream>>, key: Rsa<Private>, aes_key: [u8; 32]) {
    let listener: TcpListener = TcpListener::bind("127.0.0.1:".to_owned() + &port).unwrap();
    println!("Now listening on port {}...", listener.local_addr().unwrap());
    // Inform the server of the listener's address
    let message: Message = Message::new(listener.local_addr().unwrap().to_string().as_bytes().to_vec(), MessageType::InformAddress);
    let mut tag: [u8; 16] = [0; 16];
    rand_bytes(&mut tag).unwrap();
    send_message(message, &mut server_socket.lock().unwrap(), &aes_key, &mut tag).unwrap();
    loop {
        {
            // When a new peer connects,
            let mut new_stream: TcpStream = listener.accept().unwrap().0;
            // Handshake with them
            let mut aes_key: [u8; 32] = [0; 32];
            let mut received_rsa_data: [u8; 256] = [0; 256];
            {
                new_stream.read(&mut received_rsa_data).unwrap();
            }
            let decrypted_data = decrypt_rsa(&received_rsa_data, &key);
            for i in 0..32 {
                aes_key[i] = decrypted_data[i];
            }
            println!("Connecting to new peer...");
            // And get their public key
            let message: Message = Message::new(new_stream.peer_addr().unwrap().to_string().as_bytes().to_vec(), MessageType::RequestPublicKey);
            println!("Connected to new peer");
            let mut tag: [u8; 16] = [0; 16];
            rand_bytes(&mut tag).unwrap();
            send_message(message, &mut new_stream, &aes_key, &mut tag).unwrap();
            let received_message: Message = receive_message(&mut new_stream, &aes_key).unwrap();
            let new_peer: Peer = Peer { tcp_stream: new_stream, aes_key, public_key: Rsa::public_key_from_pem(received_message.content.as_slice()).unwrap(), tag };
            println!("New peer obtained from server");
            let mutex_peer: Arc<Mutex<Peer>> = Arc::new(Mutex::new(new_peer));
            {
                events.lock().unwrap().push_back(Event::PeerAdded(mutex_peer.clone()));
            }
            {
                all_peers.lock().unwrap().push(mutex_peer);
            }
        }
    }
}

// The entrypoint for the thread which constantly handles messages from a peer
fn handle_peer_messages(peer: Arc<Mutex<Peer>>, public_key: Arc<Rsa<Public>>) {
    loop {
        sleep(Duration::from_millis(200));
        {
            let message: Message = match peer.lock().unwrap().get_message() {
                Some(value) => value,
                None => continue
            };
            // If they want our public key,
            match message.message_type {
                MessageType::RequestPublicKey => {
                    // Send it to them
                    let message: Message = Message::new(public_key.public_key_to_pem().unwrap(), MessageType::NORMAL);
                    peer.lock().unwrap().send_message(message);
                },
                _ => {}
            }
        }
    }
}

// The entrypoint for the thread which constantly handles events
fn handle_events(events: Arc<Mutex<VecDeque<Event>>>, server_socket: Arc<Mutex<TcpStream>>, public_key: Arc<Rsa<Public>>, user_crush: String, crush_user: String, server_key: [u8; 32]) {
    loop {
        {
            let mut event_guard: MutexGuard<VecDeque<Event>> = events.lock().unwrap();
            if event_guard.len() > 0 {
                let event: &Event = event_guard.front().unwrap();
                match event {
                    // If a new peer has been added,
                    Event::PeerAdded(peer) => {
                        {
                            let cloned_peer = peer.clone();
                            let cloned_public_key = public_key.clone();
                            thread::spawn(move || {
                                // Spawn a new thread to handle any traffic from them
                                handle_peer_messages(cloned_peer, cloned_public_key);
                            });
                        }
                        // And send the server the shared secret with them
                        let aes_key = peer.lock().unwrap().aes_key;
                        let secret1: Vec<u8>= format!("{}{:x?}", user_crush, aes_key).as_bytes().to_vec();
                        let secret2: Vec<u8> = format!("{}{:x?}", crush_user, aes_key).as_bytes().to_vec();
                        let mut tag: [u8; 16] = [0; 16];
                        rand_bytes(&mut tag).unwrap();
                        println!("Sending...");
                        send_message(Message::new(secret1, MessageType::Secret), &mut server_socket.lock().unwrap(), &server_key, &mut tag).unwrap();
                        send_message(Message::new(secret2, MessageType::Secret), &mut server_socket.lock().unwrap(), &server_key, &mut tag).unwrap();
                        println!("Secret sent");
                    },
                    Event::PeerRemoved(_) => {}
                }
            }
            event_guard.pop_front();
        }
        sleep(Duration::from_millis(200));
    }
}

fn main() -> std::io::Result<()>{
    let mut user_name: String = String::new();
    let mut crush_name: String = String::new();
    let stdin = io::stdin();
    print!("Enter your name: ");
    io::stdout().flush()?;
    stdin.read_line(&mut user_name)?;
    print!("Enter the name of your crush: ");
    io::stdout().flush()?;
    stdin.read_line(&mut crush_name)?;
    let user_crush: String = user_name.clone() + &crush_name;
    let crush_user: String = crush_name + &user_name;
    let server_public_key: Rsa<Public> = get_rsa_public_key("server.pub");
    let private_key: Rsa<Private> = Rsa::generate(2048).unwrap();
    let public_key: Arc<Rsa<Public>> = Arc::new(Rsa::from_public_components(private_key.n().to_owned().unwrap(), private_key.e().to_owned().unwrap()).unwrap());
    let mut aes_key: [u8; 32] = [0; 32];
    let mut tag: [u8; 16] = [0; 16];
    let socket: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(127,0,0,1), 0);
    let events: Arc<Mutex<VecDeque<Event>>> = Arc::new(Mutex::new(VecDeque::new()));
    let all_peers: Arc<Mutex<Vec<Arc<Mutex<Peer>>>>> = Arc::new(Mutex::new(Vec::new()));
    rand_bytes(&mut aes_key)?;
    rand_bytes(&mut tag)?;
    let server_connection: Arc<Mutex<TcpStream>> = Arc::new(Mutex::new(TcpStream::connect("127.0.0.1:6666")?));
    let encrypted_aes_key: Vec<u8> = encrypt_rsa(&aes_key, &server_public_key);
    server_connection.lock().unwrap().write(&encrypted_aes_key).unwrap();
    {
        let cloned_key = aes_key.clone();
        let cloned_socket = server_connection.clone();
        let cloned_events = events.clone();
        let cloned_peers = all_peers.clone();
        thread::spawn(move || {
            listen_to_server(cloned_socket, cloned_key, cloned_events, cloned_peers)
        });
    }
    {
        let cloned_peers = all_peers.clone();
        let cloned_events = events.clone();
        let cloned_socket = server_connection.clone();
        thread::spawn(move || {
            listen_for_peers(socket.port().to_string(), cloned_peers, cloned_events, cloned_socket, private_key, aes_key.clone());
        });
    }
    {
        let cloned_events = events.clone();
        let cloned_socket = server_connection.clone();
        let cloned_key = public_key.clone();
        thread::spawn(move || {
            handle_events(cloned_events, cloned_socket, cloned_key, user_crush, crush_user, aes_key);
        });
    }
    let message: Message = Message::new(public_key.public_key_to_pem().unwrap(), MessageType::InformPublicKey);
    println!("Sending RSA key...");
    send_message(message, &mut server_connection.lock().unwrap(), &mut aes_key, &mut tag).unwrap();
    println!("Sent RSA key!");
    loop {
        sleep(Duration::from_secs(20));
    }
}
