use std::collections::{HashMap, VecDeque};
use std::net::TcpListener;
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::sleep;
use std::thread;
use std::time::{self, Duration};
mod clients;
use clients::*;
use utils::{get_rsa_private_key, Message, MessageType};
use openssl::rsa::Rsa;
use openssl::pkey::Private;

// The entrypoint for the thread which constantly sends messages to clients
fn send_to_clients(all_clients: Arc<Mutex<Vec<Arc<Mutex<Client>>>>>, to_send: Arc<Mutex<VecDeque<Message>>>, events: Arc<Mutex<VecDeque<Event>>>) {
    loop {
        sleep(time::Duration::from_millis(250));
        {
            let mut to_send_deque: MutexGuard<VecDeque<Message>> = to_send.lock().unwrap();
            let mut has_succeeded: bool = true;
            if to_send_deque.len() > 0 {
                println!("Trying to send message...");
                println!("{:?}", all_clients.lock().unwrap().first());
                for client in all_clients.lock().unwrap().iter() {
                    let message: Message = to_send_deque.front().unwrap().clone();
                    println!("Trying to get client lock...");
                    let mut client_guard: MutexGuard<Client> = match client.try_lock() {
                        Ok(val) => val,
                        Err(_) => {
                            has_succeeded = false;
                            break;
                        }
                    };
                    println!("Client lock obtained");
                    match message.message_type {
                        // If the message is informing clients of a new peer,
                        MessageType::AddPeer => {
                            // Then there is no need to inform the new peer
                            if client_guard.server_address.is_none() {
                                println!("Not informing due to server address");
                                has_succeeded = false;
                                continue;
                            }
                            if client_guard.server_address.clone().unwrap() == String::from_utf8(message.content.clone()).unwrap().split_terminator(",").collect::<Vec<&str>>()[0] {
                                continue;
                            }
                            println!("Informing client of new peer...");
                        }
                        _ => {}
                    }
                    match client_guard.send_message(message) {
                        Ok(_) => {}
                        Err(err) => {
                            println!("{}", err);
                            events.lock().unwrap().push_back(Event::ClientDisconnected(client.clone()));
                        }
                    }
                }
                if has_succeeded {
                    to_send_deque.pop_front();
                }
            }
        }
    }
}

fn handle_events(all_clients: Arc<Mutex<Vec<Arc<Mutex<Client>>>>>, to_send: Arc<Mutex<VecDeque<Message>>>, events: Arc<Mutex<VecDeque<Event>>>) {
    loop {
        sleep(time::Duration::from_millis(260));
        {
            let mut events_deque: MutexGuard<VecDeque<Event>> = events.lock().unwrap();
            if events_deque.len() > 0 {
                println!("Handling event...");
                match events_deque.front().unwrap() {
                    Event::NewClient(client) => {
                        // Wait for the client to tell us their RSA key as well as their listener's address, as long as waiting for all previous messages
                        // to be handled
                        let client_lock: MutexGuard<Client> = client.lock().unwrap();
                        let mut to_send_lock: MutexGuard<VecDeque<Message>> = match to_send.try_lock() {
                            Ok(val) => val,
                            Err(_) => continue
                        };
                        if client_lock.public_key.is_none() || client_lock.server_address.is_none() || to_send_lock.len() > 0 {
                            continue;
                        }
                        let mut message_content: String;
                        message_content = client_lock.server_address.clone().unwrap();
                        message_content = message_content + "," + &String::from_utf8(client_lock.public_key.clone().unwrap().public_key_to_pem().unwrap()).unwrap();
                        to_send_lock.push_back(Message::new(message_content.as_bytes().to_vec(), MessageType::AddPeer));
                    }
                    Event::ClientDisconnected(client) => {
                        println!("Client disconnected");
                        let client_index: usize = all_clients.lock().unwrap().iter().position(|x| x.lock().unwrap().aes_key == client.lock().unwrap().aes_key).unwrap();
                        all_clients.lock().unwrap().remove(client_index);
                        // Inform the clients that a peer should be removed
                        to_send.lock().unwrap().push_back(Message::new(client.lock().unwrap().tcp_stream.peer_addr().unwrap().ip().to_string().as_bytes().to_vec(), MessageType::RemovePeer));
                    }
                }
                events_deque.pop_front();
            }
        }
    }
}

fn handle_client_messages(client: Arc<Mutex<Client>>, user_crush_client: Arc<Mutex<HashMap<String, Arc<Mutex<Client>>>>>) {
    loop {
        {
            let mut client_guarded: MutexGuard<Client> = client.lock().unwrap();
            client_guarded.tcp_stream.set_read_timeout(Some(Duration::from_millis(200))).unwrap();
            client_guarded.tcp_stream.set_write_timeout(Some(Duration::from_millis(400))).unwrap();
            let received_message: Option<Message> = client_guarded.receive_message();
            match received_message {
                Some(x) => {
                    match x.message_type {
                        MessageType::InformPublicKey => {
                            client_guarded.public_key = Some(Rsa::public_key_from_pem(&x.content).unwrap());
                        },
                        MessageType::InformAddress => {
                            client_guarded.server_address = Some(String::from_utf8(x.content).unwrap());
                        },
                        MessageType::Secret => {
                            println!("Secret obtained from client");
                            let mut user_crush_lock: MutexGuard<HashMap<String, Arc<Mutex<Client>>>> = match user_crush_client.try_lock() {
                                Ok(val) => val,
                                Err(_) => continue
                            };
                            let client_match = user_crush_lock.get(&String::from_utf8(x.content.clone()).unwrap());
                            match client_match {
                                Some(matched_client) => {
                                    let message: Message = Message::new("MATCH OBTAINED".as_bytes().to_vec(), MessageType::DEBUG);
                                    matched_client.lock().unwrap().send_message(message.clone()).unwrap();
                                    client_guarded.send_message(message).unwrap();
                                    user_crush_lock.remove(&String::from_utf8(x.content.clone()).unwrap());
                                }
                                None => {user_crush_lock.insert(String::from_utf8(x.content).unwrap(), client.clone());}
                            }
                        },
                        _ => {}
                    }
                }, None => {}
            }
        }
        sleep(Duration::from_millis(600));
    }
}

fn main() -> std::io::Result<()> {
    let all_clients: Arc<Mutex<Vec<Arc<Mutex<Client>>>>> = Arc::new(Mutex::new(Vec::new()));
    let events: Arc<Mutex<VecDeque<Event>>> = Arc::new(Mutex::new(VecDeque::new()));
    let to_send_to_clients: Arc<Mutex<VecDeque<Message>>> = Arc::new(Mutex::new(VecDeque::new()));
    let rsa_private_key: Rsa<Private> = get_rsa_private_key("server.priv");
    let user_crush_client: Arc<Mutex<HashMap<String, Arc<Mutex<Client>>>>> = Arc::new(Mutex::new(HashMap::new()));
    let server_socket: TcpListener = TcpListener::bind("127.0.0.1:6666")?;
    // Spawn the thread which sends messages to clients
    {
        let cloned_to_send_to_clients = to_send_to_clients.clone();
        let cloned_all_clients = all_clients.clone();
        let cloned_events = events.clone();
        thread::spawn(move || {
            send_to_clients(cloned_all_clients, cloned_to_send_to_clients, cloned_events);
        });
    }
    // Spawn the thread which handles events
    {
        let cloned_to_send_to_clients = to_send_to_clients.clone();
        let cloned_all_clients = all_clients.clone();
        let cloned_events = events.clone();
        thread::spawn(move || {
            handle_events(cloned_all_clients, cloned_to_send_to_clients, cloned_events);
        });
    }
    for incoming in server_socket.incoming() {
        // On a client join,
        match incoming {
            Ok(stream) => {
                let new_client: Client = Client::new(stream, &rsa_private_key, events.clone(), to_send_to_clients.clone());
                let new_client_arc_mutex: Arc<Mutex<Client>> = Arc::new(Mutex::new(new_client));
                // Spawn a new thread to handle the client's messages
                {
                    let cloned_client = new_client_arc_mutex.clone();
                    let cloned_user_crush_client = user_crush_client.clone();
                    thread::spawn(move || {
                        handle_client_messages(cloned_client, cloned_user_crush_client);
                    });
                }
                // And append the client to all_clients
                all_clients.lock().unwrap().push(new_client_arc_mutex.clone());
                events.lock().unwrap().push_back(Event::NewClient(new_client_arc_mutex));
            }
            Err(_) => {}
        }
    }
    Ok(())
}
