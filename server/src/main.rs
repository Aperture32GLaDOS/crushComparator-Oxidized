use std::collections::VecDeque;
use std::net::TcpListener;
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::sleep;
use std::thread;
use std::time::{self, Duration};
mod clients;
use clients::*;
use utils::{get_rsa_private_key, receive_message, Message, MessageType};
use openssl::rsa::Rsa;
use openssl::pkey::Private;

fn send_to_clients(all_clients: Arc<Mutex<Vec<Arc<Mutex<Client>>>>>, to_send: Arc<Mutex<VecDeque<Message>>>, events: Arc<Mutex<VecDeque<Event>>>) {
    loop {
        {
            let mut to_send_deque: MutexGuard<VecDeque<Message>> = to_send.lock().unwrap();
            if to_send_deque.len() > 0 {
                for client in all_clients.lock().unwrap().iter() {
                    let message: Message = to_send_deque.front().unwrap().clone();
                    let mut client_guard: MutexGuard<Client> = client.lock().unwrap();
                    match client_guard.send_message(message) {
                        Ok(_) => {}
                        Err(err) => {
                            println!("{}", err);
                            events.lock().unwrap().push_back(Event::ClientDisconnected(client.clone()));
                        }
                    }
                    to_send_deque.pop_front();
                }
            }
        }
        sleep(time::Duration::from_secs(2));
    }
}

fn handle_events(all_clients: Arc<Mutex<Vec<Arc<Mutex<Client>>>>>, to_send: Arc<Mutex<VecDeque<Message>>>, events: Arc<Mutex<VecDeque<Event>>>) {
    loop {
        {
            let mut events_deque: MutexGuard<VecDeque<Event>> = events.lock().unwrap();
            if events_deque.len() > 0 {
                match events_deque.front().unwrap() {
                    Event::NewClient => {
                        to_send.lock().unwrap().push_back(Message::new("New Client".as_bytes().to_vec(), MessageType::DEBUG));
                    }
                    Event::ClientDisconnected(client) => {
                        println!("Client disconnected");
                        let client_index: usize = all_clients.lock().unwrap().iter().position(|x| x.lock().unwrap().aes_key == client.lock().unwrap().aes_key).unwrap();
                        all_clients.lock().unwrap().remove(client_index);
                    }
                }
                events_deque.pop_front();
            }
        }
        sleep(time::Duration::from_secs(2));
    }
}

fn handle_client_messages(client: Arc<Mutex<Client>>, to_send: Arc<Mutex<VecDeque<Message>>>, events: Arc<Mutex<VecDeque<Event>>>) {
    loop {
        {
            let mut client_guarded: MutexGuard<Client> = client.lock().unwrap();
            let received_message: Option<Message> = client_guarded.receive_message();
            match received_message {
                Some(x) => {},
                None => {
                    events.lock().unwrap().push_back(Event::ClientDisconnected(client.clone()));
                    return
                }
            }
        }
        sleep(Duration::from_secs(2));
    }
}

fn main() -> std::io::Result<()> {
    let mut all_clients: Arc<Mutex<Vec<Arc<Mutex<Client>>>>> = Arc::new(Mutex::new(Vec::new()));
    let events: Arc<Mutex<VecDeque<Event>>> = Arc::new(Mutex::new(VecDeque::new()));
    let to_send_to_clients: Arc<Mutex<VecDeque<Message>>> = Arc::new(Mutex::new(VecDeque::new()));
    let rsa_private_key: Rsa<Private> = get_rsa_private_key("server.priv");
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
                    let cloned_to_send = to_send_to_clients.clone();
                    let cloned_events = events.clone();
                    let cloned_client = new_client_arc_mutex.clone();
                    thread::spawn(move || {
                        handle_client_messages(cloned_client, cloned_to_send, cloned_events);
                    });
                }
                // And append the client to all_clients
                all_clients.lock().unwrap().push(new_client_arc_mutex.clone());
            }
            Err(_) => {}
        }
    }
    Ok(())
}
