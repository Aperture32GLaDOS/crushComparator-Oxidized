use std::net::{TcpStream, TcpListener};
mod clients;
use clients::*;
use utils::{get_rsa_private_key, decrypt_rsa};
use openssl::rsa::Rsa;
use openssl::pkey::{Public, Private};

fn main() -> std::io::Result<()> {
    let mut all_clients: Vec<Client> = Vec::new();
    let rsa_private_key: Rsa<Private> = get_rsa_private_key("server.priv");
    let server_socket: TcpListener = TcpListener::bind("127.0.0.1:6666")?;
    for incoming in server_socket.incoming() {
        match incoming {
            Ok(stream) => {all_clients.push(Client::new(stream, &rsa_private_key))}
            Err(_) => {}
        }
    }
    Ok(())
}
