use std::net::TcpStream;
use openssl::rsa::Rsa;
use openssl::pkey::Public;

pub struct Peer {
    tcp_stream: TcpStream,
    aes_key: [u8; 32],
    public_key: Rsa<Public>
}
