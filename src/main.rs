use kyber_pke::{decrypt, encrypt, pke_keypair};

use clap::Parser;

use serde::{Serialize, Deserialize, Serializer, Deserializer};
use serde_json::from_slice;

use std::{
    collections::HashMap,
    net::SocketAddr,
    io::{self, Write, BufRead},
    sync::Arc,
};

use tokio::{
    sync::Mutex,
    net::UdpSocket,
    time::{timeout, Duration},
    task,
};

use sha3::{Digest, Sha3_256};
use hex::encode as hex_encode;

use colored::*;

const KYBER_PUBLICKEYBYTES: usize = 1568;
const KYBER_SECRETKEYBYTES: usize = 3168;
const UDP_BUFFER_SIZE: usize = 65000;
const TIMEOUT_DURATION: u64 = 20;

#[derive(Parser)]
#[clap(name = "kypeer", version = "0.1.0", about = "secure P2P messaging with CRYSTALS-kyber")]
struct Args {
    address: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Peer {
    id: String,
    address: String,
    #[serde(serialize_with = "serialize_public_key", deserialize_with = "deserialize_public_key")]
    pk: [u8; KYBER_PUBLICKEYBYTES]
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Message {
    to: String,
    from: String,
    content: Vec<u8>
}

fn generate_id(pk: &[u8; KYBER_PUBLICKEYBYTES]) -> String {
    let mut hasher = Sha3_256::new();
    hasher.update(pk);
    hex_encode(hasher.finalize())
}

fn serialize_public_key<S>(pk: &[u8; KYBER_PUBLICKEYBYTES], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_bytes(pk.as_ref())
}

fn deserialize_public_key<'de, D>(deserializer: D) -> Result<[u8; KYBER_PUBLICKEYBYTES], D::Error>
where
    D: Deserializer<'de>,
{
    let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
    let mut public_key = [0u8; KYBER_PUBLICKEYBYTES];
    public_key.copy_from_slice(&bytes);
    Ok(public_key)
}

// server

async fn handle_peer(src: SocketAddr, socket: &UdpSocket, peer: Peer, dht: &Arc<Mutex<HashMap<String, Peer>>>, history: &Arc<Mutex<HashMap<String, Vec<Message>>>>, my_id: String, pk: &[u8; KYBER_PUBLICKEYBYTES]) {
    println!("\n{}", format!("Received Peer From {}", src).green());
    io::stdout().flush().unwrap();

    // add peer
    let mut dht = dht.lock().await;
    dht.insert(peer.id.clone(), peer.clone());

    println!("{}", format!("Added Peer {}", peer.id).green());
    io::stdout().flush().unwrap();

    // send peer info back
    let me = Peer { id: my_id.clone(), address: socket.local_addr().unwrap().to_string(), pk: pk.clone() };
    let serialized_me = serde_json::to_vec(&me).unwrap();

    if let Err(e) = timeout(Duration::from_secs(TIMEOUT_DURATION), socket.send_to(&serialized_me, src)).await {
        eprintln!("{}", format!("Error: Failed to send peer information back to {}: {}", src, e).red());
    } else {
        println!("{}", format!("Sent current peer info back to {}", src).green());
    }
}

async fn handle_message(src: SocketAddr, socket: &UdpSocket, message: Message, dht: &Arc<Mutex<HashMap<String, Peer>>>, history: &Arc<Mutex<HashMap<String, Vec<Message>>>>, my_id: String) {
    println!("{}", format!("\nReceived Message From {}", message.from).green());
    io::stdout().flush().unwrap();

    // save message

    let mut history = history.lock().await;

    let messages = history.entry(message.from.clone()).or_insert(vec![]);
    messages.push(message.clone());

    println!("{}", "Message Saved".green());
    io::stdout().flush().unwrap();

    // send acknowledgement back
    let acknowledgement = Message { to: message.from.clone(), from: my_id.clone(), content: vec![] };
    let serialized_acknowledgement = serde_json::to_vec(&acknowledgement).unwrap();

    if let Err(e) = timeout(Duration::from_secs(TIMEOUT_DURATION), socket.send_to(&serialized_acknowledgement, src)).await {
        eprintln!("{}", format!("Error: Failed to send acknowledgment to {}: {}", src, e).red());
    } else {
        println!("{}", "Acknowledgment Sent".green());
    }

}

async fn handle_string(src: SocketAddr, socket: &UdpSocket, id: String, dht: &Arc<Mutex<HashMap<String, Peer>>>) {
    let dht = dht.lock().await;

    // case 1: peer is found
    if let Some(peer) = dht.get(&id) {

        // send peer back
        let serialized_peer = serde_json::to_vec(peer).unwrap();

        if let Err(e) = timeout(Duration::from_secs(TIMEOUT_DURATION), socket.send_to(&serialized_peer, src)).await {
            eprintln!("{}", format!("Error: Failed to send peer information back to {}: {}", src, e).red());
        } else {
            println!("{}", format!("Sent peer info for ID {} back to {}", id, src).green());
        }
        
    // case 2: peer is not found
    } else {

        // send peer not found response back
        let empty_peer = Peer { id: String::new(), address: String::new(), pk: [0u8; KYBER_PUBLICKEYBYTES] };
        let serialized_empty_peer = serde_json::to_vec(&empty_peer).unwrap();

        if let Err(e) = timeout(Duration::from_secs(TIMEOUT_DURATION), socket.send_to(&serialized_empty_peer, src)).await {
            eprintln!("{}", format!("Error: Failed to send peer not found response back to {}: {}", src, e).red());
        } else {
            println!("{}", format!("Sent peer not found response back to {}", src).green());
        }

    }

}

async fn handle_incoming(data: &[u8], src: SocketAddr, socket: &UdpSocket, dht: Arc<Mutex<HashMap<String, Peer>>>, history: Arc<Mutex<HashMap<String, Vec<Message>>>>, pk: &[u8; KYBER_PUBLICKEYBYTES], my_id: String) {
    if data.len() > UDP_BUFFER_SIZE {
        eprintln!("\n{}", "Error: Message size exceeds UDP buffer limit".red());
        io::stdout().flush().unwrap();
        return;
    }

    // handle
    if let Ok(message) = from_slice::<Message>(data) {
        handle_message(src, socket, message, &dht, &history, my_id).await;
    } else if let Ok(peer) = from_slice::<Peer>(data) {
        handle_peer(src, socket, peer, &dht, &history, my_id, &pk).await;
    } else if let Ok(id) = from_slice::<String>(data) {
        handle_string(src, socket, id, &dht).await;
    } else {
        eprintln!("\n{}", "Error: Failed to deserialize data".red());
        io::stdout().flush().unwrap();
        return;
    }

}

async fn start_listener(my_id: String, address: String, dht: Arc<Mutex<HashMap<String, Peer>>>, history: Arc<Mutex<HashMap<String, Vec<Message>>>>, pk: [u8; KYBER_PUBLICKEYBYTES]) {

    // start server
    let socket = Arc::new(UdpSocket::bind(address).await.expect("Failed to bind server socket"));
    println!("{}", format!("\n\nListening on {}...\n", socket.local_addr().unwrap()).green().bold());
    io::stdout().flush().unwrap();

    let mut buf = [0u8; UDP_BUFFER_SIZE];

    loop {

        // handle
        match socket.recv_from(&mut buf).await {
            Ok((size, src)) => {
                let buf = buf.clone();
                let src = src.clone();
                let socket = Arc::clone(&socket);
                let dht = Arc::clone(&dht);
                let history = Arc::clone(&history);
                let my_id = my_id.clone();
                tokio::spawn(async move {
                    handle_incoming(&buf[..size], src, &socket, dht, history, &pk, my_id).await;
                });
            }
            Err(e) => {
                eprintln!("\n{}", format!("Error: Failed to receive message: {}", e).red());
                io::stdout().flush().unwrap();
            }
        };
        print!("{}", "kypeer> ".blue().bold());
        io::stdout().flush().unwrap();
    }
}

// client

// helper to display peers
async fn view_peers(dht: &Arc<Mutex<HashMap<String, Peer>>>) {
    let dht = dht.lock().await;

    println!("{}", format!("\nPeers in DHT:\n").green());
    io::stdout().flush().unwrap(); 

    for (id, peer) in dht.iter() {
        println!("{}", format!("ID: {}, Address: {}\n", id, peer.address).yellow());
        io::stdout().flush().unwrap();
    }
}

async fn connect_peer(my_id: &str, my_address: &str, address: &str, dht: &Arc<Mutex<HashMap<String, Peer>>>, pk: &[u8; KYBER_PUBLICKEYBYTES]) {

    let me = Peer { id: my_id.to_string(), address: my_address.to_string(), pk: pk.clone() };
    let serialized_me = serde_json::to_vec(&me).unwrap();

    // send info to new peer
    if let Ok(socket) = UdpSocket::bind("0.0.0.0:0").await {

        if let Err(e) = socket.send_to(&serialized_me, address).await {
            eprintln!("{}", format!("Error: Failed to connect: {}", e).red());
            io::stdout().flush().unwrap();
            return;
        }

        let mut buf = [0u8; UDP_BUFFER_SIZE];

        // save new peer info
        match timeout(Duration::from_secs(TIMEOUT_DURATION), socket.recv_from(&mut buf)).await {
            Ok(result) => {
                match result {
                    Ok((size, _src)) => {
                        if let Ok(response_peer) = serde_json::from_slice::<Peer>(&buf[..size]) {
                            let mut dht = dht.lock().await;
                            
                            let id = response_peer.id.clone();
                            dht.insert(id.clone(), response_peer);

                            println!("{}", format!("Added Peer {}", id).green());
                            io::stdout().flush().unwrap();
                        } else {
                            eprintln!("{}", "Error: Failed to deserialize peer information".red());
                            io::stdout().flush().unwrap();
                        }
                    }
                    Err(e) => {
                        eprintln!("{}", format!("Error: Failed to receive response: {}", e).red());
                        io::stdout().flush().unwrap();
                    }
                }
            }
            Err(e) => {
                eprintln!("{}", format!("Error: Failed to receive response: {}", e).red());
                io::stdout().flush().unwrap();
            }
        }
    } else {
        eprintln!("{}", "Error: Failed to create socket".red());
        io::stdout().flush().unwrap();
    }

}

// helper to display messages with specified peer
async fn view_messages(id: String, history: &Arc<Mutex<HashMap<String, Vec<Message>>>>, sk: &[u8; KYBER_SECRETKEYBYTES]) {
    let history = history.lock().await;

    if let Some(messages) = history.get(&id) {
        println!("{}", format!("\nViewing Messages With Peer {}:\n ", id).green());
        io::stdout().flush().unwrap();

        for message in messages {
            let content_bytes = decrypt(sk, &message.content).unwrap();
            let plaintext = String::from_utf8(content_bytes).expect("Invalid UTF-8");
            println!("{}", format!("To: {} \nFrom: {} \nMessage: {}\n\n", message.to, message.from, plaintext).yellow());
            io::stdout().flush().unwrap();
        }
    } else {
        println!("{}", format!("\nNo Messages With Peer {}\n", id).yellow());
        io::stdout().flush().unwrap();
    }
}

async fn send_message(my_id: String, id: String, content: String, dht: &Arc<Mutex<HashMap<String, Peer>>>, history: &Arc<Mutex<HashMap<String, Vec<Message>>>>, pk: &[u8; KYBER_PUBLICKEYBYTES]) {
    let dht = dht.lock().await;
    let mut history = history.lock().await;

    // case 1: peer is found in dht
    if let Some(peer) = dht.get(&id) {

        // encrypt message

        let pkp = &peer.pk;
        let content_bytes = content.as_bytes().to_vec();

        let nonce: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
        let ciphertext = encrypt(pkp, &content_bytes, &nonce).unwrap();

        let message = Message { to: id.clone(), from: my_id.clone(), content: ciphertext };
        let serialized_message = serde_json::to_vec(&message).unwrap();

        if serialized_message.len() > UDP_BUFFER_SIZE {
            eprintln!("Error: Message size exceeds UDP buffer limit");
            return;
        }

        // send message

        if let Ok(socket) = UdpSocket::bind("0.0.0.0:0").await {
            match timeout(Duration::from_secs(TIMEOUT_DURATION), socket.send_to(&serialized_message, &peer.address)).await {
                Ok(result) => {
                    
                    if let Err(e) = result {
                        eprintln!("{}", format!("Error: Failed to send message: {}", e).red());
                        io::stdout().flush().unwrap();
                        return;
                    }

                    println!("{}", format!("Message Sent To Peer {}", id).green());
                    io::stdout().flush().unwrap();

                    // wait for acknowledgement

                    let mut buf = [0u8; UDP_BUFFER_SIZE];

                    match timeout(Duration::from_secs(TIMEOUT_DURATION), socket.recv_from(&mut buf)).await {

                        Ok(Ok((size, _src))) => {
                            if let Ok(_response_message) = serde_json::from_slice::<Message>(&buf[..size]) {
                                println!("{}", "Message successfully delivered".green());

                                // save message

                                let ciphertext = encrypt(pk, &content_bytes, &nonce).unwrap();
                                let message = Message { to: id.clone(), from: my_id.clone(), content: ciphertext };

                                let messages = history.entry(id.to_string()).or_insert(vec![]);
                                messages.push(message);
                            } else {
                                eprintln!("{}", "Error: Received unexpected response".red());
                                io::stdout().flush().unwrap();
                            }
                        }
                        Ok(Err(e)) => {
                            eprintln!("{}", format!("Error: Failed to receive acknowledgment: {}", e).red());
                            io::stdout().flush().unwrap();
                        }
                        Err(_) => {
                            println!("{}", "Timeout waiting for acknowledgment".yellow());
                            io::stdout().flush().unwrap();
                        }
                    }

                }
                Err(_) => {
                    println!("{}", "Timeout".yellow());
                    io::stdout().flush().unwrap();
                }
            }

        } else {
            eprintln!("{}", "Error: Failed to create socket".red());
            io::stdout().flush().unwrap();
        }

    // case 2: peer is not found in dht
    } else {

        let mut peer_found = false;

        for peer in dht.values() {

            // request for specified peer info

            let request_peer = id.clone();
            let serialized_request = serde_json::to_vec(&request_peer).unwrap();

            if let Ok(socket) = UdpSocket::bind("0.0.0.0:0").await {
                match timeout(Duration::from_secs(TIMEOUT_DURATION), socket.send_to(&serialized_request, &peer.address)).await {
                    Ok(result) => {

                        if let Err(e) = result {
                            eprintln!("{}", format!("Error: Failed to request peer information from {}: {}", peer.address, e).red());
                            io::stdout().flush().unwrap();
                            return;
                        }

                        println!("{}", format!("Requested peer information from {}", peer.address).green());
                        io::stdout().flush().unwrap();

                        let mut buf = [0u8; UDP_BUFFER_SIZE];

                        match timeout(Duration::from_secs(TIMEOUT_DURATION), socket.recv_from(&mut buf)).await {
                            Ok(Ok((size, _src))) => {

                                if let Ok(response_peer) = serde_json::from_slice::<Peer>(&buf[..size]) {

                                    if response_peer.id == id {
                                        peer_found = true;

                                        // encrypt message

                                        let nonce: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();

                                        let content_bytes = content.as_bytes().to_vec();
                                        let ciphertext = encrypt(&response_peer.pk, &content_bytes, &nonce).unwrap();

                                        let nonce: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
                                        
                                        let message = Message { to: id.clone(), from: my_id.clone(), content: ciphertext };
                                        let serialized_message = serde_json::to_vec(&message).unwrap();

                                        if serialized_message.len() > UDP_BUFFER_SIZE {
                                            eprintln!("Error: Message size exceeds UDP buffer limit");
                                            return;
                                        }

                                        // send message

                                        if let Ok(socket) = UdpSocket::bind("0.0.0.0:0").await {
                                            match timeout(Duration::from_secs(TIMEOUT_DURATION), socket.send_to(&serialized_message, &response_peer.address)).await {
                                                Ok(Ok(_)) => {

                                                    // save message

                                                    let ciphertext = encrypt(pk, &content_bytes, &nonce).unwrap();
                                                    let message = Message { to: id.clone(), from: my_id.clone(), content: ciphertext };

                                                    let messages = history.entry(id.to_string()).or_insert(vec![]);
                                                    messages.push(message);

                                                    println!("{}", format!("Message Sent To Peer {}", id).green());
                                                    io::stdout().flush().unwrap();
                                                    break;
                                                }
                                                Ok(Err(e)) => {
                                                    eprintln!("{}", format!("Error: Failed to send message to {}: {}", response_peer.address, e).red());
                                                    io::stdout().flush().unwrap();
                                                }
                                                Err(_) => {
                                                    println!("{}", "Timeout".yellow());
                                                    io::stdout().flush().unwrap();
                                                }
                                            }
                                        } else {
                                            eprintln!("{}", "Error: Failed to create socket".red());
                                            io::stdout().flush().unwrap();
                                        }

                                    }

                                } else {
                                    eprintln!("{}", "Error: Failed to deserialize peer information".red());
                                    io::stdout().flush().unwrap();
                                }
                            }
                            Ok(Err(e)) => {
                                eprintln!("{}", format!("Error: Failed to receive peer information: {}", e).red());
                                io::stdout().flush().unwrap();
                            }
                            Err(_) => {
                                println!("{}", "Timeout".yellow());
                                io::stdout().flush().unwrap();
                            }
                        }
                    }
                    Err(_) => {
                        println!("{}", "Timeout".yellow());
                        io::stdout().flush().unwrap();
                    }
                }

            } else {
                eprintln!("{}", "Error: Failed to create socket".red());
                io::stdout().flush().unwrap();
            }
        }

        if !peer_found {
            println!("{}", format!("Peer {} not found in DHT", id).yellow());
            io::stdout().flush().unwrap();
        }

    }
}

// helper to read line
async fn read_line() -> Result<String, io::Error> {
    task::spawn_blocking(|| {
        let mut input = String::new();
        io::stdin().lock().read_line(&mut input)?;
        Ok(input)
    }).await.expect("Failed to read line")
}

async fn handle_commands(my_id: String, my_address: String, dht: Arc<Mutex<HashMap<String, Peer>>>, history: Arc<Mutex<HashMap<String, Vec<Message>>>>, pk: [u8; KYBER_PUBLICKEYBYTES], sk: [u8; KYBER_SECRETKEYBYTES]) {

    loop {

       // prompt
       print!("{}", "kypeer> ".blue().bold());
       io::stdout().flush().unwrap();

       // get input
       let input = read_line().await.unwrap();
       let args = input.trim().split_whitespace().collect::<Vec<&str>>();
       if args.is_empty() {
            continue;
        }

        // handle
        match args[0] {
            "view-peers" => view_peers(&dht).await,
            "connect-peer" if args.len() == 2 => connect_peer(&my_id, &my_address, args[1], &dht, &pk).await,
            "view-messages" if args.len() == 2 => view_messages(args[1].to_string(), &history, &sk).await,
            "send-message" if args.len() >= 3 => send_message(my_id.clone(), args[1].to_string(), args[2..].join(" ").to_string(), &dht, &history, &pk).await,
            _ => {
                eprintln!("{}", "Error: Invalid Command".red());
                io::stdout().flush().unwrap();
            }
        }

    }
}

#[tokio::main]
#[allow(unused_variables)]
async fn main() {

    // generate keys
    let (pk, sk) = pke_keypair().unwrap();

    // generate id
    let my_id = generate_id(&pk);
    println!("Your ID is {}.", my_id.blue().bold());
    io::stdout().flush().unwrap();

    // get address
    let args = Args::parse();
    let my_address = args.address;

    let dht: Arc<Mutex<HashMap<String, Peer>>> = Arc::new(Mutex::new(HashMap::new()));

    let history: Arc<Mutex<HashMap<String, Vec<Message>>>> = Arc::new(Mutex::new(HashMap::new()));

    // spawn listener
    let listener_handle = {
        let my_id = my_id.clone();
        let my_address = my_address.clone();
        let dht = Arc::clone(&dht);
        let history = Arc::clone(&history);
        let pk = pk.clone();
        tokio::spawn(async move {
            start_listener(my_id, my_address, dht, history, pk).await;
        })
    };

    // spawn handler
    tokio::spawn(async move {
        let my_id = my_id.clone();
        let my_address = my_address.clone();
        let dht = Arc::clone(&dht);
        let history = Arc::clone(&history);
        let pk = pk.clone();
        let sk = sk.clone();
        handle_commands(my_id, my_address, dht, history, pk, sk).await;
    });

    listener_handle.await.unwrap();

}

