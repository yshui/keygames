mod elgamal;
extern crate rand;
extern crate rustc_serialize;
extern crate crypto;
mod num;
use std::net::UdpSocket;
use num::bigint::BigUint;
use num::traits::Num;
use std::io;
use std::io::prelude::*;
use std::fs::File;
use std::io::BufReader;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::collections::HashMap;
use crypto::{blockmodes, aes, buffer};
use crypto::symmetriccipher::Encryptor;
use crypto::buffer::{ReadBuffer, WriteBuffer, BufferResult};
fn main() {
	let mut sock = UdpSocket::bind("127.0.0.1:12345").unwrap();
	let mut buf = [0; 65536]; //Buf for message
	let my_msg = b"We have been connected";
	//Load my secret key
	let privkey = {
		let mut k = [0; 128]; //1024bits key
		let mut f = File::open("server.priv").unwrap();
		let mut reader = BufReader::new(f);
		let mut line = String::new();

		reader.read_line(&mut line).unwrap();
		let g = BigUint::from_str_radix(&line.trim(), 10).unwrap();

		line = String::new();
		reader.read_line(&mut line).unwrap();
		let p = BigUint::from_str_radix(&line.trim(), 10).unwrap();

		line = String::new();
		reader.read_line(&mut line).unwrap();
		let x = BigUint::from_str_radix(&line.trim(), 10).unwrap();

		elgamal::PrivateKey {g:g, p:p, x:x, bit_size:1024}
	};
	let pubkey = {
		let mut f = File::open("client.pub").unwrap();
		let mut reader = BufReader::new(f);
		let mut line = String::new();

		reader.read_line(&mut line).unwrap();
		let g = BigUint::from_str_radix(&line.trim(), 10).unwrap();

		line = String::new();
		reader.read_line(&mut line).unwrap();
		let p = BigUint::from_str_radix(&line.trim(), 10).unwrap();

		line = String::new();
		reader.read_line(&mut line).unwrap();
		let x = BigUint::from_str_radix(&line.trim(), 10).unwrap();

		elgamal::PublicKey {g:g, p:p, y:x, bit_size:1024}
	};
	loop {
		let res = sock.recv_from(&mut buf);
		match res {
			Ok((sz, src)) => {
				if let SocketAddr::V4(x) = src {
					//Debug
					// Decrypt with my secret key
					let msg = privkey.decrypt(&buf[0..sz]);
					println!("{}: {:?}", msg.len(), &msg);
					assert!(msg.len() == 384);
					let key = BigUint::from_bytes_le(&msg[0..128]);
					let (sigr, sigs) = (BigUint::from_bytes_le(&msg[128..256]),
							    BigUint::from_bytes_le(&msg[256..384]));

					//Verify signature
					if pubkey.verify(&sigr, &sigs, &key) {
						//Message is a 256 bit key
						let mut en = aes::cbc_encryptor(aes::KeySize::KeySize256, &msg[0..32], &msg[32..48], blockmodes::PkcsPadding);
						let mut res : Vec<u8> = Vec::new();
						let mut read_buf = buffer::RefReadBuffer::new(&my_msg[..]);
						let mut buf = [0; 4096];
						let mut write_buf = buffer::RefWriteBuffer::new(&mut buf);
						loop {
							let result = en.encrypt(&mut read_buf, &mut write_buf, true).unwrap();

							res.extend(write_buf.take_read_buffer().take_remaining().iter().cloned());

							match result {
								BufferResult::BufferUnderflow => break,
								BufferResult::BufferOverflow => { }
							}
						}
						sock.send_to(&res, src).unwrap();
					} else {
						println!("Sign verfiy error");
					}
				}
			},
			Err(_) => break
		}
	}
}
