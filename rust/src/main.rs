mod elgamal;
extern crate num;
extern crate rand;
extern crate rustc_serialize;
extern crate crypto;
use std::net::UdpSocket;
use num::bigint::BigUint;
use std::io;
use std::io::prelude::*;
use std::fs::File;
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
	let (public, secret);
	{
		let mut k = [0; 128]; //1024bits key
		let mut f = File::open("server").unwrap();
		f.read(&mut k).unwrap();
		let p = BigUint::from_bytes_le(&k);
		f.read(&mut k).unwrap();
		let g = BigUint::from_bytes_le(&k);
		f.read(&mut k).unwrap();
		let x = BigUint::from_bytes_le(&k);
		f.read(&mut k).unwrap();
		let y = BigUint::from_bytes_le(&k);

		public = elgamal::PublicKey {g: g.clone(), p:p.clone(), y:y, bit_size:1024};

		secret = elgamal::PrivateKey {g:g, p:p, x:x, bit_size:1024};
	}
	let mut pubkey_db = HashMap::new(); //
	{
		let mut ipb = [0; 6]; //IP address and port
		let mut k = [0; 128]; //pubkey
		let mut f = File::open("pubkey_db").unwrap();
		loop {
			let res = f.read(&mut ipb);
			if let Err(_) = res {
				break;
			}
			let ip = Ipv4Addr::new(ipb[0], ipb[1], ipb[2], ipb[3]);
			let port = (ipb[4] as u16)+(ipb[5] as u16)*256;
			let saddr = SocketAddrV4::new(ip, port);
			f.read(&mut k).unwrap();
			let p = BigUint::from_bytes_le(&k);
			f.read(&mut k).unwrap();
			let g = BigUint::from_bytes_le(&k);
			f.read(&mut k).unwrap();
			let y = BigUint::from_bytes_le(&k);
			let s = elgamal::PublicKey {g:g, p:p, y:y, bit_size:1024};
			pubkey_db.insert(saddr, s);
		}
	}
	loop {
		let res = sock.recv_from(&mut buf);
		match res {
			Ok((sz, src)) => {
				if let SocketAddr::V4(x) = src {
					//Debug
					println!("{:?}", &buf[0..sz]);
					// Decrypt with my secret key
					assert!(sz == 384);
					let msg = secret.decrypt(&buf);
					let key = BigUint::from_bytes_le(&msg[0..128]);
					let (sigr, sigs) = (BigUint::from_bytes_le(&msg[128..256]),
							    BigUint::from_bytes_le(&msg[256..384]));

					// Lookup the public key
					if let Some(k) = pubkey_db.get(&x) {
						//Verify signature
						if k.verify(&sigr, &sigs, &key) {
							//Message is a 256 bit key
							let mut en = aes::cbc_encryptor(aes::KeySize::KeySize256, &msg[0..32], &msg[32..64], blockmodes::PkcsPadding);
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
						}
					}
				}
			},
			Err(_) => break
		}
	}
}
