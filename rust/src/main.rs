mod elgamal;
extern crate num;
extern crate rand;
extern crate rustc_serialize;
use std::net::UdpSocket;
use num::bigint::{BigInt, BigUint};
use num::bigint::Sign;
use std::io;
use std::io::prelude::*;
use std::fs::File;
use std::collections::HashMap;
fn main() {
	let mut sock = UdpSocket::bind("127.0.0.1:12345").unwrap();
	let mut buf = [0; 65536]; //Buf for message
	let my_msg = "We have been connected";
	//Load my secret key
	let (public, secret);
	{
		let mut k = [0; 32]; //128bits key
		let mut f = File::open("secret").unwrap();
		f.read(&mut k).unwrap();
		let p = BigUint::from_bytes_le(&k);
		f.read(&mut k).unwrap();
		let g = BigUint::from_bytes_le(&k);
		f.read(&mut k).unwrap();
		let x = BigUint::from_bytes_le(&k);
		f.read(&mut k).unwrap();
		let y = BigUint::from_bytes_le(&k);

		public = elgamal::PublicKey {g: g, p:p, y:y, bit_size:128};

		secret = elgamal::PrivateKey {g:g, p:p, x:x};
	}
	let mut pubkey_db = HashMap::new(); //
	{
		let mut ip = [0; 10]; //IP address and port
		let mut k = [0; 32]; //pubkey
		let mut f = File::open("pubkey_db").unwrap();
		loop {
			let res = f.read(&mut ip);
			if let Err(x) = res {
				break;
			}
			f.read(&mut k);
			let p = BigUint::from_bytes_le(&k);
			f.read(&mut k);
			let g = BigUint::from_bytes_le(&k);
			f.read(&mut k);
			let y = BigUint::from_bytes_le(&k);
			let s = elgamal::PublicKey {g:g, p:p, y:y, bit_size:128};
			pubkey_db.insert(ip, s);
		}
	}
	loop {
		let res = sock.recv_from(&mut buf);
		match res {
			Ok((sz, src)) => {
				//Debug
				println!("{:?}", &buf[0..sz]);
				// Decrypt with my secret key
				let msg = secret.decrypt(buf);

				// Lookup the public key
				if let Some(k) = pubkey_db.get(src) {
					//Verify signature
					if k.verify_string(msg) {
						// Send back a piece of text
						// encrypted with given key
						let ciphertext = k.encrypt_string(my_msg);
						sock.send_to(&ciphertext, src);
					}
				}
			},
			Err(_) => break
		}
	}
}
