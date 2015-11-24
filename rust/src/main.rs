mod elgamal;
extern crate num;
extern crate rand;
extern crate rustc_serialize;
use std::net::UdpSocket;
use num::bigint::BigInt;
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
		public = elgamal::PublicKey::new(BigInt::from_bytes_le(Sign::Plus, k));

		f.read(&mut k);
		secret = elgamal::PrivateKey::new(BigInt::from_bytes_le(Sign::Plus, k));
	}
	let mut pubkey_db = HashMap::new(); //
	{
		let mut ip = [0; 10]; //IP address and port
		let mut key = [0; 32]; //pubkey
		let mut f = File::open("pubkey_db").unwrap();
		loop {
			let res = f.read(&mut ip);
			if let Err(x) = res {
				break;
			}
			f.read(&mut key);
			pubkey_db.insert(&ip, &key);
		}
	}
	loop {
		let res = sock.recv_from(&mut buf);
		match res {
			Ok((sz, src)) => {
				//Debug
				println!("{:?}", &buf[0..sz]);
				// Decrypt with my secret key
				let msg = secret.decrypt_string(buf.as_slice());

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
