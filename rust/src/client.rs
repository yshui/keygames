mod elgamal;
extern crate rand;
extern crate num;
extern crate rustc_serialize;
use std::net::{SocketAddrV4, UdpSocket, Ipv4Addr};
use std::fs::File;
use rand::Rng;
use std::io::prelude::*;
use std::collections::HashMap;

use num::BigUint;
fn main() {
	let mut sock = UdpSocket::bind("127.0.0.1:0").unwrap();
	let mut buf = [0; 65536]; //Buf for message
	let my_msg = b"We have been connected";
	//Load my secret key
	let (public, secret);
	{
		let mut k = [0; 128]; //1024bits key
		let mut f = File::open("client").unwrap();
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
			let port = (ipb[4] as u16)+(ipb[5] as u16)*256u16;
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
	let mut send_buf : Vec<u8> = Vec::new();
	let mut key_iv : [u8; 128] = [0;128];
	let mut rng = rand::thread_rng();
	rng.fill_bytes(&mut key_iv);
	let n = BigUint::from_bytes_le(&key_iv);
	let (sigr, sigs) = secret.sign(&n);
	send_buf.extend(key_iv.iter());
	let mut v = sigr.to_bytes_le();
	v.resize(128, 0);
	send_buf.extend(&v);

	v = sigs.to_bytes_le();
	v.resize(128, 0);
	send_buf.extend(&v);

	let ip = Ipv4Addr::new(127, 0, 0, 1);
	let saddr = SocketAddrV4::new(ip, 12345);
	let pubkey = pubkey_db.get(&saddr).unwrap();
	let msg = pubkey.encrypt(&send_buf);
	sock.send_to(&msg, saddr).unwrap();
	let (sz, src) = sock.recv_from(&mut buf).unwrap();
	println!("{:?}", &buf[0..sz]);
}
