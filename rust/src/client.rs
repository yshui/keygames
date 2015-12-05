extern crate rand;
mod num;
mod elgamal;
extern crate rustc_serialize;
extern crate time;
extern crate crypto;
use std::net::{SocketAddrV4, UdpSocket, Ipv4Addr};
use std::fs::File;
use rand::Rng;
use std::io::prelude::*;
use std::collections::HashMap;
use std::io::BufReader;
use num::traits::Num;
use crypto::{blockmodes, aes, buffer};
use crypto::symmetriccipher;
use crypto::symmetriccipher::Encryptor;
use crypto::buffer::{ReadBuffer, WriteBuffer, BufferResult};

use num::BigUint;
fn decrypt(encrypted_data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
	let mut decryptor = aes::cbc_decryptor(
		aes::KeySize::KeySize256,
		key,
		iv,
		blockmodes::PkcsPadding);

	let mut final_result = Vec::<u8>::new();
	let mut read_buffer = buffer::RefReadBuffer::new(encrypted_data);
	let mut buffer = [0; 4096];
	let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

	loop {
		let result = try!(decryptor.decrypt(&mut read_buffer, &mut write_buffer, true));
		final_result.extend(write_buffer.take_read_buffer().take_remaining().iter().map(|&i| i));
		match result {
			BufferResult::BufferUnderflow => break,
			BufferResult::BufferOverflow => { }
		}
	}

	Ok(final_result)
}
fn main() {
	let mut sock = UdpSocket::bind("127.0.0.1:0").unwrap();
	let mut buf = [0; 65536]; //Buf for message
	let my_msg = b"We have been connected";
	//Load my secret key
	let privkey = {
		let mut k = [0; 128]; //1024bits key
		let mut f = File::open("client.priv").unwrap();
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
		let mut f = File::open("server.pub").unwrap();
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

	let mut f = File::create("time.log").unwrap();
	loop {
		let mut send_buf : Vec<u8> = Vec::new();
		let mut key_iv : [u8; 128] = [0;128];
		let mut rng = rand::thread_rng();
		rng.fill_bytes(&mut key_iv);
		let n = BigUint::from_bytes_le(&key_iv);
		let (sigr, sigs) = privkey.sign(&n);
		send_buf.extend(key_iv.iter());
		let mut v = sigr.to_bytes_le();
		v.resize(128, 0);
		send_buf.extend(&v);

		v = sigs.to_bytes_le();
		v.resize(128, 0);
		send_buf.extend(&v);

		println!("{}: {:?}", send_buf.len(), &send_buf);

		let ip = Ipv4Addr::new(127, 0, 0, 1);
		let saddr = SocketAddrV4::new(ip, 12345);
		let msg = pubkey.encrypt(&send_buf);
		sock.send_to(&msg, saddr).unwrap();

		let st = time::get_time();
		let (sz, src) = sock.recv_from(&mut buf).unwrap();
		let et = time::get_time();
		println!("{}", et-st);
		writeln!(f, "{}", et-st);

		let msg2 = decrypt(&buf[0..sz], &key_iv[0..32], &key_iv[32..48]);
		if let Ok(res) = msg2 {
			let s = String::from_utf8(res);
			if let Ok(s2) = s {
				println!("{}", s2);
			} else {
				println!("Decrypt succeeded, but invalid string");
			}
		} else {
			println!("Decrypt Error");
		}
	}
}
