mod elgamal;
extern crate num;
extern crate rustc_serialize;
use num::BigUint;
use std::iter::repeat;
use std::io::Write;
use std::fs::File;
fn biguint_to_vec(a: &BigUint, sz: usize) -> Vec<u8> {
	let mut res : Vec<u8> = Vec::new();
	res.extend(a.to_bytes_le());
	assert!(res.len() <= sz);
	let pad = sz-res.len();
	res.extend(repeat(0).take(pad));
	res
}
fn main() {
	let (p, s) = elgamal::generate_keys(1024);
	println!("Get server key");
	let mut f = File::create("server").unwrap();
	let mut buf = biguint_to_vec(&p.p, 128);
	f.write_all(&buf).unwrap();
	buf = biguint_to_vec(&p.g, 128);
	f.write_all(&buf).unwrap();
	buf = biguint_to_vec(&s.x, 128);
	f.write_all(&buf).unwrap();
	buf = biguint_to_vec(&p.y, 128);
	f.write_all(&buf).unwrap();
	let (p2, s2) = elgamal::generate_keys(1024);
	println!("Get client key");
	f = File::create("client").unwrap();
	buf = biguint_to_vec(&p2.p, 128);
	f.write_all(&buf).unwrap();
	buf = biguint_to_vec(&p2.g, 128);
	f.write_all(&buf).unwrap();
	buf = biguint_to_vec(&s2.x, 128);
	f.write_all(&buf).unwrap();
	buf = biguint_to_vec(&p2.y, 128);
	f.write_all(&buf).unwrap();

	f = File::create("pubkey_db").unwrap();
	let ip1 = [127,0,0,1,57,48];
	f.write_all(&ip1).unwrap();
	f.write_all(&biguint_to_vec(&p.p, 128)).unwrap();
	f.write_all(&biguint_to_vec(&p.g, 128)).unwrap();
	f.write_all(&biguint_to_vec(&p.y, 128)).unwrap();
	let ip2 = [127,0,0,1,103,43];
	f.write_all(&ip2).unwrap();
	f.write_all(&biguint_to_vec(&p2.p, 128)).unwrap();
	f.write_all(&biguint_to_vec(&p2.g, 128)).unwrap();
	f.write_all(&biguint_to_vec(&p2.y, 128)).unwrap();
}
