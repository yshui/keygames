/*!
* Elgamal public key cryptography implementation in Rust.
*
* - Key generation
* - Signature generation and verification (https://en.wikipedia.org/wiki/ElGamal_signature_scheme)
* - Encryption and Decryption (https://en.wikipedia.org/wiki/ElGamal_encryption)
* 
* Copyright (c) 2014, Brandon Hamilton
* All rights reserved.
* 
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions are met:
* 
* 1. Redistributions of source code must retain the above copyright notice, this
*    list of conditions and the following disclaimer. 
* 2. Redistributions in binary form must reproduce the above copyright notice,
*    this list of conditions and the following disclaimer in the documentation
*    and/or other materials provided with the distribution.
* 
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
* ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
* ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
* (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
* LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
* ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
* SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

//#![desc = "Elgamal public key cryptography."]
//#![license = "BSD"]

extern crate rand;
extern crate rustc_serialize;

use std::cmp;
use num::integer::Integer;
use num::traits::{Signed, Num};
use num::bigint::{BigInt,BigUint,RandBigInt,ToBigInt};
use num::{Zero, One};
use rustc_serialize::hex::{ToHex, FromHex};
use std::string::FromUtf8Error;
use std::iter::repeat;
//use std::num::{Zero, One, FromStrRadix, ToStrRadix};

//#[deriving(Show)]
pub struct PublicKey {
    pub g: BigUint, 
    pub p: BigUint,
    pub y: BigUint,
    pub bit_size: usize // Assumed to be 128
}

//#[deriving(Show)]
pub struct PrivateKey {
    pub g: BigUint, 
    pub p: BigUint,
    pub x: BigUint,
    pub bit_size: usize
}

// Modular exponentiation
// https://en.wikipedia.org/wiki/Modular_exponentiation
fn pow_mod(base: &BigUint, exponent: &BigUint, modulus: &BigUint) -> BigUint {
    let zero: BigUint = Zero::zero();
    let one: BigUint  = One::one();

    let mut result: BigUint = One::one();
    let mut e     : BigUint = exponent.clone();
    let mut b     : BigUint = base.clone();

    while e > zero {
        if e.is_odd() {
            result = ( &result * &b ) % modulus;
        }
        e = e >> 1;
        b = ( &b * &b ) % modulus;
    }
    result
}

// Modular multiplicative inverse using Extended Euclidean Algorithm
// https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm
fn inv_mod(num: &BigUint, modulus: &BigUint) -> Option<BigUint> {
    let zero: BigInt = Zero::zero();
    let mut x: BigInt = Zero::zero();
    let mut y: BigInt = One::one();
    let mut u: BigInt = One::one();
    let mut v: BigInt = Zero::zero();

    let mut a: BigInt = num.to_bigint().unwrap();
    let mut b: BigInt = modulus.to_bigint().unwrap();

    while a != zero {
        let q = &b / &a;
        let r = &b % &a;
        let m = &x - &u*&q;
        let n = &y - &v*&q;
        b = a; a = r;
        x = u; y = v;
        u = m; v = n;
    }

    if b == One::one() {
        let result = if x.is_negative() {
            (x + modulus.to_bigint().unwrap()).to_biguint().unwrap()
        } else {
            x.to_biguint().unwrap() % modulus
        };
        Some(result)
    } else {
        None
    }
}


// Miller-Rabin Primality Test
// https://en.wikipedia.org/wiki/Miller-Rabin_primality_test
fn is_prime_number(num: &BigUint, certainty: u32) -> bool {
    let zero: BigUint = Zero::zero();
    let one : BigUint = One::one();
    let two = &one + &one;

    if *num == two       { return true }
    if num.is_even() { return false }

    let num_less_one = num - &one;

    // write n-1 as 2**s * d
    let mut d = num_less_one.clone();
    let mut s = 0u32;
    while d.is_even()  {
        d = d >> 1;
        s = s+1;
    }

    let mut k = 0;
    let mut rng = rand::thread_rng();

    // Test for probable prime
    while k < certainty {
        let a = rng.gen_biguint_range(&two, num);
        let mut x = pow_mod(&a, &d, num);
        if x != one && x != num_less_one {
            let mut r = 0;
            loop {
                x = (&x * &x) % num;
                if x == num_less_one {
                    break;
                } else if x == one || r == s-1 {
                    return false
                }
                r = r+1;
            }
        }
        k += 2;
    }
    true
}

// Random Prime Generation
fn random_prime(bit_size: usize, certainty: u32) -> BigUint {
    let zero: BigUint = Zero::zero();
    let one : BigUint = One::one();
    let two = &one + &one;
    let mut rng = rand::thread_rng();
    let mut target = rng.gen_biguint(bit_size);
    if &target % &two == zero { target = &target + &one }
    let mut pcount = 0;
    while !is_prime_number(&target, certainty) {
        target = &target + &two;
        println!("{}", pcount);
        pcount = pcount+1;
    }
    target
}

fn random_prime_default(bit_size: usize) -> BigUint {
    random_prime(bit_size, 128)
}

// Hex string padding
fn pad_hex_str(s: String, len: usize) -> String {
    if s.len() < len {
        let mut new_s = String::with_capacity(len);
        let z = ['0'];
        new_s.extend(z.iter().cycle().take(len - s.len()));
        new_s.push_str(&s);
        return new_s
    }
    s
}

// Key generation 
pub fn generate_keys(bit_size: usize) -> (PublicKey, PrivateKey) {

    let one: BigUint = One::one();
    let zero : BigUint = Zero::zero();
    let two = &one+&one;
    let mut rng = rand::thread_rng();

    // Create a random large prime number
    // Adapt the method used in pycrypto
    let (q, p);
    let mut pcount = 0;
    loop {
        let tq = random_prime_default(bit_size-1);
        let tp = &two*&tq+&one;
        pcount = pcount+1;
        println!("Try prime No.{}", pcount);
        if is_prime_number(&tp, 128) {
            q = tq;
            p = tp;
            break;
        }
    }

    // Randomly chose a generator of the multiplicative group of integers modulo p (Zp)
    let g;
    pcount = 0;
    loop {
        let mut tg = rng.gen_biguint_range(&BigUint::from_str_radix("3", 10).unwrap(), &p);
        pcount = pcount+1;
        println!("Try generator No.{}", pcount);
        if pow_mod(&tg, &two, &p) == one {
            continue;
        }
        if pow_mod(&tg, &q, &p) == one {
            continue;
        }
        let pm1 = &p - &one;
        if &pm1 % &tg == zero {
            continue;
        }
        let ginv = inv_mod(&tg, &p).unwrap();
        if &pm1 % &ginv == zero {
            continue;
        }
        g = tg;
        break;
    }

    // Randomly choose a secret key x with 1 < x < p − 1
    let bound = &p - &one;
    let mut x: BigUint = rng.gen_biguint_range(&two, &bound);
    // Compute y = g^x mod p
    let y = pow_mod(&g, &x, &p);

    ( PublicKey{ p: p.clone(), g: g.clone(), y: y, bit_size: bit_size }, PrivateKey{ p: p.clone(), g: g.clone(), x: x, bit_size: bit_size } )
}

impl PrivateKey {
    // Signature generation
    pub fn sign(&self, m: &BigUint) -> (BigUint, BigUint) {
        let one: BigUint = One::one();
        let zero : BigUint = Zero::zero();
        let two = &one+&one;
        let mut rng = rand::thread_rng();
        let bound = &self.p - &one;
        let bx = bound.to_bigint().unwrap();
        loop {
            let mut k: BigUint = rng.gen_biguint_range(&two, &bound);
            while k.gcd(&bound) != one {
                k = rng.gen_biguint_range(&two, &bound);
            };
            let r = pow_mod(&self.g, &k, &self.p);
            let mx = m.to_bigint().unwrap();
            let xr = (&self.x*&r).to_bigint().unwrap();
            let mut xx = (mx-xr) % &bx;
            if xx.is_negative() {
                xx = &xx+&bx;
            }
            let s = xx.to_biguint().unwrap() * inv_mod( &k, &bound ).unwrap() % &bound;
            if s != zero {
                return (r, s);
            }
        }
    }

    // Signature generation (String encoding)
    pub fn sign_string(&self, m: &str) -> String {
        let (r, s) = self.sign( &Num::from_str_radix( &m.as_bytes().to_hex(), 16).unwrap() );
        let r_hex   = r.to_str_radix(16);
        let s_hex   = s.to_str_radix(16);
        let max_len = cmp::max( r_hex.len(), s_hex.len() );
        format!("{}{}", pad_hex_str(r_hex, max_len), pad_hex_str(s_hex, max_len))
    }

    // Decryption
    pub fn raw_decrypt(&self, c1: &BigUint, c2: &BigUint) -> BigUint {
        (c2 * inv_mod(&pow_mod(c1, &self.x, &self.p), &self.p).unwrap()) % &self.p
    }
    pub fn decrypt(&self, m: &[u8]) -> Vec<u8> {
        let bsz = self.bit_size/8;
        let c1 = BigUint::from_bytes_le(&m[0..bsz]);
        let s = inv_mod(&pow_mod(&c1, &self.x, &self.p), &self.p).unwrap();
        let mut res : Vec<u8> = Vec::new();
        assert!(m.len() % bsz == 0);
        for i in 1..m.len()/bsz {
            let c2 = BigUint::from_bytes_le(&m[i*bsz..(i+1)*bsz]);
            let x = (c2*&s)%&self.p;
            let v = x.to_bytes_le();
            let pad = bsz-v.len();
            println!("{}", pad);
            res.extend(v);
            res.extend(repeat(0).take(pad));
        }
        //Remove padding
        println!("{:?}", res);
        let pad_len = res.len()-res[res.len()-1] as usize;
        res.truncate(pad_len as usize);
        res
    }

}

impl PublicKey {
    // Signature verification
    pub fn verify(&self, r: &BigUint, s: &BigUint, m: &BigUint) -> bool {
        let zero: BigUint = Zero::zero();
        if r < &zero || r >= &self.p || s < &zero || s >= &self.p {
            return false
        }
        let left  = pow_mod(&self.g, m, &self.p);
        let right = ( pow_mod(&self.y, r, &self.p) * pow_mod(r, s, &self.p) ) % &self.p;
        left == right
    }
/*
    // Signature verification (String encoding)
    pub fn verify_string(&self, sig: &str, m: &str) -> bool {
        let r: BigUint = Num::from_str_radix(sig.slice_to(sig.len() / 2), 16).unwrap();
        let s: BigUint = Num::from_str_radix(sig.slice_from(sig.len() / 2), 16).unwrap();
        self.verify(&r, &s, &Num::from_str_radix( m.as_bytes().to_hex().as_slice(), 16).unwrap() )
    }
*/

    // Encryption
    pub fn raw_encrypt(&self, m: &BigUint) -> (BigUint, BigUint) {
        assert!(m < &self.p);
        let one: BigUint = One::one();
        let mut rng = rand::thread_rng();
        let k: BigUint = rng.gen_biguint_range(&one, &(&self.p - &one));
        let c1 = pow_mod(&self.g, &k, &self.p);
        let c2 = ( pow_mod(&self.y, &k, &self.p) * m ) % &self.p;
        (c1, c2)
    }

    pub fn encrypt (&self, m: &[u8]) -> Vec<u8> {
        let mut res : Vec<u8> = Vec::new();
        let bsz = self.bit_size/8;
        let one: BigUint = One::one();
        let mut rng = rand::thread_rng();
        let k: BigUint = rng.gen_biguint_range(&one, &(&self.p - &one));
        let c1 = pow_mod(&self.g, &k, &self.p);
        let mut v = c1.to_bytes_le();
        v.resize(bsz, 0);
        res.extend(c1.to_bytes_le());
        for i in 0..m.len()/bsz {
            let mp = BigUint::from_bytes_le(&m[i*bsz..(i+1)*bsz]);
            let c2 = (pow_mod(&self.y, &k, &self.p)*mp)%&self.p;
            v = c2.to_bytes_le();
            v.resize(bsz, 0);
            res.extend(v);
        }
        let pad : BigUint;
        //PKCS7 padding
        if m.len() % bsz == 0 {
            let u : Vec<u8> = repeat(bsz as u8).take(bsz).collect();
            pad = BigUint::from_bytes_le(&u);
        } else {
            let begin = m.len()-m.len()%bsz;
            let mut x : Vec<u8> = m[begin..].iter().cloned().collect();
            x.extend(repeat((bsz-(m.len()%bsz)) as u8).take(bsz-m.len()%bsz));
            pad = BigUint::from_bytes_le(&x);
        }
        let c2 = (pow_mod(&self.y, &k, &self.p)*pad)%&self.p;
        v = c2.to_bytes_le();
        v.resize(bsz, 0);
        res.extend(c2.to_bytes_le());
        res
    }

}

#[cfg(test)]
mod test_elgamal {
    use super::{generate_keys, is_prime_number, pow_mod};
    use num::bigint::BigUint;
    use std::from_str::FromStr;

    #[test]
    fn test_miller_rabin() {
        let composite = "1298074214633706835075030044377085";
        let prime     = "1298074214633706835075030044377087";
        let known_composite: BigUint = FromStr::from_str(composite).unwrap();
        let known_prime: BigUint = FromStr::from_str(prime).unwrap();
        assert!(!is_prime_number(&known_composite, 128));
        assert!(is_prime_number(&known_prime, 128));
    }

    #[test]
    fn test_keygen() {
        let (public_key, private_key) = generate_keys(128);
        assert!(public_key.bit_size == 128);
        assert!(public_key.p == private_key.p && public_key.g == private_key.g);
        assert!(public_key.y == pow_mod(&public_key.g, &private_key.x, &public_key.p));
    }

    #[test]
    fn test_encryption() {
        let (public_key, private_key) = generate_keys(128);
        let plaintext = "Secret";
        let ciphertext = public_key.encrypt_string(plaintext);
        let decrytped_plaintext = private_key.decrypt_string(ciphertext.as_slice());
        assert!(plaintext == decrytped_plaintext.as_slice());
    }

    #[test]
    fn test_signature() {
        let (public_key, private_key) = generate_keys(128);
        let ciphertext = public_key.encrypt_string("Secret");
        let signature = private_key.sign_string(ciphertext.as_slice());
        let verified  = public_key.verify_string(signature.as_slice(), ciphertext.as_slice());
        assert!(verified);
    }
}
// vim: set et sw=4 :
