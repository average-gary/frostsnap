//! Key-0 image signing for the Mk4 test files. Shared by `#[path]` include so
//! the artifact tests and the transfer tests sign with one implementation.
#![allow(dead_code)]

use frostsnap_coordinator::mk4_firmware::{two_range_digest, MK4_HEADER_MAGIC};
use sha2::{Digest, Sha256};

/// Coldcard dev key 0's private scalar, `coldcard-firmware/stm32/keys/00.pem`.
/// PUBLISHED (`stm32/keys/README.md`): this is a format key, not a secret, and
/// the test below proves it is the key `PUBKEY0` names.
pub const KEY0_SECRET: [u8; 32] = [
    0xa4, 0xc2, 0x38, 0x13, 0x84, 0x61, 0x65, 0x8f, 0xe0, 0xe1, 0x7a, 0xb1, 0x5d, 0x90, 0xf5, 0x19,
    0x4f, 0x49, 0x3d, 0x34, 0x7a, 0x77, 0xd4, 0x64, 0xee, 0xff, 0xa3, 0x1f, 0x45, 0x4e, 0xa8, 0xdf,
];
pub const HDR: usize = 0x3f80;
pub const OK_LEN: u32 = 65 * 4096; // above the 256 KiB floor, 4 KiB aligned

pub fn put(img: &mut [u8], at: usize, v: u32) {
    img[at..at + 4].copy_from_slice(&v.to_le_bytes());
}

/// An image of `size` bytes whose header declares `declared`, with a header
/// every `checkfw` rule accepts, then signed with key 0.
pub fn synth(size: usize, declared: u32, hw_compat: u32) -> Vec<u8> {
    let mut v: Vec<u8> = (0..size).map(|i| (i * 7 + i / 251) as u8).collect();
    put(&mut v, HDR, MK4_HEADER_MAGIC);
    v[HDR + 4..HDR + 12].copy_from_slice(&[0x26, 0x09, 0x23, 0x12, 0, 0, 0, 0]);
    v[HDR + 12..HDR + 20].copy_from_slice(b"6.0.1t\0\0");
    put(&mut v, HDR + 20, 0);
    put(&mut v, HDR + 24, declared);
    put(&mut v, HDR + 28, 0);
    put(&mut v, HDR + 32, hw_compat);
    sign(&mut v);
    v
}

/// (Re)sign in place over the two ranges, as `signit.py` does.
pub fn sign(v: &mut [u8]) {
    use secp256k1::{Message, Secp256k1, SecretKey};
    let fw_check: [u8; 32] = Sha256::digest(two_range_digest(v).0).into();
    let sk = SecretKey::from_slice(&KEY0_SECRET).unwrap();
    let sig = Secp256k1::new().sign_ecdsa(&Message::from_digest(fw_check), &sk);
    v[HDR + 64..HDR + 128].copy_from_slice(&sig.serialize_compact());
}

pub fn ok_image() -> Vec<u8> {
    synth(OK_LEN as usize, OK_LEN, 0x28)
}
