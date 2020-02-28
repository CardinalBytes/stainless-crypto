use std::path::Path;
use sha2::{Sha256};
use digester::file_hash::hash_file_buffered;
use hex::encode;

fn main() {
    let mut buf = [0 as u8; 32];
    hash_file_buffered::<Sha256>(
        Path::new(""),
        64,
        4096,
        &mut buf).unwrap();

    println!("{}", encode(buf))
}