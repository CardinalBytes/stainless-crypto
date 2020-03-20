use std::path::Path;
use digest::Digest;
use anyhow::{Result, Error};
use std::fs::File;
use std::io::{BufReader, Read};
use crate::hashing::naloc_extract_bin;

/// # Hash a file with a buffer backing no allocation for result
/// __for best performance `block_size` == cipher block size__
pub fn naloc_hash_file<D: Digest>(path: &Path, block_size: usize, buff_capacity: usize,
                                     digest_buffer: &mut [u8]) -> Result<(), Error> {
	let mut digest = D::new();
	let mut block = vec![0x00 as u8; block_size];


	let mut reader = match File::open(path) {
		Ok(fp) =>
			BufReader::with_capacity(buff_capacity, fp),
		Err(_) => return Err(anyhow::anyhow!("Could not open {}", path.display())),
	};

	loop {
		let read = reader.read(block.as_mut_slice())?;
		if read == block_size  {
			digest.input(&mut block);
		} else {
			digest.input(&mut block[0 .. read]);
			naloc_extract_bin::<D>(digest, digest_buffer)?;
			drop(reader);
			return Ok(())
		}
	}
}