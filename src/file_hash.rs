use std::path::Path;
use digest::Digest;
use anyhow::{Result, Context, Error};
use std::fs::File;
use std::io::{BufReader, Read};
use crate::foundation::extract_str;

/// # Hash a file with a buffer backing
/// __for best performance `block_size` == cipher block size__
pub fn hash_file_buffered<D: Digest>(path: &Path, buffer_size: usize, block_size: usize) -> Result<String, Error> {
	let mut block = vec![0x00 as u8; block_size];

	let canon_path = match path.exists() {
		true => {
			let canon = path.canonicalize()
				.with_context(|| {
					format!("Failed to make canon path from {}", path.display())
				})?;
			canon
		}
		,
		false => return Err(anyhow::anyhow!("No file named {}", path.display())),
	};

	let mut reader = match File::open(path) {
		Ok(fp) => BufReader::with_capacity(buffer_size,fp),
		Err(e) => return Err(anyhow::anyhow!("Could not open {}", canon_path.display())),
	};

	let mut digest = D::new();

	loop {
		match reader.read(&mut block) {
			Ok(read) => if read > 0 && read <= block.len() {
				digest.input(&mut block[0 .. read]);
			} else {
				return Ok(extract_str::<D>(digest))
			}
			Err(e) => return Err(anyhow::anyhow!("Error reading from buffer: {}", e))
		}
	};

}