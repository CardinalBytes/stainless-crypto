use digest::Digest;
use anyhow::Result;
use hex::encode;

pub fn bin_oneshot<D: Digest>(data: &[u8]) -> Vec<u8> {
	let result = D::digest(data);
	Vec::from(result.as_slice())
}

pub fn str_oneshot<D: Digest>(data: &[u8]) -> String {
	let data = bin_oneshot::<D>(data);
	encode(data)
}

pub fn naloc_bin_oneshot<D: Digest>(data: &[u8], result: &mut [u8]) -> Result<()> {
	let digest = D::digest(data);
	if result.len() < digest.len() {
		Err(anyhow::anyhow!("the size of the result buffer is insufficient for the chosen digest"))
	} else {
		result.clone_from_slice(digest.as_slice());
		Ok(())
	}
}

pub fn extract_bin<D: Digest>(digest: D) -> Vec<u8> {
	Vec::from(digest.result().as_slice())
}

pub fn extract_str<D: Digest>(digest: D) -> String {
	encode(extract_bin::<D>(digest))
}

pub fn naloc_extract_bin<D: Digest>(digest: D, result: &mut [u8]) -> Result<()> {
	let digest = digest.result();
	if result.len() < digest.len() {
		Err(anyhow::anyhow!("the size of the result buffer is insufficient for the chosen digest"))
	} else {
		result.clone_from_slice(digest.as_slice());
		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use sha2::{Sha256};
	use hex::encode;
	use test::Bencher;
	use std::fs::File;
	use std::path::Path;
	use std::io::Read;
	extern crate test;

	#[test]
	fn test_hash() {
		let r = bin_oneshot::<Sha256>(b"test_string");
		let r_s = str_oneshot::<Sha256>(b"test_string");
		assert_eq!(encode(r), "4b641e9a923d1ea57e18fe41dcb543e2c4005c41ff210864a710b0fbb2654c11");
		assert_eq!(r_s, "4b641e9a923d1ea57e18fe41dcb543e2c4005c41ff210864a710b0fbb2654c11");
	}

	#[test]
	fn test_naloc() {
		let mut buffer= [0x00 as u8; 32];
		naloc_bin_oneshot::<Sha256>(b"test_string", &mut buffer).unwrap();
		assert_eq!(encode(buffer), "4b641e9a923d1ea57e18fe41dcb543e2c4005c41ff210864a710b0fbb2654c11");
	}

	#[bench]
	fn bench_hash(b: &mut Bencher) {
		let mut bench_data = vec![0 as u8;500000];
		let mut fp = File::open(Path::new("/dev/urandom")).unwrap();
		fp.read_exact(&mut bench_data).unwrap();
		b.iter( || bin_oneshot::<Sha256>(b"test_string"));
	}

	#[bench]
	fn bench_naloc(b: &mut Bencher) {
		let mut bench_data = vec![0 as u8;500000];
		let mut fp = File::open(Path::new("/dev/urandom")).unwrap();
		fp.read_exact(&mut bench_data).unwrap();
		let mut buffer= [0x00 as u8; 32];
		b.iter( || naloc_bin_oneshot::<Sha256>(b"test_string", &mut buffer));
	}

}