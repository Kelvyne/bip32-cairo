use core::starknet::{secp256k1, secp256_trait::{Secp256Trait, Secp256PointTrait}};

mod keccak;
mod hmac_sha512;

fn point(x: u256) -> secp256k1::Secp256k1Point {
  let G: secp256k1::Secp256k1Point = Secp256Trait::get_generator_point();
  G.mul(x).unwrap()
}

fn main() {
  let r = keccak::hash(0x59642f809245ca2950deda7acf1d460ac419ef7a8d003ac6bb42f69b01891e5d);

  let p = point(r);

  let (x, y) = p.get_coordinates().unwrap();
  println!("[{};{}]", x, y);
}
