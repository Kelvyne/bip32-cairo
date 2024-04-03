use core::starknet::{secp256k1, secp256_trait::{Secp256Trait, Secp256PointTrait}};
use alexandria_bytes::{Bytes, BytesTrait};
use alexandria_data_structures::byte_reader::{ByteReader};

mod keccak;
mod hmac_sha512;
mod utils;

#[derive(Clone, Drop, Debug)]
pub struct ExtendedKey {
  key: Array<u8>,
  chain_code: Array<u8>,
}

trait ExtendedKeyTrait {
  fn from_seed(seed: Array<u8>) -> ExtendedKey;
  fn address(self: @ExtendedKey) -> u256;
  fn derive(self: @ExtendedKey, index: u32) -> ExtendedKey;
}

impl ExtendedKeyImpl of ExtendedKeyTrait {
  fn from_seed(seed: Array<u8>) -> ExtendedKey {
    let master_key: Array<u8> =
      array![0x42, 0x69, 0x74, 0x63, 0x6F, 0x69, 0x6E, 0x20, 0x73, 0x65, 0x65, 0x64];
    let master_bytes = hmac_sha512::hmac_sha512(master_key, seed);

    let slice = master_bytes.span();

    ExtendedKey {
      key: span_to_array(slice.slice(0, 32)),
      chain_code: span_to_array(slice.slice(32, 32)),
    }
  }

  fn address(self: @ExtendedKey) -> u256 {
    let mut reader = self.key.reader();
    let key = reader.read_u256().unwrap();
    let p = point(key);

    let (x, y) = p.get_coordinates().unwrap();
    keccak::hash_point(x, y) & 0xffffffffffffffffffffffffffffffffffffffff
  }

  fn derive(self: @ExtendedKey, index: u32) -> ExtendedKey {
    let mut buffer = BytesTrait::new_empty();
    let mut reader = self.key.reader();
    let key = reader.read_u256().unwrap();

    if index >= 0x80000000 {
      buffer.append_u8(0x00);
      buffer.append_u256(key);
      buffer.append_u32(index);
    } else {
      let p = point(key);
      p.serialize_to(ref buffer);
      buffer.append_u32(index);
    }

    let data = utils::bytes_to_u8array(@buffer);
    let mut hash = hmac_sha512::hmac_sha512(self.chain_code.clone(), data);

    let hash_span = hash.span();
    let key_slice = hash_span.slice(0, 32);
    let mut key_reader = key_slice.reader();
    let key_u256 = key_reader.read_u256();
    let child_key: u256 = (
          key_u256.unwrap() + key
      ) % 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141;

    ExtendedKey {
      key: utils::u256_to_u8array(child_key),
      chain_code: span_to_array(hash_span.slice(32, 32)),
    }
  }
}

fn point(x: u256) -> secp256k1::Secp256k1Point {
  let G: secp256k1::Secp256k1Point = Secp256Trait::get_generator_point();
  G.mul(x).unwrap()
}

trait SerializableTo<T> {
  fn serialize_to(self: T, ref buffer: Bytes);
}

impl SerializablePoint of SerializableTo<secp256k1::Secp256k1Point> {
  fn serialize_to(self: secp256k1::Secp256k1Point, ref buffer: Bytes) {
    let (x, y) = self.get_coordinates().unwrap();

    let parity: u8 = if y % 2 == 0 {
      0x02
    } else {
      0x03
    };

    buffer.append_u8(parity);
    buffer.append_u256(x);
  }
}

fn span_to_array(mut span: Span<u8>) -> Array<u8> {
  let mut arr = array![];
  loop {
    match span.pop_front() {
      Option::Some(b) => arr.append(*b),
      Option::None => { break; },
    }
  };
  arr
}

#[cfg(test)]
mod tests {
  use alexandria_data_structures::byte_reader::{ByteReader};
  use super::ExtendedKeyTrait;

  #[test]
  fn bip32_derive_key_master() {
    let seed: Array<u8> = array![
      0x33, 0x8d, 0x3e, 0xde, 0xce, 0xa6, 0x10, 0x05, 0x80, 0x06, 0xcb, 0x64, 0xde, 0xe9, 0x70, 0x56, 
      0x21, 0x2d, 0xb0, 0xa1, 0xc6, 0xba, 0x16, 0xe8, 0x10, 0xdb, 0xd1, 0xad, 0x7e, 0xc9, 0xda, 0xa4
    ];
    let key = ExtendedKeyTrait::from_seed(seed);

    assert!(key.address() == 0xb24e3ef94625e9b2618179a00e148e4386184f27);
  }

  #[test]
  fn bip32_derive_key_first_index() {
    let seed: Array<u8> = array![
      0x33, 0x8d, 0x3e, 0xde, 0xce, 0xa6, 0x10, 0x05, 0x80, 0x06, 0xcb, 0x64, 0xde, 0xe9, 0x70, 0x56, 
      0x21, 0x2d, 0xb0, 0xa1, 0xc6, 0xba, 0x16, 0xe8, 0x10, 0xdb, 0xd1, 0xad, 0x7e, 0xc9, 0xda, 0xa4
    ];
    let key = ExtendedKeyTrait::from_seed(seed)
      .derive(1);

    assert!(key.address() == 0x3AEC1eB8e6EBDD60A5ce9B976E34E6B9c8AB26aE);
  }

  #[test]
  fn bip32_derive_key_ethereum_path() {
    let seed: Array<u8> = array![
      0x33, 0x8d, 0x3e, 0xde, 0xce, 0xa6, 0x10, 0x05, 0x80, 0x06, 0xcb, 0x64, 0xde, 0xe9, 0x70, 0x56, 
      0x21, 0x2d, 0xb0, 0xa1, 0xc6, 0xba, 0x16, 0xe8, 0x10, 0xdb, 0xd1, 0xad, 0x7e, 0xc9, 0xda, 0xa4
    ];
    // m/44'/60'/0'/0/0"
    let key = ExtendedKeyTrait::from_seed(seed)
      .derive(0x80000000 + 44)
      .derive(0x80000000 + 60)
      .derive(0x80000000)
      .derive(0)
      .derive(0);

    assert!(key.address() == 0x10CdB401E294B2829251659c062BBd79Ac91ec72);
  }
}
