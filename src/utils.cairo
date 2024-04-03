use alexandria_bytes::{Bytes, BytesTrait};

pub fn bytes_to_u8array(src: @Bytes) -> Array<u8> {
  let mut dst: Array<u8> = array![];

  let mut index = 0;
  while index < src.size() {
    let (_, v) = src.read_u8(index);
    dst.append(v);
    index += 1;
  };

  dst
}

pub fn u256_to_u8array(src: u256) -> Array<u8> {
  let mut buffer = BytesTrait::new_empty();
  buffer.append_u256(src);

  bytes_to_u8array(@buffer)
}
