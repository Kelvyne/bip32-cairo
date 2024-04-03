use core::keccak::keccak_u256s_be_inputs;

pub fn hash(x: u256) -> u256 {
    let arr: Array<u256> = array![x];
    hash_span(@arr.span())
}

pub fn hash_point(x: u256, y: u256) -> u256 {
    let arr: Array<u256> = array![x, y];
    hash_span(@arr.span())
}

pub fn hash_span(span: @Span<u256>) -> u256 {
    let hash_le = keccak_u256s_be_inputs(*span);
    u256 {
       low: core::integer::u128_byte_reverse(hash_le.high),
       high: core::integer::u128_byte_reverse(hash_le.low)
    }
}

#[cfg(test)]
mod tests {
  #[test]
  fn hash_gives_correct_value() {
    let r = super::hash(0x59642f809245ca2950deda7acf1d460ac419ef7a8d003ac6bb42f69b01891e5d);
    assert!(r == 0x8e4fac25c0a5299161374aa5f8083cf7ddb029a0f78b4b3f0a15937434edc288);
  }
}
