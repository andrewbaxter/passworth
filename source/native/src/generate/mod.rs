use rand::{
    RngCore,
    rng,
    seq::IndexedRandom,
};

pub const BIP39_PHRASELEN: usize = 12;

pub fn bip39() -> Vec<&'static str> {
    let lines = include_str!("bip39.txt").lines().collect::<Vec<_>>();
    assert_eq!(lines.len(), 2048);
    return lines;
}

/// Pick `len` elements from `alphabet` uniformly and independently (i.e. with
/// replacement). Sampling without replacement would both leak structure (no
/// repeated characters) and silently cap the length at the alphabet size.
fn sample_with_replacement(alphabet: &[u8], len: usize) -> String {
    let mut rng = rng();
    let raw = (0 .. len).map(|_| *alphabet.choose(&mut rng).unwrap()).collect::<Vec<_>>();
    // All alphabets are ascii
    return String::from_utf8(raw).unwrap();
}

pub fn gen_alphanum(len: usize) -> String {
    return sample_with_replacement(b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ", len);
}

pub fn gen_alphanum_symbols(len: usize) -> String {
    return sample_with_replacement(
        b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()_-,<.>[{]};:/? ",
        len,
    );
}

pub fn gen_bip39() -> Vec<String> {
    let words = bip39();
    let mut rng = rng();
    return (0 .. BIP39_PHRASELEN).map(|_| words.choose(&mut rng).unwrap().to_string()).collect::<Vec<_>>();
}

pub fn gen_bytes(len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    rng().fill_bytes(&mut out);
    return out;
}

pub fn gen_safe_alphanum(len: usize) -> String {
    return sample_with_replacement(b"abcdefhijkmnoprstwxy34", len);
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_length_not_capped_by_alphabet() {
        assert_eq!(gen_safe_alphanum(40).len(), 40);
        assert_eq!(gen_alphanum(100).len(), 100);
    }
}
