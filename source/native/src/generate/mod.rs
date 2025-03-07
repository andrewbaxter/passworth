use {
    rand::{
        rng,
        seq::IndexedRandom,
        RngCore,
    },
};

pub const BIP39_PHRASELEN: usize = 12;

pub fn bip39() -> Vec<&'static str> {
    let lines = include_str!("bip39.txt").lines().collect::<Vec<_>>();
    assert_eq!(lines.len(), 2048);
    return lines;
}

pub fn gen_bip39() -> Vec<String> {
    return bip39().choose_multiple(&mut rng(), BIP39_PHRASELEN).map(|x| x.to_string()).collect::<Vec<_>>();
}

pub fn gen_bytes(len: usize) -> Vec<u8> {
    let mut out = vec![];
    out.resize(len, 0u8);
    rng().fill_bytes(&mut out);
    return out;
}

pub fn gen_safe_alphanum(len: usize) -> String {
    let raw = b"abcdefhijkmnoprstwxy34".choose_multiple(&mut rng(), len).map(|x| *x).collect::<Vec<_>>();
    return unsafe {
        String::from_utf8_unchecked(raw)
    };
}

pub fn gen_alphanum(len: usize) -> String {
    let raw =
        b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
            .choose_multiple(&mut rng(), len)
            .map(|x| *x)
            .collect::<Vec<_>>();
    return unsafe {
        String::from_utf8_unchecked(raw)
    };
}

pub fn gen_alphanum_symbols(len: usize) -> String {
    let raw =
        b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()_-,<.>[{]};:/? "
            .choose_multiple(&mut rng(), len)
            .map(|x| *x)
            .collect::<Vec<_>>();
    return unsafe {
        String::from_utf8_unchecked(raw)
    };
}
