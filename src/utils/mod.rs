pub fn truncate(s: String) -> String {
    if s.len() > 100 {
        let mut s = s;
        s.truncate(100);
        s.push_str("...");
        s
    } else {
        s
    }
}

pub mod bytes {
    pub fn of_len(len: usize, val: u8) -> Vec<u8> {
        vec![val; len]
    }
}
