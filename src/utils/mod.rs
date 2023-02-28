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

    pub fn rand_of_len(len: usize) -> Vec<u8> {
        let mut v = vec![];
        (0..len).for_each(|_| v.push(rand::random()));
        v
    }

    // pub fn extend_n(bytes: &[u8], times: usize) -> Vec<u8> {
    //     let mut extended = bytes.to_vec();
    //     for _ in 0..=times {
    //         extended.extend(bytes);
    //     }
    //     extended
    // }
}
