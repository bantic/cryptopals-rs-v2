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

pub mod time {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    pub fn now() -> Duration {
        let start = SystemTime::now();
        start
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
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
}
