pub struct Mt19937 {
    seed: u64,
    cnt: u64,
    w: u64,
    n: u64,
    f: u64,
    m: u64,
    r: u64,
    a: u64,
    d: u64,
    b: u64,
    c: u64,
    u: u8,
    s: u8,
    t: u8,
    l: u8,
    x: Vec<u64>,
}

// Reference: https://github.com/anneouyang/MT19937/blob/master/code/implement_mt19937.py
// and https://en.wikipedia.org/wiki/Mersenne_Twister#Algorithmic_detail
impl Mt19937 {
    pub fn new(seed: Option<u64>) -> Self {
        let seed = match seed {
            Some(s) => s,
            None => crate::utils::time::now().as_secs() as u64,
        };
        let n = 624;
        let x = vec![0; n];
        let mut out = Mt19937 {
            seed,
            cnt: 0,
            w: 32,
            n: n as u64,
            f: 1812433253,
            m: 397,
            r: 31,
            a: 0x9908B0DF,
            d: 0xFFFFFFFF,
            b: 0x9D2C5680,
            c: 0xEFC60000,
            u: 11,
            s: 7,
            t: 15,
            l: 18,
            x,
        };
        out.init();
        out
    }

    fn init(&mut self) {
        self.x[0] = self.seed;
        for i in 1..self.n {
            let i = i as usize;
            self.x[i] = (self.f * (self.x[i - 1] ^ (self.x[i - 1] >> (self.w - 2))) + i as u64)
                & ((1 << self.w) - 1)
        }
        self.twist();
    }

    fn twist(&mut self) {
        for i in 0..self.n {
            let lower_mask = (1 << self.r) - 1;
            let upper_mask = (!lower_mask) & ((1 << self.w) - 1);
            let tmp = (self.x[i as usize] & upper_mask)
                + (self.x[((i as u64 + 1) % self.n) as usize] & lower_mask);
            let mut tmp_a = tmp >> 1;
            if tmp % 2 != 0 {
                tmp_a ^= self.a;
            }
            self.x[i as usize] = self.x[((i + self.m) % self.n) as usize] ^ tmp_a;
        }
        self.cnt = 0;
    }

    pub fn temper(&mut self) -> u64 {
        if self.cnt == self.n {
            self.twist();
        }
        let y = self.x[self.cnt as usize];
        let y = y ^ ((y >> self.u) & self.d);
        let y = y ^ ((y << self.s) & self.b);
        let y = y ^ ((y << self.t) & self.c);
        let y = y ^ (y >> self.l);
        self.cnt += 1;
        y & ((1 << self.w) - 1)
    }
}

#[cfg(test)]
mod tests {
    use super::Mt19937;

    #[test]
    fn test_mt19937() {
        // validated at https://replit.com/@CoryForsyth/twister

        let mut mt = Mt19937::new(Some(0));
        let nums: Vec<u64> = (0..=2).map(|_| mt.temper()).collect();
        assert_eq!(nums, [2357136044, 2546248239, 3071714933]);

        let mut mt = Mt19937::new(Some(1));
        let nums: Vec<u64> = (0..=2).map(|_| mt.temper()).collect();
        assert_eq!(nums, [1791095845, 4282876139, 3093770124]);
    }
}
