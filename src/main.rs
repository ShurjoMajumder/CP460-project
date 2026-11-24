use std::io::{self, Write};

pub fn nth_prime(k: usize) -> usize {
    assert!(k >= 1, "k must be >= 1");
    if k == 1 {
        return 2;
    }
    let kf = k as f64;
    let limit = if k < 6 { 15 } else { (kf * (kf.ln() + kf.ln().ln())) as usize + 1 };
    let size = (limit + 1) / 2; // index i <-> number 2i+1
    let mut comp = vec![false; size];
    let mut count = 1; // the prime 2
    for i in 1..size {
        if comp[i] {
            continue;
        }
        count += 1;
        let p = 2 * i + 1;
        if count == k {
            return p;
        }
        let mut j = (p * p - 1) / 2;
        while j < size {
            comp[j] = true;
            j += p;
        }
    }
    unreachable!("bound too small");
}

fn gcd(a: usize, b: usize) -> usize {
    if b == 0 { a } else { gcd(b, a % b) }
}

fn phi(p: usize, q: usize) -> usize {
    (p - 1) * (q - 1)
}

fn gen_e(u: usize) -> usize {
    // return e s.t. gcd(e, u = phi(n)) = 1, 1 < e < u
    let mut e = if 65537 < u { 65537 } else { 3 };
    while gcd(e, u) != 1 {
        e += 2;
    }
    e
}

fn inv(e: usize, u: usize) -> usize {
    // d s.t. e*d = 1 (mod u), via extended Euclid; requires gcd(e, u) = 1
    let (mut old_r, mut r) = (e as i128, u as i128);
    let (mut old_s, mut s) = (1i128, 0i128);
    while r != 0 {
        let q = old_r / r;
        (old_r, r) = (r, old_r - q * r);
        (old_s, s) = (s, old_s - q * s);
    }
    old_s.rem_euclid(u as i128) as usize
}

fn gen_rand(seed: usize) -> usize {
    // deterministic number in 50..1000 from seed (splitmix64 finalizer); not cryptographic
    let mut x = (seed as u64).wrapping_add(0x9E3779B97F4A7C15);
    x = (x ^ (x >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94D049BB133111EB);
    x ^= x >> 31;
    50 + (x % 950) as usize
}

fn gen_keys(seed: usize) -> ((usize, usize), usize) {
    let a = gen_rand(seed);
    let mut s2 = seed.wrapping_add(1);
    while gen_rand(s2) == a {
        s2 = s2.wrapping_add(1); // ensure p != q
    }
    let p = nth_prime(a);
    let q = nth_prime(gen_rand(s2));
    let n = p * q;
    let phi_n = phi(p, q);
    let e = gen_e(phi_n);
    let d = inv(e, phi_n);
    let k = (n, e);
    (k, d)
}

fn mod_pow(base: usize, exp: usize, m: usize) -> usize {
    // square-and-multiply; u128 intermediates avoid overflow
    let (mut b, mut e, m) = (base as u128 % m as u128, exp, m as u128);
    let mut r = 1u128;
    while e > 0 {
        if e & 1 == 1 {
            r = r * b % m;
        }
        b = b * b % m;
        e >>= 1;
    }
    r as usize
}

fn encrypt(e: usize, n: usize, x: usize) -> usize {
    mod_pow(x, e, n) // x^e mod n
}

fn decrypt(d: usize, n: usize, y: usize) -> usize {
    mod_pow(y, d, n) // y^d mod n
}

fn prompt(msg: &str) -> String {
    print!("{msg}");
    io::stdout().flush().unwrap();
    let mut s = String::new();
    io::stdin().read_line(&mut s).unwrap();
    s.trim_end_matches(&['\r', '\n'][..]).to_string()
}

fn main() {
    let seed: usize = prompt("Seed (non-negative integer): ")
        .trim()
        .parse()
        .expect("seed must be a non-negative integer");
    let msg = prompt("Message: ");

    let ((n, e), d) = gen_keys(seed);
    println!("\nPublic key  (n, e): ({n}, {e})");

    println!("Private key (d):    {d}");

    // n >= 229*233 > 255, so each byte of the message fits in one block
    let cipher: Vec<usize> = msg.bytes().map(|b| encrypt(e, n, b as usize)).collect();
    println!("\nCiphertext: {:?}", cipher);

    let plain: Vec<u8> = cipher.iter().map(|&c| decrypt(d, n, c) as u8).collect();
    println!("Decrypted:  {}", String::from_utf8_lossy(&plain));
}
