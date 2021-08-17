//! A very simple RSA cryptography library. Key generation uses an implementation of the algorithm detailed in the paper: *["Fast Generation of Prime Numbers and  Secure Public-Key Cryptographic Parameters"](https://link.springer.com/content/pdf/10.1007/BF00202269.pdf)* by *Ueli M.Maurer*

extern crate num_bigint;
extern crate rand;

use num_bigint::{BigUint, RandomBits};
use rand::{
    distributions::{Distribution, Uniform},
    Rng,
};

/// Returns greatest common divisor of two unsigned integers
pub fn gcd(u: impl Into<BigUint>, v: impl Into<BigUint>) -> BigUint {
    let mut u = u.into();
    let mut v = v.into();
    let shift;
    if u == 0u8.into() {
        return v;
    };
    if v == 0u8.into() {
        return u;
    };
    shift = (&u | &v).trailing_zeros().unwrap();
    u >>= u.trailing_zeros().unwrap();
    loop {
        v >>= v.trailing_zeros().unwrap();
        if u > v {
            let t = u;
            u = v;
            v = t;
        }
        v = &v - &u;
        if v == 0u8.into() {
            break;
        };
    }
    return u << shift;
}

/// Returns lowest common multiple of two unsinged integers
pub fn lcm(u: impl Into<BigUint>, v: impl Into<BigUint>) -> BigUint {
    let mut u = u.into();
    let mut v = v.into();
    return (&u * &v) / gcd(u, v);
}

/// Returns [`true`] if given unsigned integer is prime, [`false`] otherwise
///
/// Fast for `n <= 8388608`
pub fn is_prime(n: impl Into<BigUint>) -> bool {
    let n = n.into();
    if n <= 3u8.into() {
        n > 1u8.into()
    } else if &n % 2u8 == 0u8.into() || &n % 3u8 == 0u8.into() {
        false
    } else {
        let mut i: BigUint = 5u8.into();
        while &i * &i <= n {
            if &n % &i == 0u8.into() || &n % (&i + 2u8) == 0u8.into() {
                return false;
            }
            i += 6u8;
        }
        true
    }
}

/// Returns greatest prime factor of an unsigned integer
///
/// Reasonable for `n <= 8388608`
///
/// Could be faster...
pub fn greatest_prime_factor(n: impl Into<BigUint>) -> BigUint {
    let n = n.into();
    if is_prime(n.clone()) {
        return n;
    }
    let mut i: BigUint = 2u8.into();
    while i < n {
        if &n % &i == 0u8.into() {
            return greatest_prime_factor(n / i);
        }
        i += 1u8;
    }
    return n;
}

const fn prec_is_prime(n: usize) -> bool {
    if n <= 3 {
        n > 1
    } else if n % 2 == 0 || n % 3 == 0 {
        false
    } else {
        let mut i = 5;
        while i * i <= n {
            if n % i == 0 || n % (i + 2) == 0 {
                return false;
            }
            i += 6;
        }
        true
    }
}

const A: usize = 24221; // Largest possible size
const fn prec_primes() -> [bool; A] {
    let mut primes = [false; A];
    let mut n = 1;
    while n < A {
        primes[n] = prec_is_prime(n);
        n += 1;
    }
    return primes;
}

const PRIMES: [bool; A] = prec_primes();

/// Returns [`Vec`] of `primes <= a`
///
/// Reasonable for `n <= 100`
pub fn primes_upto(a: impl Into<BigUint>) -> Vec<BigUint> {
    let a = a.into();
    if a < A.into() {
        return PRIMES[..*a.to_u64_digits().get(0).unwrap() as usize + 1].iter().enumerate().filter_map(|(n, x)| if *x { Some(BigUint::from(n)) } else { None }).collect()
    }
    let mut primes = Vec::new();
    let mut i: BigUint = 1u8.into();
    while &i <= &a {
        if is_prime(i.clone()) {
            primes.push(i.clone());
        }
        i += 1u8;
    }
    return primes;
}

/// Checks if `a` has prime factors `<= b`
pub fn trial_div(a: impl Into<BigUint>, b: impl Into<BigUint>) -> bool {
    let a = a.into();
    let b = b.into();
    let primes = primes_upto(b);
    for p in primes.iter() {
        if &a % p == 0u8.into() {
            return false;
        }
    }
    return true;
}

/// Uses Fermat's Little Theorem to check primality
///
/// TODO: Extend to Miller-Rabin Primality Test
pub fn check_primality(n: impl Into<BigUint>, a: impl Into<BigUint>) -> bool {
    let n = n.into();
    let a = a.into();
    return a.modpow(&(&n - 1u8), &n) == 1u8.into();
}

/// Selects relative size from interval `[0.5, 1]` according to probability
/// distribution of relative size `x` of the largest prime factor of a large random
/// integer give that it is at least `0.5`
pub fn gen_rel_size() -> f64 {
    let mut rng = rand::thread_rng();
    let n = rng.gen_range::<u128, _>(10000..100000);
    let gpf = *greatest_prime_factor(n).to_u64_digits().get(0).unwrap() as f64;
    return gpf.log(2.0) / (n as f64).log(2.0);
}

/// Generates a random prime `k bits` in length
pub fn gen_prime(k: usize) -> BigUint {
    const C_OPT: f64 = 0.1;
    let margin = 20;
    let mut rel_size;
    let mut n: BigUint = 1u8.into();
    let mut rng = rand::thread_rng();

    if k <= 23 {
        loop {
            n = rng.sample(RandomBits::new(k as u64));
            if n == 1u8.into() || is_prime(n.clone()) {
                break;
            }
        }
        return n;
    } else {
        let g = C_OPT * k as f64 * k as f64;
        loop {
            rel_size = gen_rel_size();
            if k as f64 * rel_size < (k as f64 - margin as f64).max(0.0) {
                break;
            }
        }

        let q = gen_prime((rel_size * k as f64) as usize);
        let i = BigUint::from(2u8).pow((k - 1) as u32) / &q;
        let range = Uniform::from(i.clone()..=2u8 * &i);

        loop {
            n = 2u8 * range.sample(&mut rng) * &q + 1u8;
            let a = rng.gen_range::<u32, _>(2..=&n.to_u32_digits()[0] - 1);
            if trial_div(n.clone(), g as u128) {
                if check_primality(n.clone(), a) {
                    break;
                }
            }
        }

        return n;
    }
}

/// Generates a secure public & private key set for RSA encryption
///
/// Returns a tuple of public & private key set
pub fn gen_rsa_keysets(length: usize) -> ((u64, BigUint), BigUint) {
    let p = gen_prime(length / 2);
    let q = gen_prime(length / 2);

    let modulus = &p * &q;
    let totient = lcm(&p - 1u8, &q - 1u8);
    let public_key = 65537;

    let mut x: u64 = 1;
    while (1u8 + x * &totient) % &public_key != 0u8.into() {
        x += 1;
    }

    let private_key = (1u8 + x * &totient) / &public_key;
    return ((public_key, modulus), private_key);
}

/// Encrypts a message using the public key set
///
/// TODO: Implement padding sceheme
pub fn rsa_encrypt(
    msg: impl Into<BigUint>,
    public_key: impl Into<BigUint>,
    modulus: impl Into<BigUint>,
) -> BigUint {
    let msg = msg.into();
    let public_key = public_key.into();
    let modulus = modulus.into();
    return msg.modpow(&public_key, &modulus);
}

/// Decrypts a message using the private key set
///
/// TODO: Implement padding scheme
pub fn rsa_decrypt(
    cipher_text: impl Into<BigUint>,
    private_key: impl Into<BigUint>,
    modulus: impl Into<BigUint>,
) -> BigUint {
    let cipher_text = cipher_text.into();
    let private_key = private_key.into();
    let modulus = modulus.into();
    return cipher_text.modpow(&private_key, &modulus);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gcd_works() {
        assert_eq!(
            gcd(
                9086502345680171u128 * 9534135720097931u128,
                9534135720097931u128 * 4487415479319029u128
            ),
            9534135720097931u128.into()
        );
        assert_eq!(gcd(5981292683278201u128, 2280630214605221u128), 1u8.into());
    }

    #[test]
    fn lcm_works() {
        assert_eq!(
            lcm(1940588876352383u128, 6950122264823503u128),
            (1940588876352383u128 * 6950122264823503u128).into()
        );
    }

    #[test]
    fn is_prime_works() {
        assert!(is_prime(6286801u64));
        assert!(!is_prime(3473502u64));
    }

    #[test]
    fn greatest_prime_factor_works() {
        assert_eq!(greatest_prime_factor(239u32 * 151u32), 239u32.into());
        assert_eq!(greatest_prime_factor(256u32), 2u8.into());
        assert_eq!(greatest_prime_factor(113u32), 113u32.into());
    }

    #[test]
    fn primes_upto_works() {
        assert_eq!(
            primes_upto(17u8),
            vec![2u8, 3u8, 5u8, 7u8, 11u8, 13u8, 17u8]
                .into_iter()
                .map(|x| x.into())
                .collect::<Vec<BigUint>>()
        );
    }

    #[test]
    fn check_primality_works() {
        assert!(check_primality(37578119u128, 3u8));
        assert!(!check_primality(66366594u128, 3u8));
    }

    #[test]
    fn gen_rsa_keysets_works() {
        let ((public_key, _modulus), private_key) = gen_rsa_keysets(256);
        assert_eq!(public_key, 65537);
        assert!(private_key.bits() <= 256);
    }

    #[test]
    fn rsa_encrypt_decrypt_works() {
        let ((public_key, modulus), private_key) = gen_rsa_keysets(256);
        let msg = BigUint::from_bytes_be(b"Hello World");
        let cipher_text = rsa_encrypt(msg.clone(), public_key.clone(), modulus.clone());
        let plain_text = rsa_decrypt(cipher_text.clone(), private_key.clone(), modulus.clone());

        assert!(&cipher_text != &plain_text);
        assert!(&plain_text == &msg);
    }
}
