//! A simple RSA cryptography library. Key generation uses an
//! implementation of the algorithm detailed in the paper:
//! *["Fast Generation of Prime Numbers and  Secure Public-Key Cryptographic Parameters"](https://link.springer.com/content/pdf/10.1007/BF00202269.pdf)* by *Ueli M.Maurer*

#[macro_use]
extern crate lazy_static;

use num_bigint::{BigUint, RandomBits};
use rand::{
    distributions::{Distribution, Uniform},
    prelude::*,
    Rng,
};
use rand_pcg::Pcg64;
use std::sync::Mutex;

lazy_static! {
    static ref PRIMES: Mutex<Vec<BigUint>> = {
        let mut primes = Vec::new();
        let mut n = BigUint::from(1u8);
        let mut i = 0;
        while i < 2634 {
            if is_prime(&n) {
                primes.push(n.clone());
                i += 1;
            }
            n += 1u8;
        }
        Mutex::new(primes)
    };
}

/// Returns greatest common divisor of two unsigned integers
pub fn gcd(u: &BigUint, v: &BigUint) -> BigUint {
    if u == &0u8.into() {
        return v.clone();
    };
    if v == &0u8.into() {
        return u.clone();
    };
    let shift = (u | v).trailing_zeros().unwrap();
    let mut new_u = u >> u.trailing_zeros().unwrap();
    let mut new_v = v.clone();
    loop {
        new_v >>= new_v.trailing_zeros().unwrap();
        if new_u > new_v {
            (new_u, new_v) = (new_v, new_u);
        }
        new_v -= &new_u;
        if new_v == 0u8.into() {
            break;
        }
    }
    return new_u << shift;
}

/// Returns lowest common multiple of two unsinged integers
pub fn lcm(u: &BigUint, v: &BigUint) -> BigUint {
    return (u * v) / gcd(u, v);
}

/// Returns [`true`] if given unsigned integer is prime, [`false`] otherwise
///
/// Fast for `n <= 8388608`
pub fn is_prime(n: &BigUint) -> bool {
    if n <= &3u8.into() {
        n > &1u8.into()
    } else if n % 2u8 == 0u8.into() || n % 3u8 == 0u8.into() {
        false
    } else {
        let mut i = BigUint::from(5u8);
        while &(&i * &i) <= n {
            if n % &i == 0u8.into() || n % (&i + 2u8) == 0u8.into() {
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
pub fn greatest_prime_factor(n: &BigUint) -> BigUint {
    if is_prime(n) {
        return n.clone();
    }
    let mut i = BigUint::from(2u8);
    while &i < n {
        if n % &i == 0u8.into() {
            return greatest_prime_factor(&(n / i));
        }
        i += 1u8;
    }
    return n.clone();
}

/// Returns [`Vec`] of `primes <= a`
///
/// Reasonable for `n <= 100`
pub fn primes_upto(a: &BigUint) -> usize {
    let mut primes = PRIMES.lock().unwrap();
    if a <= &primes.last().unwrap() {
        let i = primes.binary_search(a).unwrap_or_else(|i| i - 1);
        return i + 1;
    }
    let mut i = primes.last().unwrap().clone();
    while &i <= a {
        if is_prime(&i) {
            primes.push(i.clone());
        }
        i += 1u8;
    }
    return primes.len();
}

/// Checks if `a` has prime factors `<= b`
pub fn trial_div(a: &BigUint, primes: usize) -> bool {
    for p in PRIMES.lock().unwrap()[..primes].iter() {
        if a % p == 0u8.into() {
            return false;
        }
    }
    return true;
}

/// Uses Fermat's Little Theorem to check primality
///
/// TODO: Extend to Miller-Rabin Primality Test
pub fn check_primality(n: &BigUint, a: &BigUint) -> bool {
    return a.modpow(&(n - 1u8), n) == 1u8.into();
}

/// Selects relative size from interval `[0.5, 1]` according to probability
/// distribution of relative size `x` of the largest prime factor of a large random
/// integer give that it is at least `0.5`
pub fn gen_rel_size() -> f64 {
    let mut rng = rand::thread_rng();
    let n = rng.gen_range::<u128, _>(10000..100000);
    let gpf = *greatest_prime_factor(&n.into()).to_u64_digits().get(0).unwrap() as f64;
    return gpf.log(2.0) / (n as f64).log(2.0);
}

/// FOR BENCHMARKING ONLY
///
/// VERY INSECURE
fn seeded_gen_rel_size() -> f64 {
    let mut rng = Pcg64::seed_from_u64(2);
    let n = rng.gen_range::<u128, _>(10000..100000);
    let gpf = *greatest_prime_factor(&n.into()).to_u64_digits().get(0).unwrap() as f64;
    return gpf.log(2.0) / (n as f64).log(2.0);
}

/// Generates a random prime `k bits` in length
pub fn gen_prime(k: usize) -> BigUint {
    const C_OPT: f64 = 0.1;
    const MARGIN: f64 = 20.0;
    let mut rng = rand::thread_rng();

    if k <= 23 {
        return loop {
            let n: BigUint = rng.sample(RandomBits::new(k as u64));
            if n == 1u8.into() || is_prime(&n) {
                break n;
            }
        };
    } else {
        // TODO: Check downcast
        let g = BigUint::from((C_OPT * k as f64 * k as f64) as u64);
        let primes_upto_g = primes_upto(&g);
        let mut rel_size;
        loop {
            rel_size = gen_rel_size();
            if k as f64 * rel_size < (k as f64 - MARGIN).max(0.0) {
                break;
            }
        }

        let q = gen_prime((rel_size * k as f64) as usize);
        let i = BigUint::from(2u8).pow((k - 1) as u32) / &q;
        let range = Uniform::from(i.clone()..=2u8 * &i);

        return loop {
            let n = 2u8 * range.sample(&mut rng) * &q + 1u8;
            let a = BigUint::from(rng.gen_range::<u32, _>(2..=&n.to_u32_digits()[0] - 1));
            if trial_div(&n, primes_upto_g) {
                if check_primality(&n, &a) {
                    break n;
                }
            }
        };
    }
}

/// FOR BENCHMARKING ONLY
///
/// VERY INSECURE
pub fn seeded_gen_prime(k: usize) -> BigUint {
    const C_OPT: f64 = 0.1;
    const MARGIN: f64 = 20.0;
    let mut rng = Pcg64::seed_from_u64(2);

    if k <= 23 {
        return loop {
            let n = rng.sample(RandomBits::new(k as u64));
            if n == 1u8.into() || is_prime(&n) {
                break n;
            }
        };
    } else {
        let g = BigUint::from((C_OPT * k as f64 * k as f64) as u64);
        let primes_upto_g = primes_upto(&g);
        let mut rel_size;
        loop {
            rel_size = seeded_gen_rel_size();
            if k as f64 * rel_size < (k as f64 - MARGIN).max(0.0) {
                break;
            }
        }

        let q = gen_prime((rel_size * k as f64) as usize);
        let i = BigUint::from(2u8).pow((k - 1) as u32) / &q;
        let range = Uniform::from(i.clone()..=2u8 * &i);

        return loop {
            let n = 2u8 * range.sample(&mut rng) * &q + 1u8;
            let a = BigUint::from(rng.gen_range::<u32, _>(2..=&n.to_u32_digits()[0] - 1));
            if trial_div(&n, primes_upto_g) {
                if check_primality(&n, &a) {
                    break n;
                }
            }
        };
    }
}

/// Store RSA public key and modulus
#[derive(Debug, Clone)]
pub struct PublicKey {
    value: BigUint,
    modulus: BigUint,
}

impl PublicKey {
    pub fn new(value: impl Into<BigUint>, modulus: impl Into<BigUint>) -> Self {
        Self {
            value: value.into(),
            modulus: modulus.into(),
        }
    }
}

/// Stores RSA private key and modulus
#[derive(Debug, Clone)]
pub struct PrivateKey {
    value: BigUint,
    modulus: BigUint,
}

impl PrivateKey {
    pub fn new(value: impl Into<BigUint>, modulus: impl Into<BigUint>) -> Self {
        Self {
            value: value.into(),
            modulus: modulus.into(),
        }
    }
}

/// Generates a secure public & private key set for RSA encryption
///
/// Returns a tuple of public & private key set
pub fn gen_rsa_keysets(length: usize) -> (PublicKey, PrivateKey) {
    let p = gen_prime(length / 2);
    let q = gen_prime(length / 2);

    let modulus = &p * &q;
    let totient = lcm(&(&p - 1u8), &(&q - 1u8));
    let public_key = 65537u128;

    let mut x = 1u64;
    let private_key = loop {
        let n = 1u8 + x * &totient;
        if &n % public_key == 0u8.into() {
            break n;
        }
        x += 1;
    } / public_key;

    return (
        PublicKey::new(public_key, modulus.clone()),
        PrivateKey::new(private_key, modulus),
    );
}

/// FOR BENCHMARKING ONLY
///
/// VERY INSECURE
pub fn seeded_gen_rsa_keysets(length: usize) -> (PublicKey, PrivateKey) {
    let p = seeded_gen_prime(length / 2);
    let q = seeded_gen_prime(length / 2);

    let modulus = &p * &q;
    let totient = lcm(&(&p - 1u8), &(&q - 1u8));
    let public_key = 65537u128;

    let mut x: u64 = 1;
    let private_key = loop {
        let n = 1u8 + x * &totient;
        if &n % public_key != 0u8.into() {
            break n;
        }
        x += 1;
    } / public_key;

    return (
        PublicKey::new(public_key, modulus.clone()),
        PrivateKey::new(private_key, modulus),
    );
}

/// Encrypts a message using the public key set
///
/// TODO: Implement padding sceheme
pub fn rsa_encrypt(msg: impl Into<BigUint>, public_key: &PublicKey) -> BigUint {
    return msg.into().modpow(&public_key.value, &public_key.modulus);
}

/// Decrypts a message using the private key set
///
/// TODO: Implement padding scheme
pub fn rsa_decrypt(cipher_text: impl Into<BigUint>, private_key: &PrivateKey) -> BigUint {
    let cipher_text = cipher_text.into();
    return cipher_text.modpow(&private_key.value, &private_key.modulus);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gcd_works() {
        assert_eq!(
            gcd(
                &BigUint::from(9086502345680171u128 * 9534135720097931u128),
                &BigUint::from(9534135720097931u128 * 4487415479319029u128)
            ),
            9534135720097931u128.into()
        );
        assert_eq!(
            gcd(
                &BigUint::from(5981292683278201u128),
                &BigUint::from(2280630214605221u128)
            ),
            1u8.into()
        );
    }

    #[test]
    fn lcm_works() {
        let a = BigUint::from(1940588876352383u128);
        let b = BigUint::from(6950122264823503u128);
        assert_eq!(lcm(&a, &b), a * b);
    }

    #[test]
    fn is_prime_works() {
        assert!(is_prime(&BigUint::from(6286801u64)));
        assert!(!is_prime(&BigUint::from(3473502u64)));
    }

    #[test]
    fn greatest_prime_factor_works() {
        assert_eq!(greatest_prime_factor(&BigUint::from(239u32 * 151u32)), 239u32.into());
        assert_eq!(greatest_prime_factor(&BigUint::from(256u32)), 2u8.into());
        assert_eq!(greatest_prime_factor(&BigUint::from(113u32)), 113u32.into());
    }

    #[test]
    fn primes_upto_works() {
        assert_eq!(
            PRIMES.lock().unwrap()[..primes_upto(&BigUint::from(17u8))],
            vec![2u8, 3u8, 5u8, 7u8, 11u8, 13u8, 17u8]
                .into_iter()
                .map(|x| x.into())
                .collect::<Vec<BigUint>>()
        );
    }

    #[test]
    fn check_primality_works() {
        assert!(check_primality(&BigUint::from(37578119u128), &BigUint::from(3u8)));
        assert!(!check_primality(&BigUint::from(66366594u128), &BigUint::from(3u8)));
    }

    #[test]
    fn gen_rsa_keysets_works() {
        let (public_key, private_key) = gen_rsa_keysets(256);
        assert_eq!(public_key.value, 65537u128.into());
        assert!(private_key.value.bits() - 1 <= 256);
    }

    #[test]
    fn rsa_encrypt_decrypt_works() {
        let (public_key, private_key) = gen_rsa_keysets(256);
        let msg = BigUint::from_bytes_be(b"Hello World");
        let cipher_text = rsa_encrypt(msg.clone(), &public_key);
        let plain_text = rsa_decrypt(cipher_text.clone(), &private_key);

        assert!(&cipher_text != &plain_text);
        assert!(&plain_text == &msg);
    }
}
