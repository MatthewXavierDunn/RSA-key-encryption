# RSA-key-encryption

A simple RSA cryptography library. Key generation uses an implementation of the algorithm detailed in the paper: *["Fast Generation of Prime Numbers and  Secure Public-Key Cryptographic Parameters"](https://link.springer.com/content/pdf/10.1007/BF00202269.pdf)* by *Ueli M.Maurer*

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
rsa = "0.1"
```

Example usage:

```rust
// generates rsa key sets with 256-bit key security
let ((public_key, modulus), private_key) = gen_rsa_keysets(256);

// the type of your secret must be explicit and one of u8, u16, u32, u64, and u128
let secret = 12345u128;

// to encrypt your secret
let secure_secret = rsa_encrypt(secret, public_key, modulus);

// to unencrypt your secret
let recovered_secret = rsa_decrypt(secure_secret, private_key, modulus);

assert_eq!(secret, recovered_secret);
```

## Contribution

Feel free to clone this repository and make your own changes. \
There are some improvements to make such as implementing a [padding scheme](https://en.wikipedia.org/wiki/Padding_(cryptography)) and using the [Miller-Rabin Primality test](https://en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test) to get more robust primes. \
Additionally some of the helper functions could be more efficient.
