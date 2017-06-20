#![allow(non_upper_case_globals)]

#![feature(test)]
extern crate test;
extern crate emerald_core;
#[link(name = "scrypt")]
extern {
    pub fn crypto_scrypt(passwd: *const u8, passwdlen: usize, salt: *const u8, saltlen: usize,
                             N: u64, r: u32, p: u32,
                             buf: *mut u8, buflen: usize) -> ::std::os::raw::c_int;
}

/**
 * The Scrypt parameter values.
 */
#[derive(Clone, Copy)]
pub struct ScryptParams {
    n: u64,
    r: u32,
    p: u32
}

impl ScryptParams {
    ///
    pub fn new(n: u64, r: u32, p: u32) -> Self {
        ScryptParams {
            n: n,
            r: r,
            p: p
        }
    }
}

/// `Scrypt` key derivation function
///
/// #Arguments:
/// passwd -
/// salt -
/// params -
/// output -
///
pub fn scrypt(passwd: &[u8], salt: &[u8], params: &ScryptParams, output: &mut [u8]) {
    unsafe {
        crypto_scrypt(passwd.as_ptr(), passwd.len(), salt.as_ptr(), salt.len(),
                      params.n, params.r, params.p, output.as_mut_ptr(), 32);
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use emerald_core::ToHex;
    use test::Bencher;

    #[test]
    fn test_scrypt() {
        let salt =
            emerald_core::to_32bytes("fd4acb81182a2c8fa959d180967b374277f2ccf2f7f401cb08d042cc785464b4");
        let passwd = "1234567890";
        let mut buf = [0u8; 32];
        let params = ScryptParams::new(2, 8, 1);

        scrypt(passwd.as_bytes(), &salt, &params, &mut buf);

        assert_eq!("52a5dacfcf80e5111d2c7fbed177113a1b48a882b066a017f2c856086680fac7", buf.to_hex());
    }

    #[bench]
    fn bench_encrypt_scrypt(b: &mut Bencher) {
        let salt =
            emerald_core::to_32bytes("fd4acb81182a2c8fa959d180967b374277f2ccf2f7f401cb08d042cc785464b4");
        let passwd = "1234567890";
        let mut buf = [0u8; 32];
        let params = ScryptParams::new(262144, 8, 1);

        b.iter(|| scrypt(passwd.as_bytes(), &salt, &params, &mut buf));
    }
}