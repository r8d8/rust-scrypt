//! # C bindings to `Scrypt` key derivation function
//! specified in (RPC 7914)[https://tools.ietf.org/html/rfc7914])

#![cfg_attr(feature = "dev", feature(plugin))]
#![cfg_attr(feature = "dev", plugin(clippy))]
#![allow(non_upper_case_globals)]

#[link(name = "scrypt")]
extern "C" {
    pub fn crypto_scrypt(
        passwd: *const u8,
        passwdlen: usize,
        salt: *const u8,
        saltlen: usize,
        N: u64,
        r: u32,
        p: u32,
        buf: *mut u8,
        buflen: usize,
    ) -> ::std::os::raw::c_int;
}

///The Scrypt parameter values
#[derive(Clone, Copy, Debug)]
pub struct ScryptParams {
    /// Number of iterations
    pub n: u64,

    /// Block size for the underlying hash
    pub r: u32,

    /// Parallelization factor
    pub p: u32,
}

/// Derive fixed size key for given `salt` and `passphrase`
///
/// #Arguments:
/// passwd - password to be derived
/// salt - byte array with salt
/// params - parameters for scrypt into `ScryptParams`
/// output - resulting byte slice
///
pub fn scrypt(passwd: &[u8], salt: &[u8], params: &ScryptParams, output: &mut [u8]) {
    unsafe {
        crypto_scrypt(
            passwd.as_ptr(),
            passwd.len(),
            salt.as_ptr(),
            salt.len(),
            params.n,
            params.r,
            params.p,
            output.as_mut_ptr(),
            output.len(),
        );
    }
}

#[cfg(test)]
mod tests {
    extern crate rustc_serialize;

    use self::rustc_serialize::hex::{FromHex, ToHex};
    use super::*;

    fn to_bytes<A, T>(slice: &[T]) -> A
    where
        A: AsMut<[T]> + Default,
        T: Clone,
    {
        let mut arr = Default::default();
        <A as AsMut<[T]>>::as_mut(&mut arr).clone_from_slice(slice);
        arr
    }

    #[test]
    fn test_scrypt_128() {
        let salt: [u8; 32] = to_bytes(
            &"fd4acb81182a2c8fa959d180967b374277f2ccf2f7f401cb08d042cc785464b4"
                .from_hex()
                .unwrap(),
        );
        let passwd = "1234567890";
        let mut buf = [0u8; 16];
        let params = ScryptParams { n: 2, r: 8, p: 1 };

        scrypt(passwd.as_bytes(), &salt, &params, &mut buf);

        assert_eq!("52a5dacfcf80e5111d2c7fbed177113a", buf.to_hex());
    }

    #[test]
    fn test_scrypt_256() {
        let salt: [u8; 32] = to_bytes(
            &"fd4acb81182a2c8fa959d180967b374277f2ccf2f7f401cb08d042cc785464b4"
                .from_hex()
                .unwrap(),
        );
        let passwd = "1234567890";
        let mut buf = [0u8; 32];
        let params = ScryptParams { n: 2, r: 8, p: 1 };

        scrypt(passwd.as_bytes(), &salt, &params, &mut buf);

        assert_eq!(
            "52a5dacfcf80e5111d2c7fbed177113a1b48a882b066a017f2c856086680fac7",
            buf.to_hex()
        );
    }

    #[test]
    fn test_scrypt_512() {
        let salt: [u8; 32] = to_bytes(
            &"fd4acb81182a2c8fa959d180967b374277f2ccf2f7f401cb08d042cc785464b4"
                .from_hex()
                .unwrap(),
        );
        let passwd = "1234567890";
        let mut buf = [0u8; 64];
        let params = ScryptParams { n: 2, r: 8, p: 1 };

        scrypt(passwd.as_bytes(), &salt, &params, &mut buf);

        assert_eq!(
            "52a5dacfcf80e5111d2c7fbed177113a1b48a882b066a017f2c856086680fac7\
             43ae0dd1ba325be061003ec144f1cad75ddbadd7bb01d22970b9904720b6ba27",
            buf.to_hex()
        );
    }
}
