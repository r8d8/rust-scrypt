//! # C bindings to `Scrypt` key derivation function
//! specified in (RPC 7914)[https://tools.ietf.org/html/rfc7914])

#![cfg_attr(feature = "dev", feature(plugin))]
#![cfg_attr(feature = "dev", plugin(clippy))]
#![allow(non_upper_case_globals)]

#[link(name = "scrypt")]
extern {
    pub fn crypto_scrypt(passwd: *const u8, passwdlen: usize, salt: *const u8, saltlen: usize,
                             N: u64, r: u32, p: u32,
                             buf: *mut u8, buflen: usize) -> ::std::os::raw::c_int;
}

 ///The Scrypt parameter values
#[derive(Clone, Copy)]
pub struct ScryptParams {
    /// Number of iterations
    n: u64,

    /// Block size for the underlying hash
    r: u32,

    /// Parallelization factor
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

/// Derive fixed size key for given `salt` and `passphrase`
///
/// #Arguments:
/// passwd - password to be derived
/// salt - byte array with salt
/// params - parameters for scrypt into `ScryptParams`
/// output - resulting byte array
///
pub fn scrypt(passwd: &[u8], salt: &[u8], params: &ScryptParams, output: &mut [u8]) {
    unsafe {
        crypto_scrypt(passwd.as_ptr(), passwd.len(), salt.as_ptr(), salt.len(),
                      params.n, params.r, params.p, output.as_mut_ptr(), 32);
    }
}


#[cfg(test)]
mod tests {
    extern crate rustc_serialize;

    use super::*;
    use self::rustc_serialize::hex::{FromHex, ToHex};

    fn to_bytes<A, T>(slice: &[T]) -> A
        where A: AsMut<[T]> + Default,
        T: Clone
    {
        let mut arr = Default::default();
        <A as AsMut<[T]>>::as_mut(&mut arr).clone_from_slice(slice);
        arr
    }

    #[test]
    fn test_scrypt() {
        let salt: [u8; 32] =
            to_bytes(&"fd4acb81182a2c8fa959d180967b374277f2ccf2f7f401cb08d042cc785464b4".from_hex().unwrap());
        let passwd = "1234567890";
        let mut buf = [0u8; 32];
        let params = ScryptParams::new(2, 8, 1);

        scrypt(passwd.as_bytes(), &salt, &params, &mut buf);

        assert_eq!("52a5dacfcf80e5111d2c7fbed177113a1b48a882b066a017f2c856086680fac7", buf.to_hex());
    }
}