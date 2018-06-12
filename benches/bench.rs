#![feature(test)]
extern crate hex;
extern crate rust_scrypt;
extern crate test;

use hex::decode;
use rust_scrypt::{scrypt, ScryptParams};
use test::Bencher;

fn to_bytes<A, T>(slice: &[T]) -> A
where
    A: AsMut<[T]> + Default,
    T: Clone,
{
    let mut arr = Default::default();
    <A as AsMut<[T]>>::as_mut(&mut arr).clone_from_slice(slice);
    arr
}

#[bench]
fn bench_encrypt_scrypt(b: &mut Bencher) {
    let salt: [u8; 32] = to_bytes(
        &decode("fd4acb81182a2c8fa959d180967b374277f2ccf2f7f401cb08d042cc785464b4").unwrap(),
    );
    let passwd = "1234567890";
    let mut buf = [0u8; 32];
    let params = ScryptParams {
        n: 262144,
        r: 8,
        p: 1,
    };

    b.iter(|| scrypt(passwd.as_bytes(), &salt, &params, &mut buf));
}
