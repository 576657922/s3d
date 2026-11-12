#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    s3d_fuzz::fuzz_wal_ckpt_decode(data);
});
