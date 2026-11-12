#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    s3d_fuzz::fuzz_post_policy(data);
});
