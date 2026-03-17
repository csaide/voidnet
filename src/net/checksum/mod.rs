//! RFC 1071 implementation of the checksum algorithms.
//!
//! Checksumming utilities for all network protocols to use. These are SIMD accelerated where
//! possible. If the target architecture does not support the SIMD instructions, the fallback
//! implementation is used.

mod common;
mod compute;
mod std;
mod verify;

#[cfg(target_arch = "aarch64")]
mod neon;

pub use common::{
    checksum_to_bytes, fold_and_verify, fold_checksum, pseudo_header_sum_v4, pseudo_header_sum_v6,
    sum_words, sum_words_carry,
};
pub use compute::{
    compute_icmpv6_checksum, compute_ipv4_checksum, compute_tcp_checksum_ip,
    compute_udp_checksum_ip,
};
pub use verify::{verify_ipv4_checksum, verify_tcp_checksum_ip, verify_udp_checksum_ip};

#[cfg(test)]
mod test_utils;
#[cfg(test)]
pub(crate) use test_utils::{compute_tcp_checksum, compute_udp_checksum, compute_udp_checksum_v6};
