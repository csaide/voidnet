mod common;
mod compute;
mod verify;

#[cfg(test)]
mod test_utils;

pub(crate) use common::{
    checksum_to_bytes, fold_and_verify, fold_checksum, pseudo_header_sum_v4, pseudo_header_sum_v6,
    sum_words, sum_words_carry,
};
pub(crate) use compute::{
    compute_icmpv6_checksum, compute_ipv4_checksum, compute_tcp_checksum_from_parts,
    compute_tcp_checksum_v6_from_parts, compute_udp_checksum_from_parts,
    compute_udp_checksum_v6_from_parts,
};
pub(crate) use verify::{
    verify_ipv4_checksum, verify_tcp_checksum, verify_tcp_checksum_v6, verify_udp_checksum,
    verify_udp_checksum_v6,
};

#[cfg(test)]
pub(crate) use test_utils::{compute_tcp_checksum, compute_udp_checksum, compute_udp_checksum_v6};
