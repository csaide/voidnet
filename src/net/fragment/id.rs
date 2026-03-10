use std::sync::atomic::{AtomicU16, AtomicU32, Ordering};

/// Global atomic counter for IPv4 fragment identification field.
static FRAGMENT_IPV4_ID: AtomicU16 = AtomicU16::new(1);

/// Global atomic counter for IPv6 fragment identification field.
static FRAGMENT_IPV6_ID: AtomicU32 = AtomicU32::new(1);

/// Atomically obtain the next IPv4 fragment identification value.
#[inline]
pub(crate) fn next_ipv4_id() -> u16 {
    FRAGMENT_IPV4_ID.fetch_add(1, Ordering::Relaxed)
}

/// Atomically obtain the next IPv6 fragment identification value.
#[inline]
pub(crate) fn next_ipv6_id() -> u32 {
    FRAGMENT_IPV6_ID.fetch_add(1, Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_id_increments() {
        let a = next_ipv4_id();
        let b = next_ipv4_id();
        assert_eq!(b, a.wrapping_add(1));
    }

    #[test]
    fn ipv6_id_increments() {
        let a = next_ipv6_id();
        let b = next_ipv6_id();
        assert_eq!(b, a.wrapping_add(1));
    }
}
