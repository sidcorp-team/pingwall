//! CIDR matching for rate limit rules.
//!
//! Implemented on top of `std::net` so the crate gains no new dependency
//! (this repo gitignores Cargo.lock, so adding one is more disruptive than
//! it looks). Handles IPv4 and IPv6, and treats a bare address as a /32
//! or /128 exact match.

use std::net::IpAddr;

/// Does `ip` fall inside the CIDR range `cidr`?
///
/// `cidr` may be "43.119.100.0/24", "2a03:2880::/32", or a bare address.
/// Returns false when either side fails to parse — a malformed rule must
/// never widen what it matches.
pub fn ip_in_cidr(ip: &str, cidr: &str) -> bool {
    let addr: IpAddr = match ip.trim().parse() {
        Ok(a) => a,
        Err(_) => return false,
    };

    let (net_str, prefix_str) = match cidr.trim().split_once('/') {
        Some((n, p)) => (n, Some(p)),
        None => (cidr.trim(), None),
    };

    let network: IpAddr = match net_str.parse() {
        Ok(n) => n,
        Err(_) => return false,
    };

    match (addr, network) {
        (IpAddr::V4(a), IpAddr::V4(n)) => {
            let prefix = match parse_prefix(prefix_str, 32) {
                Some(p) => p,
                None => return false,
            };
            masked_eq(&a.octets(), &n.octets(), prefix)
        }
        (IpAddr::V6(a), IpAddr::V6(n)) => {
            let prefix = match parse_prefix(prefix_str, 128) {
                Some(p) => p,
                None => return false,
            };
            masked_eq(&a.octets(), &n.octets(), prefix)
        }
        // Never match across families; an IPv4 rule must not catch IPv6.
        _ => false,
    }
}

/// True when `ip` is inside any of the supplied ranges.
pub fn ip_in_any_cidr(ip: &str, cidrs: &[String]) -> bool {
    cidrs.iter().any(|c| ip_in_cidr(ip, c))
}

fn parse_prefix(prefix: Option<&str>, max: u32) -> Option<u32> {
    match prefix {
        None => Some(max),
        Some(p) => match p.trim().parse::<u32>() {
            Ok(v) if v <= max => Some(v),
            _ => None,
        },
    }
}

/// Compare the first `prefix` bits of two equal-length octet strings.
fn masked_eq(a: &[u8], n: &[u8], prefix: u32) -> bool {
    let full = (prefix / 8) as usize;
    let rest = prefix % 8;

    if a[..full] != n[..full] {
        return false;
    }
    if rest == 0 {
        return true;
    }
    // Compare the leftover high bits of the next octet.
    let mask = 0xffu8 << (8 - rest);
    (a[full] & mask) == (n[full] & mask)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_inside_and_outside() {
        assert!(ip_in_cidr("43.119.100.130", "43.119.100.0/24"));
        assert!(ip_in_cidr("43.119.100.0", "43.119.100.0/24"));
        assert!(ip_in_cidr("43.119.100.255", "43.119.100.0/24"));
        assert!(!ip_in_cidr("43.119.101.1", "43.119.100.0/24"));
        assert!(!ip_in_cidr("47.82.201.9", "43.119.100.0/24"));
    }

    #[test]
    fn non_byte_aligned_prefix() {
        assert!(ip_in_cidr("10.0.0.1", "10.0.0.0/25"));
        assert!(!ip_in_cidr("10.0.0.200", "10.0.0.0/25"));
        assert!(ip_in_cidr("192.168.3.7", "192.168.0.0/20"));
        assert!(!ip_in_cidr("192.168.16.7", "192.168.0.0/20"));
    }

    #[test]
    fn ipv6_and_meta_range() {
        assert!(ip_in_cidr("2a03:2880:15ff:59::1", "2a03:2880::/32"));
        assert!(!ip_in_cidr("2a04:2880:15ff:59::1", "2a03:2880::/32"));
    }

    #[test]
    fn bare_address_is_exact() {
        assert!(ip_in_cidr("1.2.3.4", "1.2.3.4"));
        assert!(!ip_in_cidr("1.2.3.5", "1.2.3.4"));
    }

    #[test]
    fn families_never_cross() {
        assert!(!ip_in_cidr("2a03:2880::1", "0.0.0.0/0"));
        assert!(!ip_in_cidr("1.2.3.4", "::/0"));
    }

    #[test]
    fn malformed_input_never_matches() {
        assert!(!ip_in_cidr("not-an-ip", "43.119.100.0/24"));
        assert!(!ip_in_cidr("43.119.100.1", "43.119.100.0/99"));
        assert!(!ip_in_cidr("43.119.100.1", "garbage"));
    }

    #[test]
    fn any_of_list() {
        let list = vec!["43.119.100.0/24".to_string(), "47.82.201.0/24".to_string()];
        assert!(ip_in_any_cidr("47.82.201.9", &list));
        assert!(!ip_in_any_cidr("8.8.8.8", &list));
    }
}
