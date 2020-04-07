use std::io::Write;
use std::net::SocketAddr;
use std::str;

use crate::{Domain, Protocol, Type};

#[test]
fn domain_for_address() {
    let ipv4: SocketAddr = "127.0.0.1:8080".parse().unwrap();
    assert!(ipv4.is_ipv4());
    let ipv6: SocketAddr = "[::1]:8080".parse().unwrap();
    assert!(ipv6.is_ipv6());

    assert_eq!(Domain::for_address(ipv4), Domain::IPV4);
    assert_eq!(Domain::for_address(ipv6), Domain::IPV6);
}

#[test]
fn domain_fmt_debug() {
    let tests = &[
        (Domain::IPV4, "AF_INET"),
        (Domain::IPV6, "AF_INET6"),
        #[cfg(unix)]
        (Domain::UNIX, "AF_UNIX"),
        #[cfg(target_os = "linux")]
        (Domain::PACKET, "AF_UNIX"),
        (0.into(), "AF_UNSPEC"),
        (500.into(), "500"),
    ];

    let mut buf = Vec::new();
    for (input, want) in tests {
        buf.clear();
        write!(buf, "{:?}", input).unwrap();
        let got = str::from_utf8(&buf).unwrap();
        assert_eq!(got, *want);
    }
}

#[test]
fn type_fmt_debug() {
    let tests = &[
        (Type::STREAM, "SOCK_STREAM"),
        (Type::DGRAM, "SOCK_DGRAM"),
        (Type::SEQPACKET, "SOCK_SEQPACKET"),
        #[cfg(not(target_os = "redox"))]
        (Type::RAW, "SOCK_RAW"),
        (500.into(), "500"),
    ];

    let mut buf = Vec::new();
    for (input, want) in tests {
        buf.clear();
        write!(buf, "{:?}", input).unwrap();
        let got = str::from_utf8(&buf).unwrap();
        assert_eq!(got, *want);
    }
}

#[test]
fn protocol_fmt_debug() {
    let tests = &[
        (Protocol::ICMPV4, "IPPROTO_ICMP"),
        (Protocol::ICMPV6, "IPPROTO_ICMPV6"),
        (Protocol::TCP, "IPPROTO_TCP"),
        (Protocol::UDP, "IPPROTO_UDP"),
        (500.into(), "500"),
    ];

    let mut buf = Vec::new();
    for (input, want) in tests {
        buf.clear();
        write!(buf, "{:?}", input).unwrap();
        let got = str::from_utf8(&buf).unwrap();
        assert_eq!(got, *want);
    }
}
