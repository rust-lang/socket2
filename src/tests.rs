use std::io::Write;
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};
use std::str;

use crate::{Domain, Protocol, SockAddr, Socket, Type};

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
        #[cfg(all(feature = "all", target_os = "linux"))]
        (Domain::PACKET, "AF_PACKET"),
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
        #[cfg(all(feature = "all", not(target_os = "redox")))]
        (Type::SEQPACKET, "SOCK_SEQPACKET"),
        #[cfg(all(feature = "all", not(target_os = "redox")))]
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

#[test]
fn socket_address_ipv4() {
    let string = "127.0.0.1:80";
    let std = string.parse::<SocketAddrV4>().unwrap();
    let addr = SockAddr::from(std);

    assert_eq!(addr.as_std(), Some(SocketAddr::V4(std)));
    assert_eq!(addr.as_inet(), Some(std));
    assert!(addr.as_inet6().is_none());
}

#[test]
fn socket_address_ipv6() {
    let string = "[2001:db8::ff00:42:8329]:80";
    let std = string.parse::<SocketAddrV6>().unwrap();
    let addr = SockAddr::from(std);

    assert_eq!(addr.as_std(), Some(SocketAddr::V6(std)));
    assert!(addr.as_inet().is_none());
    assert_eq!(addr.as_inet6(), Some(std));
}

#[test]
#[cfg(all(unix, feature = "all"))]
fn socket_address_unix() {
    let string = "/tmp/socket";
    let addr = SockAddr::unix(string).unwrap();
    assert!(addr.as_inet().is_none());
    assert!(addr.as_inet6().is_none());
}

/// Create a pair of non-connected UDP sockets suitable for unit tests.
#[cfg(not(target_os = "redox"))]
fn udp_pair_unconnected() -> (Socket, Socket) {
    // Use ephemeral ports assigned by the OS.
    let unspecified_addr = std::net::SocketAddrV6::new(std::net::Ipv6Addr::LOCALHOST, 0, 0, 0);
    let socket_a = Socket::new(Domain::IPV6, Type::DGRAM, None).unwrap();
    let socket_b = Socket::new(Domain::IPV6, Type::DGRAM, None).unwrap();

    socket_a.bind(&unspecified_addr.into()).unwrap();
    socket_b.bind(&unspecified_addr.into()).unwrap();

    // Set low timeouts to prevent the tests from blocking.
    socket_a
        .set_read_timeout(Some(std::time::Duration::from_millis(10)))
        .unwrap();
    socket_b
        .set_read_timeout(Some(std::time::Duration::from_millis(10)))
        .unwrap();
    socket_a
        .set_write_timeout(Some(std::time::Duration::from_millis(10)))
        .unwrap();
    socket_b
        .set_write_timeout(Some(std::time::Duration::from_millis(10)))
        .unwrap();

    (socket_a, socket_b)
}

/// Create a pair of connected UDP sockets suitable for unit tests.
#[cfg(not(target_os = "redox"))]
fn udp_pair_connected() -> (Socket, Socket) {
    let (socket_a, socket_b) = udp_pair_unconnected();

    let addr_a = socket_a.local_addr().unwrap();
    let addr_b = socket_b.local_addr().unwrap();
    socket_a.connect(&addr_b).unwrap();
    socket_b.connect(&addr_a).unwrap();

    (socket_a, socket_b)
}

#[test]
#[cfg(not(target_os = "redox"))]
fn send_recv_vectored() {
    use std::io::{IoSlice, IoSliceMut};

    let (socket_a, socket_b) = udp_pair_connected();

    let sent = socket_a
        .send_vectored(&[
            IoSlice::new(b"the"),
            IoSlice::new(b"weeknight"),
            IoSlice::new(b"would"),
            IoSlice::new(b"yellow"),
        ])
        .unwrap();
    assert_eq!(sent, 23);

    let mut the = [0u8; 3];
    let mut wee = [0u8; 3];
    let mut knight = [0u8; 6];
    let mut would = [0u8; 5];
    let mut yell = [0u8; 4];
    let mut ow = [0u8; 2];

    let (received, flags) = socket_b
        .recv_vectored(&mut [
            IoSliceMut::new(&mut the),
            IoSliceMut::new(&mut wee),
            IoSliceMut::new(&mut knight),
            IoSliceMut::new(&mut would),
            IoSliceMut::new(&mut yell),
            IoSliceMut::new(&mut ow),
        ])
        .unwrap();
    assert_eq!(received, 23);
    #[cfg(all(unix, not(target_os = "redox")))]
    assert_eq!(flags.is_end_of_record(), false);
    #[cfg(all(unix, not(target_os = "redox")))]
    assert_eq!(flags.is_out_of_band(), false);
    assert_eq!(flags.is_truncated(), false);

    assert_eq!(&the, b"the");
    assert_eq!(&wee, b"wee");
    assert_eq!(&knight, b"knight");
    assert_eq!(&would, b"would");
    assert_eq!(&yell, b"yell");
    assert_eq!(&ow, b"ow");
}

#[test]
#[cfg(not(target_os = "redox"))]
fn send_from_recv_to_vectored() {
    use std::io::{IoSlice, IoSliceMut};

    let (socket_a, socket_b) = udp_pair_unconnected();
    let addr_a = socket_a.local_addr().unwrap();
    let addr_b = socket_b.local_addr().unwrap();

    let sent = socket_a
        .send_to_vectored(
            &[
                IoSlice::new(b"surgeon"),
                IoSlice::new(b"has"),
                IoSlice::new(b"menswear"),
            ],
            &addr_b,
            0,
        )
        .unwrap();
    assert_eq!(sent, 18);

    let mut surgeon = [0u8; 7];
    let mut has = [0u8; 3];
    let mut men = [0u8; 3];
    let mut swear = [0u8; 5];
    let (received, flags, addr) = socket_b
        .recv_from_vectored(&mut [
            IoSliceMut::new(&mut surgeon),
            IoSliceMut::new(&mut has),
            IoSliceMut::new(&mut men),
            IoSliceMut::new(&mut swear),
        ])
        .unwrap();

    assert_eq!(received, 18);
    #[cfg(all(unix, not(target_os = "redox")))]
    assert_eq!(flags.is_end_of_record(), false);
    #[cfg(all(unix, not(target_os = "redox")))]
    assert_eq!(flags.is_out_of_band(), false);
    assert_eq!(flags.is_truncated(), false);
    assert_eq!(addr.as_inet6().unwrap(), addr_a.as_inet6().unwrap());
    assert_eq!(&surgeon, b"surgeon");
    assert_eq!(&has, b"has");
    assert_eq!(&men, b"men");
    assert_eq!(&swear, b"swear");
}

#[test]
#[cfg(not(target_os = "redox"))]
fn recv_vectored_truncated() {
    use std::io::IoSliceMut;

    let (socket_a, socket_b) = udp_pair_connected();

    let sent = socket_a
        .send(b"do not feed the gremlins after midnight")
        .unwrap();
    assert_eq!(sent, 39);

    let mut buffer = [0u8; 24];

    let (received, flags) = socket_b
        .recv_vectored(&mut [IoSliceMut::new(&mut buffer)])
        .unwrap();
    assert_eq!(received, 24);
    assert_eq!(flags.is_truncated(), true);
    assert_eq!(&buffer, b"do not feed the gremlins");
}

#[test]
#[cfg(not(target_os = "redox"))]
fn recv_from_vectored_truncated() {
    use std::io::IoSliceMut;

    let (socket_a, socket_b) = udp_pair_unconnected();
    let addr_a = socket_a.local_addr().unwrap();
    let addr_b = socket_b.local_addr().unwrap();

    let sent = socket_a
        .send_to(b"do not feed the gremlins after midnight", &addr_b)
        .unwrap();
    assert_eq!(sent, 39);

    let mut buffer = [0u8; 24];

    let (received, flags, addr) = socket_b
        .recv_from_vectored(&mut [IoSliceMut::new(&mut buffer)])
        .unwrap();
    assert_eq!(received, 24);
    assert_eq!(flags.is_truncated(), true);
    assert_eq!(addr.as_inet6().unwrap(), addr_a.as_inet6().unwrap());
    assert_eq!(&buffer, b"do not feed the gremlins");
}
