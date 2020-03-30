use std::io::Write;
use std::str;

use crate::Domain;

#[test]
fn domain_fmt_debug() {
    let tests = &[
        (Domain::ipv4(), "AF_INET"),
        (Domain::ipv6(), "AF_INET6"),
        #[cfg(unix)]
        (Domain::unix(), "AF_UNIX"),
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
