//! Tests for getting and setting socket options.

use socket2::{Domain, Socket, Type};

/// Macro to create a simple test to set and get a socket option.
macro_rules! test {
    // Test using the `arg`ument as expected return value.
    ($( #[ $attr: meta ] )* $get_fn: ident, $set_fn: ident ( $arg: expr ) ) => {
        test!($( #[$attr] )* $get_fn, $set_fn($arg), $arg);
    };
    ($( #[ $attr: meta ] )* $get_fn: ident, $set_fn: ident ( $arg: expr ), $expected: expr ) => {
        #[test]
        $( #[$attr] )*
        fn $get_fn() {
            test!(__ Domain::IPV4, $get_fn, $set_fn($arg), $expected);
            test!(__ Domain::IPV6, $get_fn, $set_fn($arg), $expected);
        }
    };
    // Only test using a IPv4 socket.
    (IPv4 $get_fn: ident, $set_fn: ident ( $arg: expr ) ) => {
        #[test]
        fn $get_fn() {
            test!(__ Domain::IPV4, $get_fn, $set_fn($arg), $arg);
        }
    };
    // Only test using a IPv6 socket.
    (IPv6 $get_fn: ident, $set_fn: ident ( $arg: expr ) ) => {
        #[test]
        fn $get_fn() {
            test!(__ Domain::IPV6, $get_fn, $set_fn($arg), $arg);
        }
    };

    // Internal to this macro.
    (__ $ty: expr, $get_fn: ident, $set_fn: ident ( $arg: expr ), $expected: expr ) => {
        let socket = Socket::new($ty, Type::STREAM, None).expect("failed to create `Socket`");

        let initial = socket.$get_fn().expect("failed to get initial value");
        let arg = $arg;
        let expected = $expected;
        assert_ne!(initial, arg, "initial value and argument are the same");

        socket.$set_fn(arg).expect("failed to set option");
        let got = socket.$get_fn().expect("failed to get value");
        assert_eq!(got, expected, "set and get values differ");
    };
}

const SET_BUF_SIZE: usize = 4096;
// Linux doubles the buffer size for kernel usage, and exposes that when
// retrieving the buffer size.
#[cfg(not(target_os = "linux"))]
const GET_BUF_SIZE: usize = SET_BUF_SIZE;
#[cfg(target_os = "linux")]
const GET_BUF_SIZE: usize = 2 * SET_BUF_SIZE;

test!(nodelay, set_nodelay(true));
test!(
    recv_buffer_size,
    set_recv_buffer_size(SET_BUF_SIZE),
    GET_BUF_SIZE
);
test!(
    send_buffer_size,
    set_send_buffer_size(SET_BUF_SIZE),
    GET_BUF_SIZE
);
#[cfg(all(feature = "all", not(target_os = "redox")))]
test!(out_of_band_inline, set_out_of_band_inline(true));
test!(reuse_address, set_reuse_address(true));
#[cfg(all(
    feature = "all",
    not(any(windows, target_os = "solaris", target_os = "illumos"))
))]
test!(reuse_port, set_reuse_port(true));
#[cfg(all(feature = "all", unix))]
test!(
    #[cfg_attr(target_os = "linux", ignore = "Different value returned")]
    mss,
    set_mss(256)
);
#[cfg(all(feature = "all", target_os = "linux"))]
test!(
    #[ignore = "setting `SO_MARK` requires the `CAP_NET_ADMIN` capability (works when running as root)"]
    mark,
    set_mark(123)
);

test!(IPv4 ttl, set_ttl(40));
#[cfg(not(windows))] // TODO: returns `WSAENOPROTOOPT` (10042) on Windows.
test!(IPv4 broadcast, set_broadcast(true));

test!(IPv6 unicast_hops_v6, set_unicast_hops_v6(20));
#[cfg(not(windows))]
test!(IPv6 only_v6, set_only_v6(true));
#[cfg(windows)] // IPv6 socket are already IPv6 only on Windows.
test!(IPv6 only_v6, set_only_v6(false));
