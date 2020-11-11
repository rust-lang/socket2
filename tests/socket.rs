#[cfg(unix)]
use std::os::unix::io::AsRawFd;

use socket2::{Domain, Socket, Type};

#[test]
fn set_nonblocking() {
    let socket = Socket::new(Domain::IPV4, Type::STREAM, None).unwrap();
    assert_non_blocking(&socket, false);

    socket.set_nonblocking(true).unwrap();
    assert_non_blocking(&socket, true);

    socket.set_nonblocking(false).unwrap();
    assert_non_blocking(&socket, false);
}

#[cfg(all(
    feature = "all",
    any(
        target_os = "android",
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "linux",
        target_os = "netbsd",
        target_os = "openbsd"
    )
))]
#[test]
fn type_nonblocking() {
    let ty = Type::Stream.nonblocking();
    let socket = Socket::new(Domain::IPV4, ty, None).unwrap();
    assert_non_blocking(&socket, true);
}

/// Assert that `NONBLOCK` is set on `socket`.
#[cfg(unix)]
#[track_caller]
pub fn assert_non_blocking<S>(socket: &S, want: bool)
where
    S: AsRawFd,
{
    let flags = unsafe { libc::fcntl(socket.as_raw_fd(), libc::F_GETFL) };
    assert_eq!(flags & libc::O_NONBLOCK != 0, want, "non-blocking option");
}

#[cfg(windows)]
#[track_caller]
pub fn assert_non_blocking<S>(_: &S, _: bool) {
    // No way to get this information...
}
