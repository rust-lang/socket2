#[cfg(windows)]
use std::io;
#[cfg(unix)]
use std::os::unix::io::AsRawFd;
#[cfg(windows)]
use std::os::windows::io::AsRawSocket;

#[cfg(windows)]
use winapi::shared::minwindef::DWORD;
#[cfg(windows)]
use winapi::um::handleapi::GetHandleInformation;
#[cfg(windows)]
use winapi::um::winbase::HANDLE_FLAG_INHERIT;

use socket2::{Domain, Socket, Type};

#[test]
fn set_nonblocking() {
    let socket = Socket::new(Domain::IPV4, Type::STREAM, None).unwrap();
    assert_nonblocking(&socket, false);

    socket.set_nonblocking(true).unwrap();
    assert_nonblocking(&socket, true);

    socket.set_nonblocking(false).unwrap();
    assert_nonblocking(&socket, false);
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
    let ty = Type::STREAM.nonblocking();
    let socket = Socket::new(Domain::IPV4, ty, None).unwrap();
    assert_nonblocking(&socket, true);
}

/// Assert that `NONBLOCK` is set on `socket`.
#[cfg(unix)]
#[track_caller]
pub fn assert_nonblocking<S>(socket: &S, want: bool)
where
    S: AsRawFd,
{
    let flags = unsafe { libc::fcntl(socket.as_raw_fd(), libc::F_GETFL) };
    assert_eq!(flags & libc::O_NONBLOCK != 0, want, "non-blocking option");
}

#[cfg(windows)]
#[track_caller]
pub fn assert_nonblocking<S>(_: &S, _: bool) {
    // No way to get this information...
}

#[cfg(unix)]
#[test]
fn set_cloexec() {
    let socket = Socket::new(Domain::IPV4, Type::STREAM, None).unwrap();
    assert_close_on_exec(&socket, false);

    socket.set_cloexec(true).unwrap();
    assert_close_on_exec(&socket, true);

    socket.set_cloexec(false).unwrap();
    assert_close_on_exec(&socket, false);
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
fn type_cloexec() {
    let ty = Type::STREAM.cloexec();
    let socket = Socket::new(Domain::IPV4, ty, None).unwrap();
    assert_close_on_exec(&socket, true);
}

/// Assert that `CLOEXEC` is set on `socket`.
#[cfg(unix)]
#[track_caller]
pub fn assert_close_on_exec<S>(socket: &S, want: bool)
where
    S: AsRawFd,
{
    let flags = unsafe { libc::fcntl(socket.as_raw_fd(), libc::F_GETFD) };
    assert_eq!(flags & libc::FD_CLOEXEC != 0, want, "CLOEXEC option");
}

#[cfg(windows)]
#[test]
fn set_no_inherit() {
    let socket = Socket::new(Domain::IPV4, Type::STREAM, None).unwrap();
    assert_flag_inherit(&socket, false);

    socket.set_no_inherit(true).unwrap();
    assert_flag_inherit(&socket, true);

    socket.set_no_inherit(false).unwrap();
    assert_flag_inherit(&socket, false);
}

#[cfg(all(feature = "all", windows))]
#[test]
fn type_no_inherit() {
    let ty = Type::STREAM.no_inherit();
    let socket = Socket::new(Domain::IPV4, ty, None).unwrap();
    assert_flag_inherit(&socket, true);
}

/// Assert that `FLAG_INHERIT` is set on `socket`.
#[cfg(windows)]
#[track_caller]
pub fn assert_flag_inherit<S>(socket: &S, want: bool)
where
    S: AsRawSocket,
{
    let mut flags: DWORD = 0;
    if unsafe { GetHandleInformation(socket.as_raw_socket() as _, &mut flags) } == 0 {
        let err = io::Error::last_os_error();
        panic!("unexpected error: {}", err);
    }
    assert_eq!(
        flags & HANDLE_FLAG_INHERIT != 0,
        want,
        "FLAG_INHERIT option"
    );
}
