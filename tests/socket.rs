#[cfg(all(feature = "all", target_os = "linux"))]
use std::ffi::CStr;
#[cfg(any(windows, target_vendor = "apple"))]
use std::io;
#[cfg(unix)]
use std::os::unix::io::AsRawFd;
#[cfg(windows)]
use std::os::windows::io::AsRawSocket;
use std::time::Duration;

#[cfg(windows)]
use winapi::shared::minwindef::DWORD;
#[cfg(windows)]
use winapi::um::handleapi::GetHandleInformation;
#[cfg(windows)]
use winapi::um::winbase::HANDLE_FLAG_INHERIT;

use socket2::{Domain, Socket, TcpKeepalive, Type};

#[test]
fn set_nonblocking() {
    let socket = Socket::new(Domain::IPV4, Type::STREAM, None).unwrap();
    assert_nonblocking(&socket, false);

    socket.set_nonblocking(true).unwrap();
    assert_nonblocking(&socket, true);

    socket.set_nonblocking(false).unwrap();
    assert_nonblocking(&socket, false);
}

#[test]
fn default_flags() {
    let socket = Socket::new(Domain::IPV4, Type::STREAM, None).unwrap();
    #[cfg(unix)]
    assert_close_on_exec(&socket, true);
    #[cfg(target_vendor = "apple")]
    assert_flag_no_sigpipe(&socket, true);
    #[cfg(windows)]
    assert_flag_no_inherit(&socket, true);
}

#[test]
fn no_default_flags() {
    let socket = Socket::new_raw(Domain::IPV4, Type::STREAM, None).unwrap();
    #[cfg(unix)]
    assert_close_on_exec(&socket, false);
    #[cfg(target_vendor = "apple")]
    assert_flag_no_sigpipe(&socket, false);
    #[cfg(windows)]
    assert_flag_no_inherit(&socket, false);
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

#[cfg(all(unix, feature = "all"))]
#[test]
fn set_cloexec() {
    let socket = Socket::new(Domain::IPV4, Type::STREAM, None).unwrap();
    assert_close_on_exec(&socket, true);

    socket.set_cloexec(false).unwrap();
    assert_close_on_exec(&socket, false);

    socket.set_cloexec(true).unwrap();
    assert_close_on_exec(&socket, true);
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

#[cfg(all(windows, feature = "all"))]
#[test]
fn set_no_inherit() {
    let socket = Socket::new(Domain::IPV4, Type::STREAM, None).unwrap();
    assert_flag_no_inherit(&socket, true);

    socket.set_no_inherit(false).unwrap();
    assert_flag_no_inherit(&socket, false);

    socket.set_no_inherit(true).unwrap();
    assert_flag_no_inherit(&socket, true);
}

#[cfg(all(feature = "all", windows))]
#[test]
fn type_no_inherit() {
    let ty = Type::STREAM.no_inherit();
    let socket = Socket::new(Domain::IPV4, ty, None).unwrap();
    assert_flag_no_inherit(&socket, true);
}

/// Assert that `FLAG_INHERIT` is not set on `socket`.
#[cfg(windows)]
#[track_caller]
pub fn assert_flag_no_inherit<S>(socket: &S, want: bool)
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
        !want,
        "FLAG_INHERIT option"
    );
}

#[cfg(all(feature = "all", target_vendor = "apple"))]
#[test]
fn set_nosigpipe() {
    let socket = Socket::new(Domain::IPV4, Type::STREAM, None).unwrap();
    assert_flag_no_sigpipe(&socket, true);

    socket.set_nosigpipe(false).unwrap();
    assert_flag_no_sigpipe(&socket, false);

    socket.set_nosigpipe(true).unwrap();
    assert_flag_no_sigpipe(&socket, true);
}

/// Assert that `SO_NOSIGPIPE` is set on `socket`.
#[cfg(target_vendor = "apple")]
#[track_caller]
pub fn assert_flag_no_sigpipe<S>(socket: &S, want: bool)
where
    S: AsRawFd,
{
    use std::mem::size_of;
    let mut flags: libc::c_int = 0;
    let mut length = size_of::<libc::c_int>() as libc::socklen_t;
    let res = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_NOSIGPIPE,
            &mut flags as *mut _ as *mut _,
            &mut length,
        )
    };
    if res != 0 {
        let err = io::Error::last_os_error();
        panic!("unexpected error: {}", err);
    }
    assert_eq!(length as usize, size_of::<libc::c_int>());
    assert_eq!(flags, want as _, "non-blocking option");
}

#[test]
fn keepalive() {
    let socket = Socket::new(Domain::IPV4, Type::STREAM, None).unwrap();
    let params = TcpKeepalive::new().with_time(Duration::from_secs(200));

    #[cfg(all(
        feature = "all",
        any(
            target_os = "freebsd",
            target_os = "linux",
            target_os = "netbsd",
            target_vendor = "apple",
            windows,
        )
    ))]
    let params = params.with_interval(Duration::from_secs(30));

    #[cfg(all(
        feature = "all",
        any(
            target_os = "freebsd",
            target_os = "linux",
            target_os = "netbsd",
            target_vendor = "apple",
        )
    ))]
    let params = params.with_retries(10);

    // Set the parameters.
    socket.set_tcp_keepalive(&params).unwrap();

    #[cfg(all(feature = "all", not(windows)))]
    assert_eq!(socket.keepalive_time().unwrap(), Duration::from_secs(200));

    #[cfg(all(
        feature = "all",
        any(
            target_os = "android",
            target_os = "dragonfly",
            target_os = "freebsd",
            target_os = "illumos",
            target_os = "linux",
            target_os = "netbsd",
            target_vendor = "apple",
        )
    ))]
    assert_eq!(
        socket.keepalive_interval().unwrap(),
        Duration::from_secs(30)
    );

    #[cfg(all(
        feature = "all",
        any(
            target_os = "android",
            target_os = "dragonfly",
            target_os = "freebsd",
            target_os = "illumos",
            target_os = "linux",
            target_os = "netbsd",
            target_vendor = "apple",
        )
    ))]
    assert_eq!(socket.keepalive_retries().unwrap(), 10);
}

#[cfg(all(feature = "all", target_os = "linux"))]
#[test]
fn device() {
    const INTERFACE: &str = "lo0\0";
    let interface = CStr::from_bytes_with_nul(INTERFACE.as_bytes()).unwrap();
    let socket = Socket::new(Domain::IPV4, Type::STREAM, None).unwrap();

    assert_eq!(socket.device().unwrap(), None);

    socket.bind_device(Some(interface)).unwrap();
    assert_eq!(socket.device().unwrap().as_deref(), Some(interface));

    socket.bind_device(None).unwrap();
    assert_eq!(socket.device().unwrap(), None);
}
