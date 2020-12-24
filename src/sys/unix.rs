// Copyright 2015 The Rust Project Developers.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::cmp::min;
#[cfg(all(feature = "all", any(target_os = "fuchsia", target_os = "linux")))]
use std::ffi::{CStr, CString};
#[cfg(not(target_os = "redox"))]
use std::io::IoSlice;
use std::marker::PhantomData;
use std::mem::{self, size_of, MaybeUninit};
use std::net::Shutdown;
use std::net::{Ipv4Addr, Ipv6Addr};
#[cfg(feature = "all")]
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd};
#[cfg(feature = "all")]
use std::os::unix::net::{UnixDatagram, UnixListener, UnixStream};
#[cfg(feature = "all")]
use std::path::Path;
#[cfg(not(all(target_os = "redox", not(feature = "all"))))]
use std::ptr;
use std::time::Duration;
use std::{io, slice};

#[cfg(not(target_vendor = "apple"))]
use libc::ssize_t;
use libc::{c_void, in6_addr, in_addr};

#[cfg(not(target_os = "redox"))]
use crate::RecvFlags;
use crate::{Domain, SockAddr, TcpKeepalive, Type};

pub(crate) use libc::c_int;

// Used in `Domain`.
pub(crate) use libc::{AF_INET, AF_INET6};
// Used in `Type`.
#[cfg(all(feature = "all", not(target_os = "redox")))]
pub(crate) use libc::SOCK_RAW;
#[cfg(feature = "all")]
pub(crate) use libc::SOCK_SEQPACKET;
pub(crate) use libc::{SOCK_DGRAM, SOCK_STREAM};
// Used in `Protocol`.
pub(crate) use libc::{IPPROTO_ICMP, IPPROTO_ICMPV6, IPPROTO_TCP, IPPROTO_UDP};
// Used in `SockAddr`.
pub(crate) use libc::{
    sa_family_t, sockaddr, sockaddr_in, sockaddr_in6, sockaddr_storage, socklen_t,
};
// Used in `RecvFlags`.
#[cfg(not(target_os = "redox"))]
pub(crate) use libc::{MSG_TRUNC, SO_OOBINLINE};
// Used in `Socket`.
pub(crate) use libc::{
    ip_mreq as IpMreq, ipv6_mreq as Ipv6Mreq, linger, IPPROTO_IP, IPPROTO_IPV6,
    IPV6_MULTICAST_HOPS, IPV6_MULTICAST_IF, IPV6_MULTICAST_LOOP, IPV6_UNICAST_HOPS, IPV6_V6ONLY,
    IP_ADD_MEMBERSHIP, IP_DROP_MEMBERSHIP, IP_MULTICAST_IF, IP_MULTICAST_LOOP, IP_MULTICAST_TTL,
    IP_TTL, MSG_OOB, MSG_PEEK, SOL_SOCKET, SO_BROADCAST, SO_ERROR, SO_KEEPALIVE, SO_LINGER,
    SO_RCVBUF, SO_RCVTIMEO, SO_REUSEADDR, SO_SNDBUF, SO_SNDTIMEO, TCP_NODELAY,
};
#[cfg(not(any(
    target_os = "dragonfly",
    target_os = "freebsd",
    target_os = "haiku",
    target_os = "illumos",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "solaris",
    target_vendor = "apple"
)))]
pub(crate) use libc::{IPV6_ADD_MEMBERSHIP, IPV6_DROP_MEMBERSHIP};
#[cfg(any(
    target_os = "dragonfly",
    target_os = "freebsd",
    target_os = "haiku",
    target_os = "illumos",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "solaris",
    target_vendor = "apple",
))]
pub(crate) use libc::{
    IPV6_JOIN_GROUP as IPV6_ADD_MEMBERSHIP, IPV6_LEAVE_GROUP as IPV6_DROP_MEMBERSHIP,
};
#[cfg(all(
    feature = "all",
    any(
        target_os = "freebsd",
        target_os = "fuchsia",
        target_os = "linux",
        target_os = "netbsd",
        target_vendor = "apple",
    )
))]
pub(crate) use libc::{TCP_KEEPCNT, TCP_KEEPINTVL};

// See this type in the Windows file.
pub(crate) type Bool = c_int;

#[cfg(any(target_os = "openbsd", target_os = "haiku"))]
use libc::SO_KEEPALIVE as KEEPALIVE_TIME;
#[cfg(target_vendor = "apple")]
use libc::TCP_KEEPALIVE as KEEPALIVE_TIME;
#[cfg(not(any(target_os = "openbsd", target_os = "haiku", target_vendor = "apple")))]
use libc::TCP_KEEPIDLE as KEEPALIVE_TIME;

/// Helper macro to execute a system call that returns an `io::Result`.
macro_rules! syscall {
    ($fn: ident ( $($arg: expr),* $(,)* ) ) => {{
        #[allow(unused_unsafe)]
        let res = unsafe { libc::$fn($($arg, )*) };
        if res == -1 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(res)
        }
    }};
}

/// Maximum size of a buffer passed to system call like `recv` and `send`.
#[cfg(not(target_vendor = "apple"))]
const MAX_BUF_LEN: usize = <ssize_t>::max_value() as usize;

// The maximum read limit on most posix-like systems is `SSIZE_MAX`, with the
// man page quoting that if the count of bytes to read is greater than
// `SSIZE_MAX` the result is "unspecified".
//
// On macOS, however, apparently the 64-bit libc is either buggy or
// intentionally showing odd behavior by rejecting any read with a size larger
// than or equal to INT_MAX. To handle both of these the read size is capped on
// both platforms.
#[cfg(target_vendor = "apple")]
const MAX_BUF_LEN: usize = <c_int>::max_value() as usize - 1;

#[cfg(any(target_os = "android", all(target_os = "linux", target_env = "gnu")))]
type IovLen = usize;

#[cfg(any(
    all(target_os = "linux", target_env = "musl"),
    target_os = "dragonfly",
    target_os = "freebsd",
    target_os = "fuchsia",
    target_os = "illumos",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "solaris",
    target_vendor = "apple",
))]
type IovLen = c_int;

/// Unix only API.
impl Domain {
    /// Domain for Unix socket communication, corresponding to `AF_UNIX`.
    pub const UNIX: Domain = Domain(libc::AF_UNIX);

    /// Domain for low-level packet interface, corresponding to `AF_PACKET`.
    ///
    /// # Notes
    ///
    /// This function is only available on Fuchsia and Linux.
    #[cfg(all(feature = "all", any(target_os = "fuchsia", target_os = "linux")))]
    pub const PACKET: Domain = Domain(libc::AF_PACKET);
}

impl_debug!(
    Domain,
    libc::AF_INET,
    libc::AF_INET6,
    libc::AF_UNIX,
    #[cfg(any(target_os = "fuchsia", target_os = "linux"))]
    libc::AF_PACKET,
    libc::AF_UNSPEC, // = 0.
);

/// Unix only API.
impl Type {
    /// Set `SOCK_NONBLOCK` on the `Type`.
    ///
    /// # Notes
    ///
    /// This function is only available on Android, DragonFlyBSD, Fuchsia,
    /// FreeBSD, Linux, NetBSD and OpenBSD.
    #[cfg(all(
        feature = "all",
        any(
            target_os = "android",
            target_os = "dragonfly",
            target_os = "freebsd",
            target_os = "fuchsia",
            target_os = "illumos",
            target_os = "linux",
            target_os = "netbsd",
            target_os = "openbsd"
        )
    ))]
    pub const fn nonblocking(self) -> Type {
        Type(self.0 | libc::SOCK_NONBLOCK)
    }

    /// Set `SOCK_CLOEXEC` on the `Type`.
    ///
    /// # Notes
    ///
    /// This function is only available on Android, DragonFlyBSD, Fuchsia,
    /// FreeBSD, Linux, NetBSD and OpenBSD.
    #[cfg(all(
        feature = "all",
        any(
            target_os = "android",
            target_os = "dragonfly",
            target_os = "freebsd",
            target_os = "fuchsia",
            target_os = "illumos",
            target_os = "linux",
            target_os = "netbsd",
            target_os = "openbsd"
        )
    ))]
    pub const fn cloexec(self) -> Type {
        self._cloexec()
    }

    #[cfg(any(
        target_os = "android",
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "fuchsia",
        target_os = "illumos",
        target_os = "linux",
        target_os = "netbsd",
        target_os = "openbsd"
    ))]
    pub(crate) const fn _cloexec(self) -> Type {
        Type(self.0 | libc::SOCK_CLOEXEC)
    }
}

impl_debug!(
    crate::Type,
    libc::SOCK_STREAM,
    libc::SOCK_DGRAM,
    #[cfg(not(target_os = "redox"))]
    libc::SOCK_RAW,
    #[cfg(not(any(target_os = "redox", target_os = "haiku")))]
    libc::SOCK_RDM,
    libc::SOCK_SEQPACKET,
    /* TODO: add these optional bit OR-ed flags:
    #[cfg(any(
        target_os = "android",
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "fuchsia",
        target_os = "linux",
        target_os = "netbsd",
        target_os = "openbsd"
    ))]
    libc::SOCK_NONBLOCK,
    #[cfg(any(
        target_os = "android",
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "fuchsia",
        target_os = "linux",
        target_os = "netbsd",
        target_os = "openbsd"
    ))]
    libc::SOCK_CLOEXEC,
    */
);

impl_debug!(
    crate::Protocol,
    libc::IPPROTO_ICMP,
    libc::IPPROTO_ICMPV6,
    libc::IPPROTO_TCP,
    libc::IPPROTO_UDP,
);

/// Unix-only API.
#[cfg(not(target_os = "redox"))]
impl RecvFlags {
    /// Check if the message terminates a record.
    ///
    /// Not all socket types support the notion of records.
    /// For socket types that do support it (such as [`SEQPACKET`][Type::SEQPACKET]),
    /// a record is terminated by sending a message with the end-of-record flag set.
    ///
    /// On Unix this corresponds to the MSG_EOR flag.
    pub const fn is_end_of_record(self) -> bool {
        self.0 & libc::MSG_EOR != 0
    }

    /// Check if the message contains out-of-band data.
    ///
    /// This is useful for protocols where you receive out-of-band data
    /// mixed in with the normal data stream.
    ///
    /// On Unix this corresponds to the MSG_OOB flag.
    pub const fn is_out_of_band(self) -> bool {
        self.0 & libc::MSG_OOB != 0
    }
}

#[cfg(not(target_os = "redox"))]
impl std::fmt::Debug for RecvFlags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecvFlags")
            .field("is_end_of_record", &self.is_end_of_record())
            .field("is_out_of_band", &self.is_out_of_band())
            .field("is_truncated", &self.is_truncated())
            .finish()
    }
}

#[repr(transparent)]
pub struct MaybeUninitSlice<'a> {
    vec: libc::iovec,
    _lifetime: PhantomData<&'a mut [MaybeUninit<u8>]>,
}

impl<'a> MaybeUninitSlice<'a> {
    pub(crate) fn new(buf: &'a mut [MaybeUninit<u8>]) -> MaybeUninitSlice<'a> {
        MaybeUninitSlice {
            vec: libc::iovec {
                iov_base: buf.as_mut_ptr().cast(),
                iov_len: buf.len(),
            },
            _lifetime: PhantomData,
        }
    }

    pub(crate) fn as_slice(&self) -> &[MaybeUninit<u8>] {
        unsafe { slice::from_raw_parts(self.vec.iov_base.cast(), self.vec.iov_len) }
    }

    pub(crate) fn as_mut_slice(&mut self) -> &mut [MaybeUninit<u8>] {
        unsafe { slice::from_raw_parts_mut(self.vec.iov_base.cast(), self.vec.iov_len) }
    }
}

/// Unix only API.
impl SockAddr {
    /// Constructs a `SockAddr` with the family `AF_UNIX` and the provided path.
    ///
    /// This function is only available on Unix.
    ///
    /// # Failure
    ///
    /// Returns an error if the path is longer than `SUN_LEN`.
    #[cfg(feature = "all")]
    pub fn unix<P>(path: P) -> io::Result<SockAddr>
    where
        P: AsRef<Path>,
    {
        // Safety: zeroed `sockaddr_un` is valid.
        let mut addr: libc::sockaddr_un = unsafe { mem::zeroed() };

        let bytes = path.as_ref().as_os_str().as_bytes();
        if bytes.len() >= addr.sun_path.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "path must be shorter than SUN_LEN",
            ));
        }

        addr.sun_family = libc::AF_UNIX as sa_family_t;
        // Safety: `bytes` and `addr.sun_path` are not overlapping and `bytes`
        // points to valid memory.
        unsafe {
            ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                addr.sun_path.as_mut_ptr() as *mut u8,
                bytes.len(),
            )
        };
        // Zeroed memory above, so the path is already null terminated.

        let base = &addr as *const _ as usize;
        let path = &addr.sun_path as *const _ as usize;
        let sun_path_offset = path - base;
        let mut len = sun_path_offset + bytes.len();
        match bytes.first() {
            Some(&0) | None => {}
            Some(_) => len += 1,
        };
        Ok(unsafe { SockAddr::from_raw_parts(&addr as *const _ as *const _, len as socklen_t) })
    }
}

pub(crate) type Socket = c_int;

pub(crate) fn socket(family: c_int, ty: c_int, protocol: c_int) -> io::Result<Socket> {
    syscall!(socket(family, ty, protocol))
}

#[cfg(feature = "all")]
pub(crate) fn socketpair(family: c_int, ty: c_int, protocol: c_int) -> io::Result<[Socket; 2]> {
    let mut fds = [0, 0];
    syscall!(socketpair(family, ty, protocol, fds.as_mut_ptr())).map(|_| fds)
}

pub(crate) fn bind(fd: Socket, addr: &SockAddr) -> io::Result<()> {
    syscall!(bind(fd, addr.as_ptr(), addr.len() as _)).map(|_| ())
}

pub(crate) fn connect(fd: Socket, addr: &SockAddr) -> io::Result<()> {
    syscall!(connect(fd, addr.as_ptr(), addr.len())).map(|_| ())
}

pub(crate) fn listen(fd: Socket, backlog: i32) -> io::Result<()> {
    syscall!(listen(fd, backlog)).map(|_| ())
}

pub(crate) fn accept(fd: Socket) -> io::Result<(Socket, SockAddr)> {
    // Safety: `accept` initialises the `SockAddr` for us.
    unsafe { SockAddr::init(|storage, len| syscall!(accept(fd, storage.cast(), len))) }
}

pub(crate) fn getsockname(fd: Socket) -> io::Result<SockAddr> {
    // Safety: `accept` initialises the `SockAddr` for us.
    unsafe { SockAddr::init(|storage, len| syscall!(getsockname(fd, storage.cast(), len))) }
        .map(|(_, addr)| addr)
}

pub(crate) fn getpeername(fd: Socket) -> io::Result<SockAddr> {
    // Safety: `accept` initialises the `SockAddr` for us.
    unsafe { SockAddr::init(|storage, len| syscall!(getpeername(fd, storage.cast(), len))) }
        .map(|(_, addr)| addr)
}

pub(crate) fn try_clone(fd: Socket) -> io::Result<Socket> {
    syscall!(fcntl(fd, libc::F_DUPFD_CLOEXEC, 0))
}

pub(crate) fn set_nonblocking(fd: Socket, nonblocking: bool) -> io::Result<()> {
    if nonblocking {
        fcntl_add(fd, libc::F_GETFL, libc::F_SETFL, libc::O_NONBLOCK)
    } else {
        fcntl_remove(fd, libc::F_GETFL, libc::F_SETFL, libc::O_NONBLOCK)
    }
}

pub(crate) fn shutdown(fd: Socket, how: Shutdown) -> io::Result<()> {
    let how = match how {
        Shutdown::Write => libc::SHUT_WR,
        Shutdown::Read => libc::SHUT_RD,
        Shutdown::Both => libc::SHUT_RDWR,
    };
    syscall!(shutdown(fd, how)).map(|_| ())
}

pub(crate) fn recv(fd: Socket, buf: &mut [MaybeUninit<u8>], flags: c_int) -> io::Result<usize> {
    syscall!(recv(
        fd,
        buf.as_mut_ptr().cast(),
        min(buf.len(), MAX_BUF_LEN),
        flags,
    ))
    .map(|n| n as usize)
}

pub(crate) fn recv_from(
    fd: Socket,
    buf: &mut [MaybeUninit<u8>],
    flags: c_int,
) -> io::Result<(usize, SockAddr)> {
    // Safety: `recvfrom` initialises the `SockAddr` for us.
    unsafe {
        SockAddr::init(|addr, addrlen| {
            syscall!(recvfrom(
                fd,
                buf.as_mut_ptr().cast(),
                min(buf.len(), MAX_BUF_LEN),
                flags,
                addr.cast(),
                addrlen
            ))
            .map(|n| n as usize)
        })
    }
}

#[cfg(not(target_os = "redox"))]
pub(crate) fn recv_vectored(
    fd: Socket,
    bufs: &mut [crate::MaybeUninitSlice<'_>],
    flags: c_int,
) -> io::Result<(usize, RecvFlags)> {
    recvmsg(fd, ptr::null_mut(), bufs, flags).map(|(n, _, recv_flags)| (n, recv_flags))
}

#[cfg(not(target_os = "redox"))]
pub(crate) fn recv_from_vectored(
    fd: Socket,
    bufs: &mut [crate::MaybeUninitSlice<'_>],
    flags: c_int,
) -> io::Result<(usize, RecvFlags, SockAddr)> {
    // Safety: `recvmsg` initialises the address storage and we set the length
    // manually.
    unsafe {
        SockAddr::init(|storage, len| {
            recvmsg(fd, storage, bufs, flags).map(|(n, addrlen, recv_flags)| {
                // Set the correct address length.
                *len = addrlen;
                (n, recv_flags)
            })
        })
    }
    .map(|((n, recv_flags), addr)| (n, recv_flags, addr))
}

/// Returns the (bytes received, sending address len, `RecvFlags`).
#[cfg(not(target_os = "redox"))]
fn recvmsg(
    fd: Socket,
    msg_name: *mut sockaddr_storage,
    bufs: &mut [crate::MaybeUninitSlice<'_>],
    flags: c_int,
) -> io::Result<(usize, libc::socklen_t, RecvFlags)> {
    let msg_namelen = if msg_name.is_null() {
        0
    } else {
        size_of::<libc::sockaddr_storage>() as libc::socklen_t
    };
    // libc::msghdr contains unexported padding fields on Fuchsia.
    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_name = msg_name.cast();
    msg.msg_namelen = msg_namelen;
    msg.msg_iov = bufs.as_mut_ptr().cast();
    msg.msg_iovlen = min(bufs.len(), IovLen::MAX as usize) as IovLen;
    syscall!(recvmsg(fd, &mut msg, flags))
        .map(|n| (n as usize, msg.msg_namelen, RecvFlags(msg.msg_flags)))
}

pub(crate) fn send(fd: Socket, buf: &[u8], flags: c_int) -> io::Result<usize> {
    syscall!(send(
        fd,
        buf.as_ptr().cast(),
        min(buf.len(), MAX_BUF_LEN),
        flags,
    ))
    .map(|n| n as usize)
}

#[cfg(not(target_os = "redox"))]
pub(crate) fn send_vectored(fd: Socket, bufs: &[IoSlice<'_>], flags: c_int) -> io::Result<usize> {
    sendmsg(fd, ptr::null(), 0, bufs, flags)
}

pub(crate) fn send_to(fd: Socket, buf: &[u8], addr: &SockAddr, flags: c_int) -> io::Result<usize> {
    syscall!(sendto(
        fd,
        buf.as_ptr().cast(),
        min(buf.len(), MAX_BUF_LEN),
        flags,
        addr.as_ptr(),
        addr.len(),
    ))
    .map(|n| n as usize)
}

#[cfg(not(target_os = "redox"))]
pub(crate) fn send_to_vectored(
    fd: Socket,
    bufs: &[IoSlice<'_>],
    addr: &SockAddr,
    flags: c_int,
) -> io::Result<usize> {
    sendmsg(fd, addr.as_storage_ptr(), addr.len(), bufs, flags)
}

/// Returns the (bytes received, sending address len, `RecvFlags`).
#[cfg(not(target_os = "redox"))]
fn sendmsg(
    fd: Socket,
    msg_name: *const sockaddr_storage,
    msg_namelen: socklen_t,
    bufs: &[IoSlice<'_>],
    flags: c_int,
) -> io::Result<usize> {
    // libc::msghdr contains unexported padding fields on Fuchsia.
    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    // Safety: we're creating a `*mut` pointer from a reference, which is UB
    // once actually used. However the OS should not write to it in the
    // `sendmsg` system call.
    msg.msg_name = (msg_name as *mut sockaddr_storage).cast();
    msg.msg_namelen = msg_namelen;
    // Safety: Same as above about `*const` -> `*mut`.
    msg.msg_iov = bufs.as_ptr() as *mut _;
    msg.msg_iovlen = min(bufs.len(), IovLen::MAX as usize) as IovLen;
    syscall!(sendmsg(fd, &mut msg, flags)).map(|n| n as usize)
}

/// Wrapper around `getsockopt` to deal with platform specific timeouts.
pub(crate) fn timeout_opt(fd: Socket, opt: c_int, val: c_int) -> io::Result<Option<Duration>> {
    unsafe { getsockopt(fd, opt, val).map(from_timeval) }
}

fn from_timeval(duration: libc::timeval) -> Option<Duration> {
    if duration.tv_sec == 0 && duration.tv_usec == 0 {
        None
    } else {
        let sec = duration.tv_sec as u64;
        let nsec = (duration.tv_usec as u32) * 1000;
        Some(Duration::new(sec, nsec))
    }
}

/// Wrapper around `setsockopt` to deal with platform specific timeouts.
pub(crate) fn set_timeout_opt(
    fd: Socket,
    opt: c_int,
    val: c_int,
    duration: Option<Duration>,
) -> io::Result<()> {
    let duration = into_timeval(duration);
    unsafe { setsockopt(fd, opt, val, duration) }
}

fn into_timeval(duration: Option<Duration>) -> libc::timeval {
    match duration {
        Some(duration) => libc::timeval {
            tv_sec: min(duration.as_secs(), libc::time_t::max_value() as u64) as libc::time_t,
            tv_usec: (duration.subsec_nanos() / 1000) as libc::suseconds_t,
        },
        None => libc::timeval {
            tv_sec: 0,
            tv_usec: 0,
        },
    }
}

#[cfg(feature = "all")]
pub(crate) fn keepalive_time(fd: Socket) -> io::Result<Duration> {
    unsafe {
        getsockopt::<c_int>(fd, IPPROTO_TCP, KEEPALIVE_TIME)
            .map(|secs| Duration::from_secs(secs as u64))
    }
}

pub(crate) fn set_tcp_keepalive(fd: Socket, keepalive: &TcpKeepalive) -> io::Result<()> {
    if let Some(time) = keepalive.time {
        let secs = into_secs(time);
        unsafe { setsockopt(fd, libc::IPPROTO_TCP, KEEPALIVE_TIME, secs)? }
    }

    #[cfg(any(
        target_os = "android",
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "fuchsia",
        target_os = "illumos",
        target_os = "linux",
        target_os = "netbsd",
        target_vendor = "apple",
    ))]
    {
        if let Some(interval) = keepalive.interval {
            let secs = into_secs(interval);
            unsafe { setsockopt(fd, libc::IPPROTO_TCP, libc::TCP_KEEPINTVL, secs)? }
        }

        if let Some(retries) = keepalive.retries {
            unsafe { setsockopt(fd, libc::IPPROTO_TCP, libc::TCP_KEEPCNT, retries as c_int)? }
        }
    }

    Ok(())
}

fn into_secs(duration: Duration) -> c_int {
    min(duration.as_secs(), c_int::max_value() as u64) as c_int
}

/// Add `flag` to the current set flags of `F_GETFD`.
fn fcntl_add(fd: Socket, get_cmd: c_int, set_cmd: c_int, flag: c_int) -> io::Result<()> {
    let previous = syscall!(fcntl(fd, get_cmd))?;
    let new = previous | flag;
    if new != previous {
        syscall!(fcntl(fd, set_cmd, new)).map(|_| ())
    } else {
        // Flag was already set.
        Ok(())
    }
}

/// Remove `flag` to the current set flags of `F_GETFD`.
fn fcntl_remove(fd: Socket, get_cmd: c_int, set_cmd: c_int, flag: c_int) -> io::Result<()> {
    let previous = syscall!(fcntl(fd, get_cmd))?;
    let new = previous & !flag;
    if new != previous {
        syscall!(fcntl(fd, set_cmd, new)).map(|_| ())
    } else {
        // Flag was already set.
        Ok(())
    }
}

/// Caller must ensure `T` is the correct type for `opt` and `val`.
pub(crate) unsafe fn getsockopt<T>(fd: Socket, opt: c_int, val: c_int) -> io::Result<T> {
    let mut payload: MaybeUninit<T> = MaybeUninit::uninit();
    let mut len = size_of::<T>() as libc::socklen_t;
    syscall!(getsockopt(
        fd,
        opt,
        val,
        payload.as_mut_ptr().cast(),
        &mut len,
    ))
    .map(|_| {
        debug_assert_eq!(len as usize, size_of::<T>());
        // Safety: `getsockopt` initialised `payload` for us.
        payload.assume_init()
    })
}

/// Caller must ensure `T` is the correct type for `opt` and `val`.
pub(crate) unsafe fn setsockopt<T>(
    fd: Socket,
    opt: c_int,
    val: c_int,
    payload: T,
) -> io::Result<()> {
    let payload = &payload as *const T as *const c_void;
    syscall!(setsockopt(
        fd,
        opt,
        val,
        payload,
        mem::size_of::<T>() as libc::socklen_t,
    ))
    .map(|_| ())
}

pub(crate) fn close(fd: Socket) {
    unsafe {
        let _ = libc::close(fd);
    }
}

pub(crate) fn to_in_addr(addr: &Ipv4Addr) -> in_addr {
    // `s_addr` is stored as BE on all machines, and the array is in BE order.
    // So the native endian conversion method is used so that it's never
    // swapped.
    in_addr {
        s_addr: u32::from_ne_bytes(addr.octets()),
    }
}

pub(crate) fn from_in_addr(in_addr: in_addr) -> Ipv4Addr {
    Ipv4Addr::from(in_addr.s_addr.to_ne_bytes())
}

pub(crate) fn to_in6_addr(addr: &Ipv6Addr) -> in6_addr {
    let mut ret: in6_addr = unsafe { mem::zeroed() };
    ret.s6_addr = addr.octets();
    return ret;
}

pub(crate) fn from_in6_addr(addr: in6_addr) -> Ipv6Addr {
    Ipv6Addr::from(addr.s6_addr)
}

/// Unix only API.
impl crate::Socket {
    /// Accept a new incoming connection from this listener.
    ///
    /// This function directly corresponds to the `accept4(2)` function.
    ///
    /// This function will block the calling thread until a new connection is
    /// established. When established, the corresponding `Socket` and the remote
    /// peer's address will be returned.
    #[cfg(all(
        feature = "all",
        any(
            target_os = "android",
            target_os = "dragonfly",
            target_os = "freebsd",
            target_os = "fuchsia",
            target_os = "illumos",
            target_os = "linux",
            target_os = "netbsd",
            target_os = "openbsd"
        )
    ))]
    pub fn accept4(&self, flags: c_int) -> io::Result<(crate::Socket, SockAddr)> {
        self._accept4(flags)
    }

    #[cfg(any(
        target_os = "android",
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "fuchsia",
        target_os = "illumos",
        target_os = "linux",
        target_os = "netbsd",
        target_os = "openbsd"
    ))]
    pub(crate) fn _accept4(&self, flags: c_int) -> io::Result<(crate::Socket, SockAddr)> {
        // Safety: `accept4` initialises the `SockAddr` for us.
        unsafe {
            SockAddr::init(|storage, len| {
                syscall!(accept4(self.inner, storage.cast(), len, flags))
                    .map(|inner| crate::Socket { inner })
            })
        }
    }

    /// Sets `CLOEXEC` on the socket.
    ///
    /// # Notes
    ///
    /// On supported platforms you can use [`Type::cloexec`].
    #[cfg(feature = "all")]
    pub fn set_cloexec(&self, close_on_exec: bool) -> io::Result<()> {
        self._set_cloexec(close_on_exec)
    }

    pub(crate) fn _set_cloexec(&self, close_on_exec: bool) -> io::Result<()> {
        if close_on_exec {
            fcntl_add(self.inner, libc::F_GETFD, libc::F_SETFD, libc::FD_CLOEXEC)
        } else {
            fcntl_remove(self.inner, libc::F_GETFD, libc::F_SETFD, libc::FD_CLOEXEC)
        }
    }

    /// Sets `SO_NOSIGPIPE` on the socket.
    ///
    /// # Notes
    ///
    /// Only supported on Apple platforms (`target_vendor = "apple"`).
    #[cfg(all(feature = "all", target_vendor = "apple"))]
    pub fn set_nosigpipe(&self, nosigpipe: bool) -> io::Result<()> {
        self._set_nosigpipe(nosigpipe)
    }

    #[cfg(target_vendor = "apple")]
    pub(crate) fn _set_nosigpipe(&self, nosigpipe: bool) -> io::Result<()> {
        unsafe {
            setsockopt(
                self.inner,
                libc::SOL_SOCKET,
                libc::SO_NOSIGPIPE,
                nosigpipe as c_int,
            )
        }
    }

    /// Gets the value of the `TCP_MAXSEG` option on this socket.
    ///
    /// For more information about this option, see [`set_mss`].
    ///
    /// [`set_mss`]: crate::Socket::set_mss
    #[cfg(all(feature = "all", not(target_os = "redox")))]
    pub fn mss(&self) -> io::Result<u32> {
        unsafe {
            getsockopt::<c_int>(self.inner, libc::IPPROTO_TCP, libc::TCP_MAXSEG)
                .map(|mss| mss as u32)
        }
    }

    /// Sets the value of the `TCP_MAXSEG` option on this socket.
    ///
    /// The `TCP_MAXSEG` option denotes the TCP Maximum Segment Size and is only
    /// available on TCP sockets.
    #[cfg(all(feature = "all", not(target_os = "redox")))]
    pub fn set_mss(&self, mss: u32) -> io::Result<()> {
        unsafe {
            setsockopt(
                self.inner,
                libc::IPPROTO_TCP,
                libc::TCP_MAXSEG,
                mss as c_int,
            )
        }
    }

    /// Gets the value for the `SO_MARK` option on this socket.
    ///
    /// This value gets the socket mark field for each packet sent through
    /// this socket.
    ///
    /// This function is only available on Fuchsia and Linux. On Linux it
    /// requires the `CAP_NET_ADMIN` capability.
    #[cfg(all(feature = "all", any(target_os = "fuchsia", target_os = "linux")))]
    pub fn mark(&self) -> io::Result<u32> {
        unsafe {
            getsockopt::<c_int>(self.inner, libc::SOL_SOCKET, libc::SO_MARK).map(|mark| mark as u32)
        }
    }

    /// Sets the value for the `SO_MARK` option on this socket.
    ///
    /// This value sets the socket mark field for each packet sent through
    /// this socket. Changing the mark can be used for mark-based routing
    /// without netfilter or for packet filtering.
    ///
    /// This function is only available on Fuchsia and Linux. On Linux it
    /// requires the `CAP_NET_ADMIN` capability.
    #[cfg(all(feature = "all", any(target_os = "fuchsia", target_os = "linux")))]
    pub fn set_mark(&self, mark: u32) -> io::Result<()> {
        unsafe { setsockopt::<c_int>(self.inner, libc::SOL_SOCKET, libc::SO_MARK, mark as c_int) }
    }

    /// Gets the value for the `SO_BINDTODEVICE` option on this socket.
    ///
    /// This value gets the socket binded device's interface name.
    ///
    /// This function is only available on Fuchsia and Linux.
    #[cfg(all(feature = "all", any(target_os = "fuchsia", target_os = "linux")))]
    pub fn device(&self) -> io::Result<Option<CString>> {
        // TODO: replace with `MaybeUninit::uninit_array` once stable.
        let mut buf: [MaybeUninit<u8>; libc::IFNAMSIZ] =
            unsafe { MaybeUninit::<[MaybeUninit<u8>; libc::IFNAMSIZ]>::uninit().assume_init() };
        let mut len = buf.len() as libc::socklen_t;
        unsafe {
            syscall!(getsockopt(
                self.inner,
                libc::SOL_SOCKET,
                libc::SO_BINDTODEVICE,
                buf.as_mut_ptr().cast(),
                &mut len,
            ))?;
        }
        if len == 0 {
            Ok(None)
        } else {
            // Allocate a buffer for `CString` with the length including the
            // null terminator.
            let len = len as usize;
            let mut name = Vec::with_capacity(len);

            // TODO: use `MaybeUninit::slice_assume_init_ref` once stable.
            // Safety: `len` bytes are writen by the OS, this includes a null
            // terminator. However we don't copy the null terminator because
            // `CString::from_vec_unchecked` adds its own null terminator.
            let buf = unsafe { slice::from_raw_parts(buf.as_ptr().cast(), len - 1) };
            name.extend_from_slice(buf);

            // Safety: the OS initialised the string for us, which shouldn't
            // include any null bytes.
            Ok(Some(unsafe { CString::from_vec_unchecked(name) }))
        }
    }

    /// Sets the value for the `SO_BINDTODEVICE` option on this socket.
    ///
    /// If a socket is bound to an interface, only packets received from that
    /// particular interface are processed by the socket. Note that this only
    /// works for some socket types, particularly `AF_INET` sockets.
    ///
    /// If `interface` is `None` or an empty string it removes the binding.
    ///
    /// This function is only available on Fuchsia and Linux.
    #[cfg(all(feature = "all", any(target_os = "fuchsia", target_os = "linux")))]
    pub fn bind_device(&self, interface: Option<&CStr>) -> io::Result<()> {
        let (value, len) = if let Some(interface) = interface {
            (interface.as_ptr(), interface.to_bytes_with_nul().len())
        } else {
            (ptr::null(), 0)
        };
        syscall!(setsockopt(
            self.inner,
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            value.cast(),
            len as libc::socklen_t,
        ))
        .map(|_| ())
    }

    /// Get the value of the `SO_REUSEPORT` option on this socket.
    ///
    /// For more information about this option, see [`set_reuse_port`].
    ///
    /// This function is only available on Unix.
    ///
    /// [`set_reuse_port`]: crate::Socket::set_reuse_port
    #[cfg(all(
        feature = "all",
        not(any(target_os = "solaris", target_os = "illumos"))
    ))]
    pub fn reuse_port(&self) -> io::Result<bool> {
        unsafe {
            getsockopt::<c_int>(self.inner, libc::SOL_SOCKET, libc::SO_REUSEPORT)
                .map(|reuse| reuse != 0)
        }
    }

    /// Set value for the `SO_REUSEPORT` option on this socket.
    ///
    /// This indicates that further calls to `bind` may allow reuse of local
    /// addresses. For IPv4 sockets this means that a socket may bind even when
    /// there's a socket already listening on this port.
    ///
    /// This function is only available on Unix.
    #[cfg(all(
        feature = "all",
        not(any(target_os = "solaris", target_os = "illumos"))
    ))]
    pub fn set_reuse_port(&self, reuse: bool) -> io::Result<()> {
        unsafe {
            setsockopt(
                self.inner,
                libc::SOL_SOCKET,
                libc::SO_REUSEPORT,
                reuse as c_int,
            )
        }
    }

    /// Get the value of the `IP_FREEBIND` option on this socket.
    ///
    /// For more information about this option, see [`set_freebind`].
    ///
    /// This function is only available on Fuchsia and Linux.
    ///
    /// [`set_freebind`]: Socket::set_freebind
    #[cfg(all(feature = "all", any(target_os = "fuchsia", target_os = "linux")))]
    pub fn freebind(&self) -> io::Result<bool> {
        unsafe {
            getsockopt::<c_int>(self.inner, libc::SOL_SOCKET, libc::IP_FREEBIND)
                .map(|reuse| reuse != 0)
        }
    }

    /// Set value for the `IP_FREEBIND` option on this socket.
    ///
    /// If enabled, this boolean option allows binding to an IP address that is
    /// nonlocal or does not (yet) exist.  This permits listening on a socket,
    /// without requiring the underlying network interface or the specified
    /// dynamic IP address to be up at the time that the application is trying
    /// to bind to it.
    ///
    /// This function is only available on Fuchsia and Linux.
    #[cfg(all(feature = "all", any(target_os = "fuchsia", target_os = "linux")))]
    pub fn set_freebind(&self, reuse: bool) -> io::Result<()> {
        unsafe {
            setsockopt(
                self.inner,
                libc::SOL_SOCKET,
                libc::IP_FREEBIND,
                reuse as c_int,
            )
        }
    }
}

impl AsRawFd for crate::Socket {
    fn as_raw_fd(&self) -> c_int {
        self.inner
    }
}

impl IntoRawFd for crate::Socket {
    fn into_raw_fd(self) -> c_int {
        let fd = self.inner;
        mem::forget(self);
        fd
    }
}

impl FromRawFd for crate::Socket {
    unsafe fn from_raw_fd(fd: c_int) -> crate::Socket {
        crate::Socket { inner: fd }
    }
}

#[cfg(feature = "all")]
from!(UnixStream, crate::Socket);
#[cfg(feature = "all")]
from!(UnixListener, crate::Socket);
#[cfg(feature = "all")]
from!(UnixDatagram, crate::Socket);
#[cfg(feature = "all")]
from!(crate::Socket, UnixStream);
#[cfg(feature = "all")]
from!(crate::Socket, UnixListener);
#[cfg(feature = "all")]
from!(crate::Socket, UnixDatagram);

#[test]
fn in_addr_convertion() {
    let ip = Ipv4Addr::new(127, 0, 0, 1);
    let raw = to_in_addr(&ip);
    assert_eq!(raw.s_addr, 127 << 0 | 1 << 24);
    assert_eq!(from_in_addr(raw), ip);

    let ip = Ipv4Addr::new(127, 34, 4, 12);
    let raw = to_in_addr(&ip);
    assert_eq!(raw.s_addr, 127 << 0 | 34 << 8 | 4 << 16 | 12 << 24);
    assert_eq!(from_in_addr(raw), ip);
}

#[test]
fn in6_addr_convertion() {
    let ip = Ipv6Addr::new(0x2000, 1, 2, 3, 4, 5, 6, 7);
    let raw = to_in6_addr(&ip);
    let want = [32, 0, 0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7];
    assert_eq!(raw.s6_addr, want);
    assert_eq!(from_in6_addr(raw), ip);
}
