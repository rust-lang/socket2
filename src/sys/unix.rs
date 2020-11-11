// Copyright 2015 The Rust Project Developers.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::cmp::min;
#[cfg(not(target_os = "redox"))]
use std::io::{IoSlice, IoSliceMut};
use std::mem::{self, size_of, size_of_val, MaybeUninit};
use std::net::Shutdown;
use std::net::{Ipv4Addr, Ipv6Addr};
#[cfg(feature = "all")]
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd};
#[cfg(feature = "all")]
use std::os::unix::net::{UnixDatagram, UnixListener, UnixStream};
#[cfg(feature = "all")]
use std::path::Path;
use std::time::Duration;
use std::{fmt, io, ptr};

#[cfg(not(target_vendor = "apple"))]
use libc::ssize_t;
use libc::{c_void, in6_addr, in_addr};

#[cfg(not(target_os = "redox"))]
use crate::RecvFlags;
use crate::{Domain, Type};

pub use libc::c_int;

// Used in `Domain`.
pub(crate) use libc::{AF_INET, AF_INET6};
// Used in `Type`.
pub(crate) use libc::{SOCK_DGRAM, SOCK_STREAM};
#[cfg(all(feature = "all", not(target_os = "redox")))]
pub(crate) use libc::{SOCK_RAW, SOCK_SEQPACKET};
// Used in `Protocol`.
pub(crate) use libc::{IPPROTO_ICMP, IPPROTO_ICMPV6, IPPROTO_TCP, IPPROTO_UDP};
// Used in `SockAddr`.
pub(crate) use libc::{
    sa_family_t, sockaddr, sockaddr_in, sockaddr_in6, sockaddr_storage, socklen_t,
};
// Used in `RecvFlags`.
#[cfg(not(target_os = "redox"))]
pub(crate) use libc::MSG_TRUNC;
// Used in `Socket`.
#[cfg(all(unix, feature = "all", not(target_os = "redox")))]
pub(crate) use libc::MSG_OOB;
pub(crate) use libc::MSG_PEEK;

cfg_if::cfg_if! {
    if #[cfg(any(target_os = "dragonfly", target_os = "freebsd",
                 target_os = "ios", target_os = "macos",
                 target_os = "openbsd", target_os = "netbsd",
                 target_os = "solaris", target_os = "illumos",
                 target_os = "haiku"))] {
        use libc::IPV6_JOIN_GROUP as IPV6_ADD_MEMBERSHIP;
        use libc::IPV6_LEAVE_GROUP as IPV6_DROP_MEMBERSHIP;
    } else {
        use libc::IPV6_ADD_MEMBERSHIP;
        use libc::IPV6_DROP_MEMBERSHIP;
    }
}

cfg_if::cfg_if! {
    if #[cfg(any(target_os = "macos", target_os = "ios"))] {
        use libc::TCP_KEEPALIVE as KEEPALIVE_OPTION;
    } else if #[cfg(any(target_os = "openbsd", target_os = "netbsd", target_os = "haiku"))] {
        use libc::SO_KEEPALIVE as KEEPALIVE_OPTION;
    } else {
        use libc::TCP_KEEPIDLE as KEEPALIVE_OPTION;
    }
}

use crate::SockAddr;

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
    target_os = "dragonfly",
    target_os = "freebsd",
    target_os = "ios",
    all(target_os = "linux", target_env = "musl"),
    target_os = "macos",
    target_os = "netbsd",
    target_os = "openbsd",
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
    /// This function is only available on Linux.
    #[cfg(all(feature = "all", target_os = "linux"))]
    pub const PACKET: Domain = Domain(libc::AF_PACKET);
}

impl_debug!(
    Domain,
    libc::AF_INET,
    libc::AF_INET6,
    libc::AF_UNIX,
    #[cfg(target_os = "linux")]
    libc::AF_PACKET,
    #[cfg(not(target_os = "redox"))]
    libc::AF_UNSPEC, // = 0.
);

/// Unix only API.
impl Type {
    /// Set `SOCK_NONBLOCK` on the `Type`.
    ///
    /// # Notes
    ///
    /// This function is only available on Android, DragonFlyBSD, FreeBSD,
    /// Linux, NetBSD and OpenBSD.
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
    pub const fn nonblocking(self) -> Type {
        Type(self.0 | libc::SOCK_NONBLOCK)
    }

    /// Set `SOCK_CLOEXEC` on the `Type`.
    ///
    /// # Notes
    ///
    /// This function is only available on Android, DragonFlyBSD, FreeBSD,
    /// Linux, NetBSD and OpenBSD.
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
    pub const fn cloexec(self) -> Type {
        self._cloexec()
    }

    #[cfg(any(
        target_os = "android",
        target_os = "dragonfly",
        target_os = "freebsd",
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
    #[cfg(not(target_os = "redox"))]
    libc::SOCK_SEQPACKET,
    /* TODO: add these optional bit OR-ed flags:
    #[cfg(any(
        target_os = "android",
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "linux",
        target_os = "netbsd",
        target_os = "openbsd"
    ))]
    libc::SOCK_NONBLOCK,
    #[cfg(any(
        target_os = "android",
        target_os = "dragonfly",
        target_os = "freebsd",
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

// TODO: rename to `Socket` once the struct `Socket` is no longer used.
pub(crate) type SysSocket = c_int;

pub(crate) fn socket(family: c_int, ty: c_int, protocol: c_int) -> io::Result<SysSocket> {
    syscall!(socket(family, ty, protocol))
}

#[cfg(feature = "all")]
pub(crate) fn socketpair(family: c_int, ty: c_int, protocol: c_int) -> io::Result<[SysSocket; 2]> {
    let mut fds = [0, 0];
    syscall!(socketpair(family, ty, protocol, fds.as_mut_ptr())).map(|_| fds)
}

pub(crate) fn bind(fd: SysSocket, addr: &SockAddr) -> io::Result<()> {
    syscall!(bind(fd, addr.as_ptr(), addr.len() as _)).map(|_| ())
}

pub(crate) fn connect(fd: SysSocket, addr: &SockAddr) -> io::Result<()> {
    syscall!(connect(fd, addr.as_ptr(), addr.len())).map(|_| ())
}

pub(crate) fn listen(fd: SysSocket, backlog: i32) -> io::Result<()> {
    syscall!(listen(fd, backlog)).map(|_| ())
}

pub(crate) fn accept(fd: SysSocket) -> io::Result<(SysSocket, SockAddr)> {
    // Safety: zeroed `sockaddr_storage` is valid.
    let mut storage: libc::sockaddr_storage = unsafe { mem::zeroed() };
    let mut len = size_of_val(&storage) as socklen_t;
    syscall!(accept(fd, &mut storage as *mut _ as *mut _, &mut len)).map(|fd| {
        let addr = unsafe { SockAddr::from_raw_parts(&storage as *const _ as *const _, len) };
        (fd, addr)
    })
}

pub(crate) fn getsockname(fd: SysSocket) -> io::Result<SockAddr> {
    let mut storage: libc::sockaddr_storage = unsafe { mem::zeroed() };
    let mut len = size_of_val(&storage) as libc::socklen_t;
    syscall!(getsockname(fd, &mut storage as *mut _ as *mut _, &mut len,))
        .map(|_| unsafe { SockAddr::from_raw_parts(&storage as *const _ as *const _, len) })
}

pub(crate) fn getpeername(fd: SysSocket) -> io::Result<SockAddr> {
    let mut storage: libc::sockaddr_storage = unsafe { mem::zeroed() };
    let mut len = size_of_val(&storage) as libc::socklen_t;
    syscall!(getpeername(fd, &mut storage as *mut _ as *mut _, &mut len,))
        .map(|_| unsafe { SockAddr::from_raw_parts(&storage as *const _ as *const _, len) })
}

pub(crate) fn try_clone(fd: SysSocket) -> io::Result<SysSocket> {
    syscall!(fcntl(fd, libc::F_DUPFD_CLOEXEC, 0))
}

pub(crate) fn take_error(fd: SysSocket) -> io::Result<Option<io::Error>> {
    match unsafe { getsockopt::<c_int>(fd, libc::SOL_SOCKET, libc::SO_ERROR) } {
        Ok(0) => Ok(None),
        Ok(errno) => Ok(Some(io::Error::from_raw_os_error(errno))),
        Err(err) => Err(err),
    }
}

pub(crate) fn set_nonblocking(fd: SysSocket, nonblocking: bool) -> io::Result<()> {
    if nonblocking {
        fcntl_add(fd, libc::F_GETFL, libc::F_SETFL, libc::O_NONBLOCK)
    } else {
        fcntl_remove(fd, libc::F_GETFL, libc::F_SETFL, libc::O_NONBLOCK)
    }
}

pub(crate) fn shutdown(fd: SysSocket, how: Shutdown) -> io::Result<()> {
    let how = match how {
        Shutdown::Write => libc::SHUT_WR,
        Shutdown::Read => libc::SHUT_RD,
        Shutdown::Both => libc::SHUT_RDWR,
    };
    syscall!(shutdown(fd, how)).map(|_| ())
}

pub(crate) fn recv(fd: SysSocket, buf: &mut [u8], flags: c_int) -> io::Result<usize> {
    syscall!(recv(
        fd,
        buf.as_mut_ptr().cast(),
        min(buf.len(), MAX_BUF_LEN),
        flags,
    ))
    .map(|n| n as usize)
}

pub(crate) fn recv_from(
    fd: SysSocket,
    buf: &mut [u8],
    flags: c_int,
) -> io::Result<(usize, SockAddr)> {
    let mut storage: MaybeUninit<libc::sockaddr_storage> = MaybeUninit::zeroed();
    let mut addrlen = size_of_val(&storage) as socklen_t;
    syscall!(recvfrom(
        fd,
        buf.as_mut_ptr().cast(),
        min(buf.len(), MAX_BUF_LEN),
        flags,
        storage.as_mut_ptr().cast(),
        &mut addrlen,
    ))
    .map(|n| {
        // Safety: `recvfrom` wrote an address of `addrlen` bytes for us. The
        // remaining bytes are initialised to zero (which is valid for
        // `sockaddr_storage`).
        let addr = SockAddr::from_raw(unsafe { storage.assume_init() }, addrlen);
        (n as usize, addr)
    })
}

#[cfg(not(target_os = "redox"))]
pub(crate) fn recv_vectored(
    fd: SysSocket,
    bufs: &mut [IoSliceMut<'_>],
    flags: c_int,
) -> io::Result<(usize, RecvFlags)> {
    recvmsg(fd, ptr::null_mut(), bufs, flags).map(|(n, _, recv_flags)| (n, recv_flags))
}

#[cfg(not(target_os = "redox"))]
pub(crate) fn recv_from_vectored(
    fd: SysSocket,
    bufs: &mut [IoSliceMut<'_>],
    flags: c_int,
) -> io::Result<(usize, RecvFlags, SockAddr)> {
    let mut storage: MaybeUninit<libc::sockaddr_storage> = MaybeUninit::zeroed();
    recvmsg(fd, storage.as_mut_ptr(), bufs, flags).map(|(n, addrlen, recv_flags)| {
        // Safety: `recvmsg` wrote an address of `addrlen` bytes for us. The
        // remaining bytes are initialised to zero (which is valid for
        // `sockaddr_storage`).
        let addr = SockAddr::from_raw(unsafe { storage.assume_init() }, addrlen);
        (n as usize, recv_flags, addr)
    })
}

/// Returns the (bytes received, sending address len, `RecvFlags`).
fn recvmsg(
    fd: SysSocket,
    msg_name: *mut sockaddr_storage,
    bufs: &mut [IoSliceMut<'_>],
    flags: c_int,
) -> io::Result<(usize, libc::socklen_t, RecvFlags)> {
    let msg_namelen = if msg_name.is_null() {
        0
    } else {
        size_of::<libc::sockaddr_storage>() as libc::socklen_t
    };
    let mut msg = libc::msghdr {
        msg_name: msg_name.cast(),
        msg_namelen,
        msg_iov: bufs.as_mut_ptr().cast(),
        msg_iovlen: min(bufs.len(), IovLen::MAX as usize) as IovLen,
        msg_control: ptr::null_mut(),
        msg_controllen: 0,
        msg_flags: 0,
    };
    syscall!(recvmsg(fd, &mut msg, flags))
        .map(|n| (n as usize, msg.msg_namelen, RecvFlags(msg.msg_flags)))
}

pub(crate) fn send(fd: SysSocket, buf: &[u8], flags: c_int) -> io::Result<usize> {
    syscall!(send(
        fd,
        buf.as_ptr().cast(),
        min(buf.len(), MAX_BUF_LEN),
        flags,
    ))
    .map(|n| n as usize)
}

#[cfg(not(target_os = "redox"))]
pub(crate) fn send_vectored(
    fd: SysSocket,
    bufs: &[IoSlice<'_>],
    flags: c_int,
) -> io::Result<usize> {
    sendmsg(fd, ptr::null(), 0, bufs, flags)
}

pub(crate) fn send_to(
    fd: SysSocket,
    buf: &[u8],
    addr: &SockAddr,
    flags: c_int,
) -> io::Result<usize> {
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
    fd: SysSocket,
    bufs: &[IoSlice<'_>],
    addr: &SockAddr,
    flags: c_int,
) -> io::Result<usize> {
    sendmsg(fd, addr.as_storage_ptr(), addr.len(), bufs, flags)
}

/// Returns the (bytes received, sending address len, `RecvFlags`).
fn sendmsg(
    fd: SysSocket,
    msg_name: *const sockaddr_storage,
    msg_namelen: socklen_t,
    bufs: &[IoSlice<'_>],
    flags: c_int,
) -> io::Result<usize> {
    let mut msg = libc::msghdr {
        // Safety: we're creating a `*mut` pointer from a reference, which is UB
        // once actually used. However the OS should not write to it in the
        // `sendmsg` system call.
        msg_name: (msg_name as *mut sockaddr_storage).cast(),
        msg_namelen,
        // Safety: Same as above about `*const` -> `*mut`.
        msg_iov: bufs.as_ptr() as *mut _,
        msg_iovlen: min(bufs.len(), IovLen::MAX as usize) as IovLen,
        msg_control: ptr::null_mut(),
        msg_controllen: 0,
        msg_flags: 0,
    };
    syscall!(sendmsg(fd, &mut msg, flags)).map(|n| n as usize)
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
        target_os = "illumos",
        target_os = "linux",
        target_os = "netbsd",
        target_os = "openbsd"
    ))]
    pub(crate) fn _accept4(&self, flags: c_int) -> io::Result<(crate::Socket, SockAddr)> {
        // Safety: zeroed `sockaddr_storage` is valid.
        let mut storage: libc::sockaddr_storage = unsafe { mem::zeroed() };
        let mut len = mem::size_of_val(&storage) as socklen_t;
        syscall!(accept4(
            self.inner,
            &mut storage as *mut _ as *mut _,
            &mut len,
            flags
        ))
        .map(|inner| {
            let addr = unsafe { SockAddr::from_raw_parts(&storage as *const _ as *const _, len) };
            (crate::Socket { inner }, addr)
        })
    }

    /// Sets `CLOEXEC` on the socket.
    ///
    /// # Notes
    ///
    /// On supported platforms you can use [`Protocol::cloexec`].
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
}

/// Add `flag` to the current set flags of `F_GETFD`.
fn fcntl_add(fd: SysSocket, get_cmd: c_int, set_cmd: c_int, flag: c_int) -> io::Result<()> {
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
fn fcntl_remove(fd: SysSocket, get_cmd: c_int, set_cmd: c_int, flag: c_int) -> io::Result<()> {
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
unsafe fn getsockopt<T>(fd: SysSocket, opt: c_int, val: c_int) -> io::Result<T> {
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
#[cfg(target_vendor = "apple")]
unsafe fn setsockopt<T>(fd: SysSocket, opt: c_int, val: c_int, payload: T) -> io::Result<()> {
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

#[repr(transparent)] // Required during rewriting.
pub struct Socket {
    fd: SysSocket,
}

impl Socket {
    pub fn ttl(&self) -> io::Result<u32> {
        unsafe {
            let raw: c_int = self.getsockopt(libc::IPPROTO_IP, libc::IP_TTL)?;
            Ok(raw as u32)
        }
    }

    pub fn set_ttl(&self, ttl: u32) -> io::Result<()> {
        unsafe { self.setsockopt(libc::IPPROTO_IP, libc::IP_TTL, ttl as c_int) }
    }

    #[cfg(target_os = "linux")]
    pub fn set_mark(&self, mark: u32) -> io::Result<()> {
        unsafe { self.setsockopt(libc::SOL_SOCKET, libc::SO_MARK, mark as c_int) }
    }

    pub fn unicast_hops_v6(&self) -> io::Result<u32> {
        unsafe {
            let raw: c_int = self.getsockopt(libc::IPPROTO_IPV6, libc::IPV6_UNICAST_HOPS)?;
            Ok(raw as u32)
        }
    }

    pub fn set_unicast_hops_v6(&self, hops: u32) -> io::Result<()> {
        unsafe {
            self.setsockopt(
                libc::IPPROTO_IPV6 as c_int,
                libc::IPV6_UNICAST_HOPS,
                hops as c_int,
            )
        }
    }

    pub fn only_v6(&self) -> io::Result<bool> {
        unsafe {
            let raw: c_int = self.getsockopt(libc::IPPROTO_IPV6, libc::IPV6_V6ONLY)?;
            Ok(raw != 0)
        }
    }

    pub fn set_only_v6(&self, only_v6: bool) -> io::Result<()> {
        unsafe { self.setsockopt(libc::IPPROTO_IPV6, libc::IPV6_V6ONLY, only_v6 as c_int) }
    }

    pub fn read_timeout(&self) -> io::Result<Option<Duration>> {
        unsafe {
            Ok(timeval2dur(
                self.getsockopt(libc::SOL_SOCKET, libc::SO_RCVTIMEO)?,
            ))
        }
    }

    pub fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        unsafe { self.setsockopt(libc::SOL_SOCKET, libc::SO_RCVTIMEO, dur2timeval(dur)?) }
    }

    pub fn write_timeout(&self) -> io::Result<Option<Duration>> {
        unsafe {
            Ok(timeval2dur(
                self.getsockopt(libc::SOL_SOCKET, libc::SO_SNDTIMEO)?,
            ))
        }
    }

    pub fn set_write_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        unsafe { self.setsockopt(libc::SOL_SOCKET, libc::SO_SNDTIMEO, dur2timeval(dur)?) }
    }

    pub fn nodelay(&self) -> io::Result<bool> {
        unsafe {
            let raw: c_int = self.getsockopt(libc::IPPROTO_TCP, libc::TCP_NODELAY)?;
            Ok(raw != 0)
        }
    }

    pub fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        unsafe { self.setsockopt(libc::IPPROTO_TCP, libc::TCP_NODELAY, nodelay as c_int) }
    }

    pub fn broadcast(&self) -> io::Result<bool> {
        unsafe {
            let raw: c_int = self.getsockopt(libc::SOL_SOCKET, libc::SO_BROADCAST)?;
            Ok(raw != 0)
        }
    }

    pub fn set_broadcast(&self, broadcast: bool) -> io::Result<()> {
        unsafe { self.setsockopt(libc::SOL_SOCKET, libc::SO_BROADCAST, broadcast as c_int) }
    }

    pub fn multicast_loop_v4(&self) -> io::Result<bool> {
        unsafe {
            let raw: c_int = self.getsockopt(libc::IPPROTO_IP, libc::IP_MULTICAST_LOOP)?;
            Ok(raw != 0)
        }
    }

    pub fn set_multicast_loop_v4(&self, multicast_loop_v4: bool) -> io::Result<()> {
        unsafe {
            self.setsockopt(
                libc::IPPROTO_IP,
                libc::IP_MULTICAST_LOOP,
                multicast_loop_v4 as c_int,
            )
        }
    }

    pub fn multicast_ttl_v4(&self) -> io::Result<u32> {
        unsafe {
            let raw: c_int = self.getsockopt(libc::IPPROTO_IP, libc::IP_MULTICAST_TTL)?;
            Ok(raw as u32)
        }
    }

    pub fn set_multicast_ttl_v4(&self, multicast_ttl_v4: u32) -> io::Result<()> {
        unsafe {
            self.setsockopt(
                libc::IPPROTO_IP,
                libc::IP_MULTICAST_TTL,
                multicast_ttl_v4 as c_int,
            )
        }
    }

    pub fn multicast_hops_v6(&self) -> io::Result<u32> {
        unsafe {
            let raw: c_int = self.getsockopt(libc::IPPROTO_IPV6, libc::IPV6_MULTICAST_HOPS)?;
            Ok(raw as u32)
        }
    }

    pub fn set_multicast_hops_v6(&self, hops: u32) -> io::Result<()> {
        unsafe { self.setsockopt(libc::IPPROTO_IPV6, libc::IPV6_MULTICAST_HOPS, hops as c_int) }
    }

    pub fn multicast_if_v4(&self) -> io::Result<Ipv4Addr> {
        unsafe {
            let imr_interface: libc::in_addr =
                self.getsockopt(libc::IPPROTO_IP, libc::IP_MULTICAST_IF)?;
            Ok(from_in_addr(imr_interface))
        }
    }

    pub fn set_multicast_if_v4(&self, interface: &Ipv4Addr) -> io::Result<()> {
        let imr_interface = to_in_addr(interface);

        unsafe { self.setsockopt(libc::IPPROTO_IP, libc::IP_MULTICAST_IF, imr_interface) }
    }

    pub fn multicast_if_v6(&self) -> io::Result<u32> {
        unsafe {
            let raw: c_int = self.getsockopt(libc::IPPROTO_IPV6, libc::IPV6_MULTICAST_IF)?;
            Ok(raw as u32)
        }
    }

    pub fn set_multicast_if_v6(&self, interface: u32) -> io::Result<()> {
        unsafe {
            self.setsockopt(
                libc::IPPROTO_IPV6,
                libc::IPV6_MULTICAST_IF,
                interface as c_int,
            )
        }
    }

    pub fn multicast_loop_v6(&self) -> io::Result<bool> {
        unsafe {
            let raw: c_int = self.getsockopt(libc::IPPROTO_IPV6, libc::IPV6_MULTICAST_LOOP)?;
            Ok(raw != 0)
        }
    }

    pub fn set_multicast_loop_v6(&self, multicast_loop_v6: bool) -> io::Result<()> {
        unsafe {
            self.setsockopt(
                libc::IPPROTO_IPV6,
                libc::IPV6_MULTICAST_LOOP,
                multicast_loop_v6 as c_int,
            )
        }
    }

    pub fn join_multicast_v4(&self, multiaddr: &Ipv4Addr, interface: &Ipv4Addr) -> io::Result<()> {
        let mreq = libc::ip_mreq {
            imr_multiaddr: to_in_addr(multiaddr),
            imr_interface: to_in_addr(interface),
        };
        unsafe { self.setsockopt(libc::IPPROTO_IP, libc::IP_ADD_MEMBERSHIP, mreq) }
    }

    pub fn join_multicast_v6(&self, multiaddr: &Ipv6Addr, interface: u32) -> io::Result<()> {
        let multiaddr = to_in6_addr(multiaddr);
        let mreq = libc::ipv6_mreq {
            ipv6mr_multiaddr: multiaddr,
            ipv6mr_interface: to_ipv6mr_interface(interface),
        };
        unsafe { self.setsockopt(libc::IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, mreq) }
    }

    pub fn leave_multicast_v4(&self, multiaddr: &Ipv4Addr, interface: &Ipv4Addr) -> io::Result<()> {
        let mreq = libc::ip_mreq {
            imr_multiaddr: to_in_addr(multiaddr),
            imr_interface: to_in_addr(interface),
        };
        unsafe { self.setsockopt(libc::IPPROTO_IP, libc::IP_DROP_MEMBERSHIP, mreq) }
    }

    pub fn leave_multicast_v6(&self, multiaddr: &Ipv6Addr, interface: u32) -> io::Result<()> {
        let multiaddr = to_in6_addr(multiaddr);
        let mreq = libc::ipv6_mreq {
            ipv6mr_multiaddr: multiaddr,
            ipv6mr_interface: to_ipv6mr_interface(interface),
        };
        unsafe { self.setsockopt(libc::IPPROTO_IPV6, IPV6_DROP_MEMBERSHIP, mreq) }
    }

    pub fn linger(&self) -> io::Result<Option<Duration>> {
        unsafe {
            Ok(linger2dur(
                self.getsockopt(libc::SOL_SOCKET, libc::SO_LINGER)?,
            ))
        }
    }

    pub fn set_linger(&self, dur: Option<Duration>) -> io::Result<()> {
        unsafe { self.setsockopt(libc::SOL_SOCKET, libc::SO_LINGER, dur2linger(dur)) }
    }

    pub fn set_reuse_address(&self, reuse: bool) -> io::Result<()> {
        unsafe { self.setsockopt(libc::SOL_SOCKET, libc::SO_REUSEADDR, reuse as c_int) }
    }

    pub fn reuse_address(&self) -> io::Result<bool> {
        unsafe {
            let raw: c_int = self.getsockopt(libc::SOL_SOCKET, libc::SO_REUSEADDR)?;
            Ok(raw != 0)
        }
    }

    pub fn recv_buffer_size(&self) -> io::Result<usize> {
        unsafe {
            let raw: c_int = self.getsockopt(libc::SOL_SOCKET, libc::SO_RCVBUF)?;
            Ok(raw as usize)
        }
    }

    pub fn set_recv_buffer_size(&self, size: usize) -> io::Result<()> {
        unsafe {
            // TODO: casting usize to a c_int should be a checked cast
            self.setsockopt(libc::SOL_SOCKET, libc::SO_RCVBUF, size as c_int)
        }
    }

    pub fn send_buffer_size(&self) -> io::Result<usize> {
        unsafe {
            let raw: c_int = self.getsockopt(libc::SOL_SOCKET, libc::SO_SNDBUF)?;
            Ok(raw as usize)
        }
    }

    pub fn set_send_buffer_size(&self, size: usize) -> io::Result<()> {
        unsafe {
            // TODO: casting usize to a c_int should be a checked cast
            self.setsockopt(libc::SOL_SOCKET, libc::SO_SNDBUF, size as c_int)
        }
    }

    pub fn keepalive(&self) -> io::Result<Option<Duration>> {
        unsafe {
            let raw: c_int = self.getsockopt(libc::SOL_SOCKET, libc::SO_KEEPALIVE)?;
            if raw == 0 {
                return Ok(None);
            }
            let secs: c_int = self.getsockopt(libc::IPPROTO_TCP, KEEPALIVE_OPTION)?;
            Ok(Some(Duration::new(secs as u64, 0)))
        }
    }

    pub fn set_keepalive(&self, keepalive: Option<Duration>) -> io::Result<()> {
        unsafe {
            self.setsockopt(
                libc::SOL_SOCKET,
                libc::SO_KEEPALIVE,
                keepalive.is_some() as c_int,
            )?;
            if let Some(dur) = keepalive {
                // TODO: checked cast here
                self.setsockopt(libc::IPPROTO_TCP, KEEPALIVE_OPTION, dur.as_secs() as c_int)?;
            }
            Ok(())
        }
    }

    #[cfg(all(
        feature = "all",
        not(any(target_os = "solaris", target_os = "illumos"))
    ))]
    pub fn reuse_port(&self) -> io::Result<bool> {
        unsafe {
            let raw: c_int = self.getsockopt(libc::SOL_SOCKET, libc::SO_REUSEPORT)?;
            Ok(raw != 0)
        }
    }

    #[cfg(all(
        feature = "all",
        not(any(target_os = "solaris", target_os = "illumos"))
    ))]
    pub fn set_reuse_port(&self, reuse: bool) -> io::Result<()> {
        unsafe { self.setsockopt(libc::SOL_SOCKET, libc::SO_REUSEPORT, reuse as c_int) }
    }

    #[cfg(all(feature = "all", not(target_os = "redox")))]
    pub fn out_of_band_inline(&self) -> io::Result<bool> {
        unsafe {
            let raw: c_int = self.getsockopt(libc::SOL_SOCKET, libc::SO_OOBINLINE)?;
            Ok(raw != 0)
        }
    }

    #[cfg(all(feature = "all", not(target_os = "redox")))]
    pub fn set_out_of_band_inline(&self, oob_inline: bool) -> io::Result<()> {
        unsafe { self.setsockopt(libc::SOL_SOCKET, libc::SO_OOBINLINE, oob_inline as c_int) }
    }

    unsafe fn setsockopt<T>(&self, opt: c_int, val: c_int, payload: T) -> io::Result<()>
    where
        T: Copy,
    {
        let payload = &payload as *const T as *const c_void;
        syscall!(setsockopt(
            self.fd,
            opt,
            val,
            payload,
            mem::size_of::<T>() as libc::socklen_t,
        ))?;
        Ok(())
    }

    unsafe fn getsockopt<T: Copy>(&self, opt: c_int, val: c_int) -> io::Result<T> {
        let mut slot: T = mem::zeroed();
        let mut len = mem::size_of::<T>() as libc::socklen_t;
        syscall!(getsockopt(
            self.fd,
            opt,
            val,
            &mut slot as *mut _ as *mut _,
            &mut len,
        ))?;
        assert_eq!(len as usize, mem::size_of::<T>());
        Ok(slot)
    }

    pub fn inner(self) -> SysSocket {
        self.fd
    }
}

impl fmt::Debug for Socket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut f = f.debug_struct("Socket");
        f.field("fd", &self.fd);
        if let Ok(addr) = getsockname(self.fd) {
            f.field("local_addr", &addr);
        }
        if let Ok(addr) = getpeername(self.fd) {
            f.field("peer_addr", &addr);
        }
        f.finish()
    }
}

impl AsRawFd for Socket {
    fn as_raw_fd(&self) -> c_int {
        self.fd
    }
}

impl IntoRawFd for Socket {
    fn into_raw_fd(self) -> c_int {
        let fd = self.fd;
        mem::forget(self);
        return fd;
    }
}

impl FromRawFd for Socket {
    unsafe fn from_raw_fd(fd: c_int) -> Socket {
        Socket { fd: fd }
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
        crate::Socket {
            inner: Socket::from_raw_fd(fd).inner(),
        }
    }
}

#[cfg(feature = "all")]
impl From<crate::Socket> for UnixStream {
    fn from(socket: crate::Socket) -> UnixStream {
        unsafe { UnixStream::from_raw_fd(socket.into_raw_fd()) }
    }
}

#[cfg(feature = "all")]
impl From<crate::Socket> for UnixListener {
    fn from(socket: crate::Socket) -> UnixListener {
        unsafe { UnixListener::from_raw_fd(socket.into_raw_fd()) }
    }
}

#[cfg(feature = "all")]
impl From<crate::Socket> for UnixDatagram {
    fn from(socket: crate::Socket) -> UnixDatagram {
        unsafe { UnixDatagram::from_raw_fd(socket.into_raw_fd()) }
    }
}

#[cfg(feature = "all")]
impl From<UnixStream> for crate::Socket {
    fn from(socket: UnixStream) -> crate::Socket {
        crate::Socket {
            inner: socket.into_raw_fd(),
        }
    }
}

#[cfg(feature = "all")]
impl From<UnixListener> for crate::Socket {
    fn from(socket: UnixListener) -> crate::Socket {
        crate::Socket {
            inner: socket.into_raw_fd(),
        }
    }
}

#[cfg(feature = "all")]
impl From<UnixDatagram> for crate::Socket {
    fn from(socket: UnixDatagram) -> crate::Socket {
        crate::Socket {
            inner: socket.into_raw_fd(),
        }
    }
}

pub(crate) fn close(fd: SysSocket) {
    unsafe {
        let _ = libc::close(fd);
    }
}

fn dur2timeval(dur: Option<Duration>) -> io::Result<libc::timeval> {
    match dur {
        Some(dur) => {
            if dur.as_secs() == 0 && dur.subsec_nanos() == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "cannot set a 0 duration timeout",
                ));
            }

            let secs = if dur.as_secs() > libc::time_t::max_value() as u64 {
                libc::time_t::max_value()
            } else {
                dur.as_secs() as libc::time_t
            };
            let mut timeout = libc::timeval {
                tv_sec: secs,
                tv_usec: (dur.subsec_nanos() / 1000) as libc::suseconds_t,
            };
            if timeout.tv_sec == 0 && timeout.tv_usec == 0 {
                timeout.tv_usec = 1;
            }
            Ok(timeout)
        }
        None => Ok(libc::timeval {
            tv_sec: 0,
            tv_usec: 0,
        }),
    }
}

fn timeval2dur(raw: libc::timeval) -> Option<Duration> {
    if raw.tv_sec == 0 && raw.tv_usec == 0 {
        None
    } else {
        let sec = raw.tv_sec as u64;
        let nsec = (raw.tv_usec as u32) * 1000;
        Some(Duration::new(sec, nsec))
    }
}

pub(crate) fn to_in_addr(addr: &Ipv4Addr) -> in_addr {
    // `s_addr` is stored as BE on all machines, and the array is in BE order.
    // So the native endian conversion method is used so that it's never swapped.
    in_addr {
        s_addr: u32::from_ne_bytes(addr.octets()),
    }
}

pub(crate) fn from_in_addr(in_addr: in_addr) -> Ipv4Addr {
    Ipv4Addr::from(in_addr.s_addr.to_ne_bytes())
}

pub(crate) fn to_in6_addr(addr: &Ipv6Addr) -> libc::in6_addr {
    let mut ret: libc::in6_addr = unsafe { mem::zeroed() };
    ret.s6_addr = addr.octets();
    return ret;
}

pub(crate) fn from_in6_addr(in6_addr: in6_addr) -> Ipv6Addr {
    Ipv6Addr::from(in6_addr.s6_addr)
}

#[cfg(target_os = "android")]
fn to_ipv6mr_interface(value: u32) -> c_int {
    value as c_int
}

#[cfg(not(target_os = "android"))]
fn to_ipv6mr_interface(value: u32) -> libc::c_uint {
    value as libc::c_uint
}

fn linger2dur(linger_opt: libc::linger) -> Option<Duration> {
    if linger_opt.l_onoff == 0 {
        None
    } else {
        Some(Duration::from_secs(linger_opt.l_linger as u64))
    }
}

fn dur2linger(dur: Option<Duration>) -> libc::linger {
    match dur {
        Some(d) => libc::linger {
            l_onoff: 1,
            l_linger: d.as_secs() as c_int,
        },
        None => libc::linger {
            l_onoff: 0,
            l_linger: 0,
        },
    }
}

#[test]
fn test_ip() {
    let ip = Ipv4Addr::new(127, 0, 0, 1);
    assert_eq!(ip, from_in_addr(to_in_addr(&ip)));

    let ip = Ipv4Addr::new(127, 34, 4, 12);
    let want = 127 << 0 | 34 << 8 | 4 << 16 | 12 << 24;
    assert_eq!(to_in_addr(&ip).s_addr, want);
    assert_eq!(from_in_addr(in_addr { s_addr: want }), ip);
}

#[test]
#[cfg(all(feature = "all", not(target_os = "redox")))]
fn test_out_of_band_inline() {
    let tcp = Socket {
        fd: socket(libc::AF_INET, libc::SOCK_STREAM, 0).unwrap(),
    };
    assert_eq!(tcp.out_of_band_inline().unwrap(), false);

    tcp.set_out_of_band_inline(true).unwrap();
    assert_eq!(tcp.out_of_band_inline().unwrap(), true);
}
