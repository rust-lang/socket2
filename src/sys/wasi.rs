// Copyright 2015 The Rust Project Developers.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::cmp::min;
use std::mem::MaybeUninit;
use std::net::{Ipv4Addr, Ipv6Addr, Shutdown};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, IntoRawFd, OwnedFd};
use std::time::{Duration, Instant};
use std::{io, mem, ptr};

pub(crate) use libc::{
    c_int, sa_family_t, sockaddr, sockaddr_in, sockaddr_in6, sockaddr_storage, socklen_t, ssize_t,
    AF_INET, AF_INET6, IPPROTO_IP, IPPROTO_IPV6, IPPROTO_TCP, IPPROTO_UDP, IPV6_UNICAST_HOPS,
    IP_TTL, SOCK_DGRAM, SOCK_STREAM, SOL_SOCKET, SO_ERROR, SO_KEEPALIVE, SO_RCVBUF, SO_REUSEADDR,
    SO_SNDBUF, SO_TYPE, TCP_NODELAY,
};
use libc::{in6_addr, in_addr};
#[cfg(feature = "all")]
pub(crate) use libc::{TCP_KEEPCNT, TCP_KEEPINTVL};

use crate::{Domain, Protocol, SockAddr, TcpKeepalive, Type};

pub(crate) type Bool = c_int;

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

const MAX_BUF_LEN: usize = ssize_t::MAX as usize;

impl_debug!(
    Domain,
    libc::AF_INET,
    libc::AF_INET6,
    libc::AF_UNSPEC, // = 0.
);

/// WASI only API.
impl Type {
    /// Set `SOCK_NONBLOCK` on the `Type`.
    pub const fn nonblocking(self) -> Type {
        Type(self.0 | libc::SOCK_NONBLOCK)
    }
}

impl_debug!(
    Type,
    libc::SOCK_STREAM,
    libc::SOCK_DGRAM,
    libc::SOCK_NONBLOCK,
);

impl_debug!(Protocol, libc::IPPROTO_TCP, libc::IPPROTO_UDP,);

pub(crate) type Socket = c_int;

pub(crate) unsafe fn socket_from_raw(socket: Socket) -> crate::socket::Inner {
    crate::socket::Inner::from_raw_fd(socket)
}

pub(crate) fn socket_as_raw(socket: &crate::socket::Inner) -> Socket {
    socket.as_raw_fd()
}

pub(crate) fn socket_into_raw(socket: crate::socket::Inner) -> Socket {
    socket.into_raw_fd()
}

pub(crate) fn socket(family: c_int, ty: c_int, protocol: c_int) -> io::Result<Socket> {
    syscall!(socket(family, ty, protocol))
}

pub(crate) fn bind(fd: Socket, addr: &SockAddr) -> io::Result<()> {
    syscall!(bind(fd, addr.as_ptr(), addr.len() as _)).map(|_| ())
}

pub(crate) fn connect(fd: Socket, addr: &SockAddr) -> io::Result<()> {
    syscall!(connect(fd, addr.as_ptr(), addr.len())).map(|_| ())
}

pub(crate) fn poll_connect(socket: &crate::Socket, timeout: Duration) -> io::Result<()> {
    let start = Instant::now();

    let mut pollfd = libc::pollfd {
        fd: socket.as_raw(),
        events: libc::POLLIN | libc::POLLOUT,
        revents: 0,
    };

    loop {
        let elapsed = start.elapsed();
        if elapsed >= timeout {
            return Err(io::ErrorKind::TimedOut.into());
        }

        let timeout = (timeout - elapsed).as_millis();
        let timeout = timeout.clamp(1, c_int::MAX as u128) as c_int;

        match syscall!(poll(&mut pollfd, 1, timeout)) {
            Ok(0) => return Err(io::ErrorKind::TimedOut.into()),
            Ok(_) => {
                // WASI poll does not return  POLLHUP or POLLERR in revents. Check if the
                // connnection actually succeeded and return ok only when the socket is
                // ready and no errors were found.
                if let Some(e) = socket.take_error()? {
                    return Err(e);
                }
                return Ok(());
            }
            // Got interrupted, try again.
            Err(ref err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err),
        }
    }
}

pub(crate) fn listen(fd: Socket, backlog: c_int) -> io::Result<()> {
    syscall!(listen(fd, backlog)).map(|_| ())
}

pub(crate) fn accept(fd: Socket) -> io::Result<(Socket, SockAddr)> {
    // Safety: `accept` initialises the `SockAddr` for us.
    unsafe { SockAddr::try_init(|storage, len| syscall!(accept(fd, storage.cast(), len))) }
}

pub(crate) fn getsockname(fd: Socket) -> io::Result<SockAddr> {
    // Safety: `accept` initialises the `SockAddr` for us.
    unsafe { SockAddr::try_init(|storage, len| syscall!(getsockname(fd, storage.cast(), len))) }
        .map(|(_, addr)| addr)
}

pub(crate) fn getpeername(fd: Socket) -> io::Result<SockAddr> {
    // Safety: `accept` initialises the `SockAddr` for us.
    unsafe { SockAddr::try_init(|storage, len| syscall!(getpeername(fd, storage.cast(), len))) }
        .map(|(_, addr)| addr)
}

pub(crate) fn set_nonblocking(fd: Socket, nonblocking: bool) -> io::Result<()> {
    let mut nonblocking = nonblocking as c_int;
    syscall!(ioctl(fd, libc::FIONBIO, &mut nonblocking)).map(|_| ())
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
        SockAddr::try_init(|addr, addrlen| {
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

pub(crate) fn send(fd: Socket, buf: &[u8], flags: c_int) -> io::Result<usize> {
    syscall!(send(
        fd,
        buf.as_ptr().cast(),
        min(buf.len(), MAX_BUF_LEN),
        flags,
    ))
    .map(|n| n as usize)
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

#[cfg(feature = "all")]
pub(crate) fn keepalive_time(fd: Socket) -> io::Result<Duration> {
    unsafe {
        getsockopt::<c_int>(fd, IPPROTO_TCP, libc::TCP_KEEPIDLE)
            .map(|secs| Duration::from_secs(secs as u64))
    }
}

pub(crate) fn set_tcp_keepalive(fd: Socket, keepalive: &TcpKeepalive) -> io::Result<()> {
    if let Some(time) = keepalive.time {
        let secs = into_secs(time);
        unsafe { setsockopt(fd, libc::IPPROTO_TCP, libc::TCP_KEEPIDLE, secs)? }
    }

    if let Some(interval) = keepalive.interval {
        let secs = into_secs(interval);
        unsafe { setsockopt(fd, libc::IPPROTO_TCP, libc::TCP_KEEPINTVL, secs)? }
    }

    if let Some(retries) = keepalive.retries {
        unsafe { setsockopt(fd, libc::IPPROTO_TCP, libc::TCP_KEEPCNT, retries as c_int)? }
    }

    Ok(())
}

fn into_secs(duration: Duration) -> c_int {
    min(duration.as_secs(), c_int::MAX as u64) as c_int
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
    let payload = ptr::addr_of!(payload).cast();
    syscall!(setsockopt(
        fd,
        opt,
        val,
        payload,
        mem::size_of::<T>() as libc::socklen_t,
    ))
    .map(|_| ())
}

pub(crate) const fn to_in_addr(addr: &Ipv4Addr) -> in_addr {
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

pub(crate) const fn to_in6_addr(addr: &Ipv6Addr) -> in6_addr {
    in6_addr {
        s6_addr: addr.octets(),
    }
}

pub(crate) fn from_in6_addr(addr: in6_addr) -> Ipv6Addr {
    Ipv6Addr::from(addr.s6_addr)
}

/// WASI only API.
impl crate::Socket {
    /// Accept a new incoming connection from this listener.
    ///
    /// This function directly corresponds to the `accept4(2)` function.
    ///
    /// This function will block the calling thread until a new connection is
    /// established. When established, the corresponding `Socket` and the remote
    /// peer's address will be returned.
    pub fn accept4(&self, flags: c_int) -> io::Result<(crate::Socket, SockAddr)> {
        // Safety: `accept4` initialises the `SockAddr` for us.
        unsafe {
            SockAddr::try_init(|storage, len| {
                syscall!(accept4(self.as_raw(), storage.cast(), len, flags))
                    .map(crate::Socket::from_raw)
            })
        }
    }

    /// Returns `true` if `listen(2)` was called on this socket by checking the
    /// `SO_ACCEPTCONN` option on this socket.
    pub fn is_listener(&self) -> io::Result<bool> {
        unsafe {
            getsockopt::<c_int>(self.as_raw(), libc::SOL_SOCKET, libc::SO_ACCEPTCONN)
                .map(|v| v != 0)
        }
    }

    /// Returns the [`Domain`] of this socket by checking the `SO_DOMAIN` option
    /// on this socket.
    pub fn domain(&self) -> io::Result<Domain> {
        unsafe { getsockopt::<c_int>(self.as_raw(), libc::SOL_SOCKET, libc::SO_DOMAIN).map(Domain) }
    }

    /// Returns the [`Protocol`] of this socket by checking the `SO_PROTOCOL`
    /// option on this socket.
    pub fn protocol(&self) -> io::Result<Option<Protocol>> {
        unsafe {
            getsockopt::<c_int>(self.as_raw(), libc::SOL_SOCKET, libc::SO_PROTOCOL).map(|v| match v
            {
                0 => None,
                p => Some(Protocol(p)),
            })
        }
    }
}

impl AsFd for crate::Socket {
    fn as_fd(&self) -> BorrowedFd<'_> {
        // SAFETY: lifetime is bound by self.
        unsafe { BorrowedFd::borrow_raw(self.as_raw()) }
    }
}

impl AsRawFd for crate::Socket {
    fn as_raw_fd(&self) -> c_int {
        self.as_raw()
    }
}

impl From<crate::Socket> for OwnedFd {
    fn from(sock: crate::Socket) -> OwnedFd {
        // SAFETY: sock.into_raw() always returns a valid fd.
        unsafe { OwnedFd::from_raw_fd(sock.into_raw()) }
    }
}

impl IntoRawFd for crate::Socket {
    fn into_raw_fd(self) -> c_int {
        self.into_raw()
    }
}

impl From<OwnedFd> for crate::Socket {
    fn from(fd: OwnedFd) -> crate::Socket {
        // SAFETY: `OwnedFd` ensures the fd is valid.
        unsafe { crate::Socket::from_raw_fd(fd.into_raw_fd()) }
    }
}

impl FromRawFd for crate::Socket {
    unsafe fn from_raw_fd(fd: c_int) -> crate::Socket {
        crate::Socket::from_raw(fd)
    }
}

#[test]
fn in_addr_convertion() {
    let ip = Ipv4Addr::new(127, 0, 0, 1);
    let raw = to_in_addr(&ip);
    // NOTE: `in_addr` is packed on NetBSD and it's unsafe to borrow.
    let a = raw.s_addr;
    assert_eq!(a, u32::from_ne_bytes([127, 0, 0, 1]));
    assert_eq!(from_in_addr(raw), ip);

    let ip = Ipv4Addr::new(127, 34, 4, 12);
    let raw = to_in_addr(&ip);
    let a = raw.s_addr;
    assert_eq!(a, u32::from_ne_bytes([127, 34, 4, 12]));
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
