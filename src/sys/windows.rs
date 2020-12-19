// Copyright 2015 The Rust Project Developers.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::cmp::min;
use std::io::{self, IoSlice, IoSliceMut};
use std::mem::{self, size_of, MaybeUninit};
use std::net::{self, Ipv4Addr, Ipv6Addr, Shutdown};
use std::os::windows::prelude::*;
use std::sync::Once;
use std::time::Duration;
use std::{fmt, ptr};

use winapi::ctypes::{c_char, c_long};
use winapi::shared::in6addr::*;
use winapi::shared::inaddr::*;
use winapi::shared::minwindef::DWORD;
use winapi::shared::mstcpip::{tcp_keepalive, SIO_KEEPALIVE_VALS};
use winapi::shared::ntdef::HANDLE;
use winapi::shared::ws2def;
use winapi::shared::ws2ipdef::*;
use winapi::um::handleapi::SetHandleInformation;
use winapi::um::processthreadsapi::GetCurrentProcessId;
use winapi::um::winbase::{self, INFINITE};
use winapi::um::winsock2::{self as sock, u_long, SD_BOTH, SD_RECEIVE, SD_SEND};

use crate::{RecvFlags, SockAddr, TcpKeepalive, Type};

pub(crate) use winapi::ctypes::c_int;

/// Fake MSG_TRUNC flag for the [`RecvFlags`] struct.
///
/// The flag is enabled when a `WSARecv[From]` call returns `WSAEMSGSIZE`. The
/// value of the flag is defined by us.
pub(crate) const MSG_TRUNC: c_int = 0x01;

// Used in `Domain`.
pub(crate) use winapi::shared::ws2def::{AF_INET, AF_INET6};
// Used in `Type`.
pub(crate) use winapi::shared::ws2def::{SOCK_DGRAM, SOCK_STREAM};
#[cfg(feature = "all")]
pub(crate) use winapi::shared::ws2def::{SOCK_RAW, SOCK_SEQPACKET};
// Used in `Protocol`.
pub(crate) const IPPROTO_ICMP: c_int = winapi::shared::ws2def::IPPROTO_ICMP as c_int;
pub(crate) const IPPROTO_ICMPV6: c_int = winapi::shared::ws2def::IPPROTO_ICMPV6 as c_int;
pub(crate) const IPPROTO_TCP: c_int = winapi::shared::ws2def::IPPROTO_TCP as c_int;
pub(crate) const IPPROTO_UDP: c_int = winapi::shared::ws2def::IPPROTO_UDP as c_int;
// Used in `SockAddr`.
pub(crate) use winapi::shared::ws2def::{
    ADDRESS_FAMILY as sa_family_t, SOCKADDR as sockaddr, SOCKADDR_IN as sockaddr_in,
    SOCKADDR_STORAGE as sockaddr_storage,
};
pub(crate) use winapi::shared::ws2ipdef::SOCKADDR_IN6_LH as sockaddr_in6;
pub(crate) use winapi::um::ws2tcpip::socklen_t;
// Used in `Socket`.
pub(crate) use winapi::shared::ws2def::{
    IPPROTO_IP, SOL_SOCKET, SO_BROADCAST, SO_ERROR, SO_KEEPALIVE, SO_LINGER, SO_OOBINLINE,
    SO_RCVBUF, SO_RCVTIMEO, SO_REUSEADDR, SO_SNDBUF, SO_SNDTIMEO, TCP_NODELAY,
};
pub(crate) use winapi::shared::ws2ipdef::{
    IPV6_ADD_MEMBERSHIP, IPV6_DROP_MEMBERSHIP, IPV6_MREQ as Ipv6Mreq, IPV6_MULTICAST_HOPS,
    IPV6_MULTICAST_LOOP, IPV6_UNICAST_HOPS, IPV6_V6ONLY, IP_ADD_MEMBERSHIP, IP_DROP_MEMBERSHIP,
    IP_MREQ as IpMreq, IP_MULTICAST_IF, IP_MULTICAST_LOOP, IP_MULTICAST_TTL, IP_TTL,
};
#[cfg(all(windows, feature = "all"))]
pub(crate) use winapi::um::winsock2::MSG_OOB;
pub(crate) use winapi::um::winsock2::{linger, MSG_PEEK};
pub(crate) const IPPROTO_IPV6: c_int = winapi::shared::ws2def::IPPROTO_IPV6 as c_int;

/// Type used in set/getsockopt to retrieve the `TCP_NODELAY` option.
///
/// NOTE: <https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-getsockopt>
/// documents that options such as `TCP_NODELAY` and `SO_KEEPALIVE` expect a
/// `BOOL` (alias for `c_int`, 4 bytes), however in practice this turns out to
/// be false (or misleading) as a `BOOLEAN` (`c_uchar`, 1 byte) is returned by
/// `getsockopt`.
pub(crate) type Bool = winapi::shared::ntdef::BOOLEAN;

/// Maximum size of a buffer passed to system call like `recv` and `send`.
const MAX_BUF_LEN: usize = <c_int>::max_value() as usize;

/// Helper macro to execute a system call that returns an `io::Result`.
macro_rules! syscall {
    ($fn: ident ( $($arg: expr),* $(,)* ), $err_test: path, $err_value: expr) => {{
        #[allow(unused_unsafe)]
        let res = unsafe { sock::$fn($($arg, )*) };
        if $err_test(&res, &$err_value) {
            Err(io::Error::last_os_error())
        } else {
            Ok(res)
        }
    }};
}

impl_debug!(
    crate::Domain,
    ws2def::AF_INET,
    ws2def::AF_INET6,
    ws2def::AF_UNIX,
    ws2def::AF_UNSPEC, // = 0.
);

/// Windows only API.
impl Type {
    /// Our custom flag to set `WSA_FLAG_NO_HANDLE_INHERIT` on socket creation.
    /// Trying to mimic `Type::cloexec` on windows.
    const NO_INHERIT: c_int = 1 << ((size_of::<c_int>() * 8) - 1); // Last bit.

    /// Set `WSA_FLAG_NO_HANDLE_INHERIT` on the socket.
    #[cfg(feature = "all")]
    pub const fn no_inherit(self) -> Type {
        self._no_inherit()
    }

    pub(crate) const fn _no_inherit(self) -> Type {
        Type(self.0 | Type::NO_INHERIT)
    }
}

impl_debug!(
    crate::Type,
    ws2def::SOCK_STREAM,
    ws2def::SOCK_DGRAM,
    ws2def::SOCK_RAW,
    ws2def::SOCK_RDM,
    ws2def::SOCK_SEQPACKET,
);

impl_debug!(
    crate::Protocol,
    self::IPPROTO_ICMP,
    self::IPPROTO_ICMPV6,
    self::IPPROTO_TCP,
    self::IPPROTO_UDP,
);

impl std::fmt::Debug for RecvFlags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecvFlags")
            .field("is_truncated", &self.is_truncated())
            .finish()
    }
}

fn init() {
    static INIT: Once = Once::new();

    INIT.call_once(|| {
        // Initialize winsock through the standard library by just creating a
        // dummy socket. Whether this is successful or not we drop the result as
        // libstd will be sure to have initialized winsock.
        let _ = net::UdpSocket::bind("127.0.0.1:34254");
    });
}

fn last_error() -> io::Error {
    io::Error::from_raw_os_error(unsafe { sock::WSAGetLastError() })
}

// TODO: rename to `Socket` once the struct `Socket` is no longer used.
pub(crate) type SysSocket = sock::SOCKET;

pub(crate) fn socket(family: c_int, mut ty: c_int, protocol: c_int) -> io::Result<SysSocket> {
    init();

    // Check if we set our custom flag.
    let flags = if ty & Type::NO_INHERIT != 0 {
        ty = ty & !Type::NO_INHERIT;
        sock::WSA_FLAG_NO_HANDLE_INHERIT
    } else {
        0
    };

    syscall!(
        WSASocketW(
            family,
            ty,
            protocol,
            ptr::null_mut(),
            0,
            sock::WSA_FLAG_OVERLAPPED | flags,
        ),
        PartialEq::eq,
        sock::INVALID_SOCKET
    )
}

pub(crate) fn bind(socket: SysSocket, addr: &SockAddr) -> io::Result<()> {
    syscall!(bind(socket, addr.as_ptr(), addr.len()), PartialEq::ne, 0).map(|_| ())
}

pub(crate) fn connect(socket: SysSocket, addr: &SockAddr) -> io::Result<()> {
    syscall!(connect(socket, addr.as_ptr(), addr.len()), PartialEq::ne, 0).map(|_| ())
}

pub(crate) fn listen(socket: SysSocket, backlog: i32) -> io::Result<()> {
    syscall!(listen(socket, backlog), PartialEq::ne, 0).map(|_| ())
}

pub(crate) fn accept(socket: SysSocket) -> io::Result<(SysSocket, SockAddr)> {
    // Safety: `accept` initialises the `SockAddr` for us.
    unsafe {
        SockAddr::init(|storage, len| {
            syscall!(
                accept(socket, storage.cast(), len),
                PartialEq::eq,
                sock::INVALID_SOCKET
            )
        })
    }
}

pub(crate) fn getsockname(socket: SysSocket) -> io::Result<SockAddr> {
    // Safety: `getsockname` initialises the `SockAddr` for us.
    unsafe {
        SockAddr::init(|storage, len| {
            syscall!(
                getsockname(socket, storage.cast(), len),
                PartialEq::eq,
                sock::SOCKET_ERROR
            )
        })
    }
    .map(|(_, addr)| addr)
}

pub(crate) fn getpeername(socket: SysSocket) -> io::Result<SockAddr> {
    // Safety: `getpeername` initialises the `SockAddr` for us.
    unsafe {
        SockAddr::init(|storage, len| {
            syscall!(
                getpeername(socket, storage.cast(), len),
                PartialEq::eq,
                sock::SOCKET_ERROR
            )
        })
    }
    .map(|(_, addr)| addr)
}

pub(crate) fn try_clone(socket: SysSocket) -> io::Result<SysSocket> {
    let mut info: MaybeUninit<sock::WSAPROTOCOL_INFOW> = MaybeUninit::uninit();
    syscall!(
        WSADuplicateSocketW(socket, GetCurrentProcessId(), info.as_mut_ptr()),
        PartialEq::eq,
        sock::SOCKET_ERROR
    )?;
    // Safety: `WSADuplicateSocketW` intialised `info` for us.
    let mut info = unsafe { info.assume_init() };

    syscall!(
        WSASocketW(
            info.iAddressFamily,
            info.iSocketType,
            info.iProtocol,
            &mut info,
            0,
            sock::WSA_FLAG_OVERLAPPED | sock::WSA_FLAG_NO_HANDLE_INHERIT,
        ),
        PartialEq::eq,
        sock::INVALID_SOCKET
    )
}

pub(crate) fn set_nonblocking(socket: SysSocket, nonblocking: bool) -> io::Result<()> {
    let mut nonblocking = nonblocking as u_long;
    ioctlsocket(socket, sock::FIONBIO, &mut nonblocking)
}

pub(crate) fn shutdown(socket: SysSocket, how: Shutdown) -> io::Result<()> {
    let how = match how {
        Shutdown::Write => SD_SEND,
        Shutdown::Read => SD_RECEIVE,
        Shutdown::Both => SD_BOTH,
    };
    syscall!(shutdown(socket, how), PartialEq::eq, sock::SOCKET_ERROR).map(|_| ())
}

pub(crate) fn recv(socket: SysSocket, buf: &mut [u8], flags: c_int) -> io::Result<usize> {
    let res = syscall!(
        recv(
            socket,
            buf.as_mut_ptr().cast(),
            min(buf.len(), MAX_BUF_LEN) as c_int,
            flags,
        ),
        PartialEq::eq,
        sock::SOCKET_ERROR
    );
    match res {
        Ok(n) => Ok(n as usize),
        Err(ref err) if err.raw_os_error() == Some(sock::WSAESHUTDOWN as i32) => Ok(0),
        Err(err) => Err(err),
    }
}

pub(crate) fn recv_vectored(
    socket: SysSocket,
    bufs: &mut [IoSliceMut<'_>],
    flags: c_int,
) -> io::Result<(usize, RecvFlags)> {
    let mut nread = 0;
    let mut flags = flags as DWORD;
    let res = syscall!(
        WSARecv(
            socket,
            bufs.as_mut_ptr().cast(),
            min(bufs.len(), DWORD::max_value() as usize) as DWORD,
            &mut nread,
            &mut flags,
            ptr::null_mut(),
            None,
        ),
        PartialEq::eq,
        sock::SOCKET_ERROR
    );
    match res {
        Ok(_) => Ok((nread as usize, RecvFlags(0))),
        Err(ref err) if err.raw_os_error() == Some(sock::WSAESHUTDOWN as i32) => {
            Ok((0, RecvFlags(0)))
        }
        Err(ref err) if err.raw_os_error() == Some(sock::WSAEMSGSIZE as i32) => {
            Ok((nread as usize, RecvFlags(MSG_TRUNC)))
        }
        Err(err) => Err(err),
    }
}

pub(crate) fn recv_from(
    socket: SysSocket,
    buf: &mut [u8],
    flags: c_int,
) -> io::Result<(usize, SockAddr)> {
    // Safety: `recvfrom` initialises the `SockAddr` for us.
    unsafe {
        SockAddr::init(|storage, addrlen| {
            let res = syscall!(
                recvfrom(
                    socket,
                    buf.as_mut_ptr().cast(),
                    min(buf.len(), MAX_BUF_LEN) as c_int,
                    flags,
                    storage.cast(),
                    addrlen,
                ),
                PartialEq::eq,
                sock::SOCKET_ERROR
            );
            match res {
                Ok(n) => Ok(n as usize),
                Err(ref err) if err.raw_os_error() == Some(sock::WSAESHUTDOWN as i32) => Ok(0),
                Err(err) => Err(err),
            }
        })
    }
}

pub(crate) fn recv_from_vectored(
    socket: SysSocket,
    bufs: &mut [IoSliceMut<'_>],
    flags: c_int,
) -> io::Result<(usize, RecvFlags, SockAddr)> {
    // Safety: `recvfrom` initialises the `SockAddr` for us.
    unsafe {
        SockAddr::init(|storage, addrlen| {
            let mut nread = 0;
            let mut flags = flags as DWORD;
            let res = syscall!(
                WSARecvFrom(
                    socket,
                    bufs.as_mut_ptr().cast(),
                    min(bufs.len(), DWORD::max_value() as usize) as DWORD,
                    &mut nread,
                    &mut flags,
                    storage.cast(),
                    addrlen,
                    ptr::null_mut(),
                    None,
                ),
                PartialEq::eq,
                sock::SOCKET_ERROR
            );
            match res {
                Ok(_) => Ok((nread as usize, RecvFlags(0))),
                Err(ref err) if err.raw_os_error() == Some(sock::WSAESHUTDOWN as i32) => {
                    Ok((nread as usize, RecvFlags(0)))
                }
                Err(ref err) if err.raw_os_error() == Some(sock::WSAEMSGSIZE as i32) => {
                    Ok((nread as usize, RecvFlags(MSG_TRUNC)))
                }
                Err(err) => Err(err),
            }
        })
    }
    .map(|((n, recv_flags), addr)| (n, recv_flags, addr))
}

pub(crate) fn send(socket: SysSocket, buf: &[u8], flags: c_int) -> io::Result<usize> {
    syscall!(
        send(
            socket,
            buf.as_ptr().cast(),
            min(buf.len(), MAX_BUF_LEN) as c_int,
            flags,
        ),
        PartialEq::eq,
        sock::SOCKET_ERROR
    )
    .map(|n| n as usize)
}

pub(crate) fn send_vectored(
    socket: SysSocket,
    bufs: &[IoSlice<'_>],
    flags: c_int,
) -> io::Result<usize> {
    let mut nsent = 0;
    syscall!(
        WSASend(
            socket,
            // FIXME: From the `WSASend` docs [1]:
            // > For a Winsock application, once the WSASend function is called,
            // > the system owns these buffers and the application may not
            // > access them.
            //
            // So what we're doing is actually UB as `bufs` needs to be `&mut
            // [IoSlice<'_>]`.
            //
            // Tracking issue: https://github.com/rust-lang/socket2-rs/issues/129.
            //
            // NOTE: `send_to_vectored` has the same problem.
            //
            // [1] https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsasend
            bufs.as_ptr() as *mut _,
            min(bufs.len(), DWORD::max_value() as usize) as DWORD,
            &mut nsent,
            flags as DWORD,
            std::ptr::null_mut(),
            None,
        ),
        PartialEq::eq,
        sock::SOCKET_ERROR
    )
    .map(|_| nsent as usize)
}

pub(crate) fn send_to(
    socket: SysSocket,
    buf: &[u8],
    addr: &SockAddr,
    flags: c_int,
) -> io::Result<usize> {
    syscall!(
        sendto(
            socket,
            buf.as_ptr().cast(),
            min(buf.len(), MAX_BUF_LEN) as c_int,
            flags,
            addr.as_ptr(),
            addr.len(),
        ),
        PartialEq::eq,
        sock::SOCKET_ERROR
    )
    .map(|n| n as usize)
}

pub(crate) fn send_to_vectored(
    socket: SysSocket,
    bufs: &[IoSlice<'_>],
    addr: &SockAddr,
    flags: c_int,
) -> io::Result<usize> {
    let mut nsent = 0;
    syscall!(
        WSASendTo(
            socket,
            // FIXME: Same problem as in `send_vectored`.
            bufs.as_ptr() as *mut _,
            bufs.len().min(DWORD::MAX as usize) as DWORD,
            &mut nsent,
            flags as DWORD,
            addr.as_ptr(),
            addr.len(),
            ptr::null_mut(),
            None,
        ),
        PartialEq::eq,
        sock::SOCKET_ERROR
    )
    .map(|_| nsent as usize)
}

/// Wrapper around `getsockopt` to deal with platform specific timeouts.
pub(crate) fn timeout_opt(fd: SysSocket, lvl: c_int, name: c_int) -> io::Result<Option<Duration>> {
    unsafe { getsockopt(fd, lvl, name).map(from_ms) }
}

fn from_ms(duration: DWORD) -> Option<Duration> {
    if duration == 0 {
        None
    } else {
        let secs = duration / 1000;
        let nsec = (duration % 1000) * 1000000;
        Some(Duration::new(secs as u64, nsec as u32))
    }
}

/// Wrapper around `setsockopt` to deal with platform specific timeouts.
pub(crate) fn set_timeout_opt(
    fd: SysSocket,
    level: c_int,
    optname: c_int,
    duration: Option<Duration>,
) -> io::Result<()> {
    let duration = into_ms(duration);
    unsafe { setsockopt(fd, level, optname, duration) }
}

fn into_ms(duration: Option<Duration>) -> DWORD {
    // Note that a duration is a (u64, u32) (seconds, nanoseconds) pair, and the
    // timeouts in windows APIs are typically u32 milliseconds. To translate, we
    // have two pieces to take care of:
    //
    // * Nanosecond precision is rounded up
    // * Greater than u32::MAX milliseconds (50 days) is rounded up to
    //   INFINITE (never time out).
    duration
        .map(|duration| min(duration.as_millis(), INFINITE as u128) as DWORD)
        .unwrap_or(0)
}

pub(crate) fn set_tcp_keepalive(socket: SysSocket, keepalive: &TcpKeepalive) -> io::Result<()> {
    let mut keepalive = tcp_keepalive {
        onoff: 1,
        keepalivetime: into_ms(keepalive.time),
        keepaliveinterval: into_ms(keepalive.interval),
    };
    let mut out = 0;
    syscall!(
        WSAIoctl(
            socket,
            SIO_KEEPALIVE_VALS,
            &mut keepalive as *mut _ as *mut _,
            size_of::<tcp_keepalive>() as _,
            ptr::null_mut(),
            0,
            &mut out,
            ptr::null_mut(),
            None,
        ),
        PartialEq::eq,
        sock::SOCKET_ERROR
    )
    .map(|_| ())
}

/// Caller must ensure `T` is the correct type for `level` and `optname`.
pub(crate) unsafe fn getsockopt<T>(
    socket: SysSocket,
    level: c_int,
    optname: c_int,
) -> io::Result<T> {
    let mut optval: MaybeUninit<T> = MaybeUninit::uninit();
    let mut optlen = mem::size_of::<T>() as c_int;
    syscall!(
        getsockopt(
            socket,
            level,
            optname,
            optval.as_mut_ptr().cast(),
            &mut optlen,
        ),
        PartialEq::eq,
        sock::SOCKET_ERROR
    )
    .map(|_| {
        debug_assert_eq!(optlen as usize, mem::size_of::<T>());
        // Safety: `getsockopt` initialised `optval` for us.
        optval.assume_init()
    })
}

/// Caller must ensure `T` is the correct type for `level` and `optname`.
pub(crate) unsafe fn setsockopt<T>(
    socket: SysSocket,
    level: c_int,
    optname: c_int,
    optval: T,
) -> io::Result<()> {
    syscall!(
        setsockopt(
            socket,
            level,
            optname,
            (&optval as *const T).cast(),
            mem::size_of::<T>() as c_int,
        ),
        PartialEq::eq,
        sock::SOCKET_ERROR
    )
    .map(|_| ())
}

fn ioctlsocket(socket: SysSocket, cmd: c_long, payload: &mut u_long) -> io::Result<()> {
    syscall!(
        ioctlsocket(socket, cmd, payload),
        PartialEq::eq,
        sock::SOCKET_ERROR
    )
    .map(|_| ())
}

/// Windows only API.
impl crate::Socket {
    /// Sets `HANDLE_FLAG_INHERIT` using `SetHandleInformation`.
    #[cfg(feature = "all")]
    pub fn set_no_inherit(&self, no_inherit: bool) -> io::Result<()> {
        self._set_no_inherit(no_inherit)
    }

    pub(crate) fn _set_no_inherit(&self, no_inherit: bool) -> io::Result<()> {
        // NOTE: can't use `syscall!` because it expects the function in the
        // `sock::` path.
        let res = unsafe {
            SetHandleInformation(
                self.inner as HANDLE,
                winbase::HANDLE_FLAG_INHERIT,
                !no_inherit as _,
            )
        };
        if res == 0 {
            // Zero means error.
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

pub(crate) fn to_in_addr(addr: &Ipv4Addr) -> IN_ADDR {
    let mut s_un: in_addr_S_un = unsafe { mem::zeroed() };
    // `S_un` is stored as BE on all machines, and the array is in BE order. So
    // the native endian conversion method is used so that it's never swapped.
    unsafe { *(s_un.S_addr_mut()) = u32::from_ne_bytes(addr.octets()) };
    IN_ADDR { S_un: s_un }
}

pub(crate) fn from_in_addr(in_addr: IN_ADDR) -> Ipv4Addr {
    Ipv4Addr::from(unsafe { *in_addr.S_un.S_addr() }.to_ne_bytes())
}

#[repr(transparent)] // Required during rewriting.
pub struct Socket {
    socket: SysSocket,
}

impl Socket {
    pub fn multicast_if_v6(&self) -> io::Result<u32> {
        unsafe {
            let raw: c_int = self.getsockopt(IPPROTO_IPV6 as c_int, IPV6_MULTICAST_IF)?;
            Ok(raw as u32)
        }
    }

    pub fn set_multicast_if_v6(&self, interface: u32) -> io::Result<()> {
        unsafe { self.setsockopt(IPPROTO_IPV6 as c_int, IPV6_MULTICAST_IF, interface as c_int) }
    }

    unsafe fn setsockopt<T>(&self, opt: c_int, val: c_int, payload: T) -> io::Result<()>
    where
        T: Copy,
    {
        let payload = &payload as *const T as *const c_char;
        if sock::setsockopt(self.socket, opt, val, payload, mem::size_of::<T>() as c_int) == 0 {
            Ok(())
        } else {
            Err(last_error())
        }
    }

    unsafe fn getsockopt<T: Copy>(&self, opt: c_int, val: c_int) -> io::Result<T> {
        let mut slot: T = mem::zeroed();
        let mut len = mem::size_of::<T>() as c_int;
        if sock::getsockopt(
            self.socket,
            opt,
            val,
            &mut slot as *mut _ as *mut _,
            &mut len,
        ) == 0
        {
            assert_eq!(len as usize, mem::size_of::<T>());
            Ok(slot)
        } else {
            Err(last_error())
        }
    }
}

impl fmt::Debug for Socket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut f = f.debug_struct("Socket");
        f.field("socket", &self.socket);
        if let Ok(addr) = getsockname(self.socket) {
            f.field("local_addr", &addr);
        }
        if let Ok(addr) = getpeername(self.socket) {
            f.field("peer_addr", &addr);
        }
        f.finish()
    }
}

impl AsRawSocket for Socket {
    fn as_raw_socket(&self) -> RawSocket {
        self.socket as RawSocket
    }
}

impl IntoRawSocket for Socket {
    fn into_raw_socket(self) -> RawSocket {
        let socket = self.socket;
        mem::forget(self);
        socket as RawSocket
    }
}

impl FromRawSocket for Socket {
    unsafe fn from_raw_socket(socket: RawSocket) -> Socket {
        Socket {
            socket: socket as sock::SOCKET,
        }
    }
}

impl AsRawSocket for crate::Socket {
    fn as_raw_socket(&self) -> RawSocket {
        self.inner as RawSocket
    }
}

impl IntoRawSocket for crate::Socket {
    fn into_raw_socket(self) -> RawSocket {
        let socket = self.inner;
        mem::forget(self);
        socket as RawSocket
    }
}

impl FromRawSocket for crate::Socket {
    unsafe fn from_raw_socket(socket: RawSocket) -> crate::Socket {
        crate::Socket {
            inner: socket as SysSocket,
        }
    }
}

pub(crate) fn close(socket: SysSocket) {
    unsafe {
        let _ = sock::closesocket(socket);
    }
}

pub(crate) fn to_in6_addr(addr: &Ipv6Addr) -> in6_addr {
    let mut ret_addr: in6_addr_u = unsafe { mem::zeroed() };
    unsafe { *(ret_addr.Byte_mut()) = addr.octets() };
    let mut ret: in6_addr = unsafe { mem::zeroed() };
    ret.u = ret_addr;
    ret
}

pub(crate) fn from_in6_addr(in6_addr: in6_addr) -> Ipv6Addr {
    Ipv6Addr::from(*unsafe { in6_addr.u.Byte() })
}

#[test]
fn test_ipv4() {
    let ip = Ipv4Addr::new(127, 0, 0, 1);
    assert_eq!(ip, from_in_addr(to_in_addr(&ip)));

    let ip = Ipv4Addr::new(127, 34, 4, 12);
    let want = 127 << 0 | 34 << 8 | 4 << 16 | 12 << 24;
    assert_eq!(unsafe { *to_in_addr(&ip).S_un.S_addr() }, want);
    let mut addr: in_addr_S_un = unsafe { mem::zeroed() };
    unsafe { *(addr.S_addr_mut()) = want };
    assert_eq!(from_in_addr(IN_ADDR { S_un: addr }), ip);
}

#[test]
fn test_ipv6() {
    let ip = Ipv6Addr::new(0x2000, 1, 2, 3, 4, 5, 6, 7);
    assert_eq!(ip, from_in6_addr(to_in6_addr(&ip)));

    let ip = Ipv6Addr::new(0x2000, 1, 2, 3, 4, 5, 6, 7);
    let want = [
        0x2000u16.to_be(),
        1u16.to_be(),
        2u16.to_be(),
        3u16.to_be(),
        4u16.to_be(),
        5u16.to_be(),
        6u16.to_be(),
        7u16.to_be(),
    ];
    assert_eq!(unsafe { *to_in6_addr(&ip).u.Word() }, want);
    let mut addr: in6_addr_u = unsafe { mem::zeroed() };
    unsafe { *(addr.Word_mut()) = want };
    assert_eq!(from_in6_addr(IN6_ADDR { u: addr }), ip);
}
