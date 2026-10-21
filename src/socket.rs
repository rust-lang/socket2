Warning: truncated output (original token count: 23077)
Total output lines: 2537

// Copyright 2015 The Rust Project Developers.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::fmt;
use std::io::{self, Read, Write};
#[cfg(not(any(target_os = "redox", target_os = "wasi", target_os = "horizon")))]
use std::io::{IoSlice, IoSliceMut};
use std::mem::MaybeUninit;
#[cfg(not(any(target_os = "nuttx")))]
use std::net::Ipv6Addr;
use std::net::{self, Ipv4Addr, Shutdown};
#[cfg(any(unix, all(target_os = "wasi", not(target_env = "p1"))))]
use std::os::fd::{FromRawFd, IntoRawFd};
#[cfg(windows)]
use std::os::windows::io::{FromRawSocket, IntoRawSocket};
use std::time::Duration;

use crate::sys::{self, c_int, getsockopt, setsockopt, Bool};
#[cfg(all(unix, not(any(target_os = "redox", target_os = "horizon"))))]
use crate::MsgHdrMut;
use crate::{Domain, Protocol, SockAddr, TcpKeepalive, Type};
#[cfg(not(any(target_os = "redox", target_os = "wasi", target_os = "horizon")))]
use crate::{MaybeUninitSlice, MsgHdr, RecvFlags};

/// Owned wrapper around a system socket.
///
/// This type simply wraps an instance of a file descriptor (`c_int`) on Unix
/// and an instance of `SOCKET` on Windows. This is the main type exported by
/// this crate and is intended to mirror the raw semantics of sockets on
/// platforms as closely as possible. Almost all methods correspond to
/// precisely one libc or OS API call which is essentially just a "Rustic
/// translation" of what's below.
///
/// ## Converting to and from other types
///
/// This type can be freely converted into the network primitives provided by
/// the standard library, such as [`TcpStream`] or [`UdpSocket`], using the
/// [`From`] trait, see the example below.
///
/// [`TcpStream`]: std::net::TcpStream
/// [`UdpSocket`]: std::net::UdpSocket
///
/// # Notes
///
/// Some methods that set options on `Socket` require two system calls to set
/// their options without overwriting previously set options. We do this by
/// first getting the current settings, applying the desired changes, and then
/// updating the settings. This means that the operation is **not** atomic. This
/// can lead to a data race when two threads are changing options in parallel.
///
/// # Examples
/// ```no_run
/// # fn main() -> std::io::Result<()> {
/// use std::net::{SocketAddr, TcpListener};
/// use socket2::{Socket, Domain, Type};
///
/// // create a TCP listener
/// let socket = Socket::new(Domain::IPV6, Type::STREAM, None)?;
///
/// let address: SocketAddr = "[::1]:12345".parse().unwrap();
/// let address = address.into();
/// socket.bind(&address)?;
/// socket.listen(128)?;
///
/// let listener: TcpListener = socket.into();
/// // ...
/// # drop(listener);
/// # Ok(()) }
/// ```
pub struct Socket {
    inner: sys::Socket,
}

impl Socket {
    /// # Safety
    ///
    /// The caller must ensure `raw` is a valid file descriptor/socket. NOTE:
    /// this should really be marked `unsafe`, but this being an internal
    /// function, often passed as mapping function, it's makes it very
    /// inconvenient to mark it as `unsafe`.
    pub(crate) fn from_raw(raw: sys::RawSocket) -> Socket {
        Socket {
            // SAFETY: the caller must ensure that `raw` is a valid file
            // descriptor, but when it isn't it could return I/O errors, or
            // potentially close a fd it doesn't own. All of that isn't memory
            // unsafe, so it's not desired but never memory unsafe or causes UB.
            inner: unsafe { sys::socket_from_raw(raw) },
        }
    }

    pub(crate) fn as_raw(&self) -> sys::RawSocket {
        sys::socket_as_raw(&self.inner)
    }

    pub(crate) fn into_raw(self) -> sys::RawSocket {
        sys::socket_into_raw(self.inner)
    }

    /// Creates a new socket and sets common flags.
    ///
    /// This function corresponds to `socket(2)` on Unix and `WSASocketW` on
    /// Windows.
    ///
    /// On Unix-like systems, the close-on-exec flag is set on the new socket.
    /// Additionally, on Apple platforms `SOCK_NOSIGPIPE` is set. On Windows,
    /// the socket is made non-inheritable.
    ///
    /// [`Socket::new_raw`] can be used if you don't want these flags to be set.
    #[doc = man_links!(socket(2))]
    pub fn new(domain: Domain, ty: Type, protocol: Option<Protocol>) -> io::Result<Socket> {
        let ty = set_common_type(ty);
        Socket::new_raw(domain, ty, protocol).and_then(set_common_flags)
    }

    /// Creates a new socket ready to be configured.
    ///
    /// This function corresponds to `socket(2)` on Unix and `WSASocketW` on
    /// Windows and simply creates a new socket, no other configuration is done.
    pub fn new_raw(domain: Domain, ty: Type, protocol: Option<Protocol>) -> io::Result<Socket> {
        let protocol = protocol.map_or(0, |p| p.0);
        sys::socket(domain.0, ty.0, protocol).map(Socket::from_raw)
    }

    /// Creates a pair of sockets which are connected to each other.
    ///
    /// This function corresponds to `socketpair(2)`.
    ///
    /// This function sets the same flags as in done for [`Socket::new`],
    /// [`Socket::pair_raw`] can be used if you don't want to set those flags.
    #[doc = man_links!(unix: socketpair(2))]
    #[cfg(all(feature = "all", unix))]
    pub fn pair(
        domain: Domain,
        ty: Type,
        protocol: Option<Protocol>,
    ) -> io::Result<(Socket, Socket)> {
        let ty = set_common_type(ty);
        let (a, b) = Socket::pair_raw(domain, ty, protocol)?;
        let a = set_common_flags(a)?;
        let b = set_common_flags(b)?;
        Ok((a, b))
    }

    /// Creates a pair of sockets which are connected to each other.
    ///
    /// This function corresponds to `socketpair(2)`.
    #[cfg(all(feature = "all", unix))]
    pub fn pair_raw(
        domain: Domain,
        ty: Type,
        protocol: Option<Protocol>,
    ) -> io::Result<(Socket, Socket)> {
        let protocol = protocol.map_or(0, |p| p.0);
        sys::socketpair(domain.0, ty.0, protocol)
            .map(|[a, b]| (Socket::from_raw(a), Socket::from_raw(b)))
    }

    /// Binds this socket to the specified address.
    ///
    /// This function directly corresponds to the `bind(2)` function on Windows
    /// and Unix.
    #[doc = man_links!(bind(2))]
    pub fn bind(&self, address: &SockAddr) -> io::Result<()> {
        sys::bind(self.as_raw(), address)
    }

    /// Initiate a connection on this socket to the specified address.
    ///
    /// This function directly corresponds to the `connect(2)` function on
    /// Windows and Unix.
    ///
    /// An error will be returned if `listen` or `connect` has already been
    /// called on this builder.
    #[doc = man_links!(connect(2))]
    ///
    /// # Notes
    ///
    /// When using a non-blocking connect (by setting the socket into
    /// non-blocking mode before calling this function), socket option can't be
    /// set *while connecting*. This will cause errors on Windows. Socket
    /// options can be safely set before and after connecting the socket.
    ///
    /// On Cygwin, a Unix domain socket connect blocks until the server accepts
    /// it. If the behavior is not expected, try [`Socket::set_no_peercred`]
    /// (Cygwin only).
    #[allow(rustdoc::broken_intra_doc_links)] // Socket::set_no_peercred
    pub fn connect(&self, address: &SockAddr) -> io::Result<()> {
        sys::connect(self.as_raw(), address)
    }

    /// Initiate a connection on this socket to the specified address, only
    /// only waiting for a certain period of time for the connection to be
    /// established.
    ///
    /// Unlike many other methods on `Socket`, this does *not* correspond to a
    /// single C function. It sets the socket to nonblocking mode, connects via
    /// connect(2), and then waits for the connection to complete with poll(2)
    /// on Unix and select on Windows. When the connection is complete, the
    /// socket is set back to blocking mode. On Unix, this will loop over
    /// `EINTR` errors.
    ///
    /// # Warnings
    ///
    /// The non-blocking state of the socket is overridden by this function -
    /// it will be returned in blocking mode on success, and in an indeterminate
    /// state on failure.
    ///
    /// If the connection request times out, it may still be processing in the
    /// background - a second call to `connect` or `connect_timeout` may fail.
    pub fn connect_timeout(&self, addr: &SockAddr, timeout: Duration) -> io::Result<()> {
        self.set_nonblocking(true)?;
        let res = self.connect(addr);
        self.set_nonblocking(false)?;

        match res {
            Ok(()) => {
                // On Apple platforms (macOS, iOS, tvOS, watchOS, visionOS) a
                // non-blocking `connect(2)` may return success even though the
                // connection is not yet established, so we always fall through
                // to `poll_connect` to wait for the connection to complete.
                #[cfg(not(target_vendor = "apple"))]
                return Ok(());
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {}
            #[cfg(any(unix, all(target_os = "wasi", not(target_env = "p1"))))]
            Err(ref e) if e.raw_os_error() == Some(libc::EINPROGRESS) => {}
            Err(e) => return Err(e),
        }

        sys::poll_connect(self, timeout)
    }

    /// Mark a socket as ready to accept incoming connection requests using
    /// [`Socket::accept()`].
    ///
    /// This function directly corresponds to the `listen(2)` function on
    /// Windows and Unix.
    ///
    /// An error will be returned if `listen` or `connect` has already been
    /// called on this builder.
    #[doc = man_links!(listen(2))]
    pub fn listen(&self, backlog: c_int) -> io::Result<()> {
        sys::listen(self.as_raw(), backlog)
    }

    /// Accept a new incoming connection from this listener.
    ///
    /// This function uses `accept4(2)` on platforms that support it and
    /// `accept(2)` platforms that do not.
    ///
    /// This function sets the same flags as in done for [`Socket::new`],
    /// [`Socket::accept_raw`] can be used if you don't want to set those flags.
    #[doc = man_links!(accept(2))]
    ///
    /// # Notes
    ///
    /// On Cygwin, a Unix domain socket connect blocks until the server accepts
    /// it. If the behavior is not expected, try [`Socket::set_no_peercred`]
    /// (Cygwin only).
    #[allow(rustdoc::broken_intra_doc_links)] // Socket::set_no_peercred
    pub fn accept(&self) -> io::Result<(Socket, SockAddr)> {
        // Use `accept4` on platforms that support it.
        #[cfg(any(
            target_os = "android",
            target_os = "dragonfly",
            target_os = "freebsd",
            target_os = "fuchsia",
            target_os = "illumos",
            target_os = "linux",
            target_os = "netbsd",
            target_os = "openbsd",
            target_os = "cygwin",
        ))]
        return self._accept4(libc::SOCK_CLOEXEC);

        // Fall back to `accept` on platforms that do not support `accept4`.
        #[cfg(not(any(
            target_os = "android",
            target_os = "dragonfly",
            target_os = "freebsd",
            target_os = "fuchsia",
            target_os = "illumos",
            target_os = "linux",
            target_os = "netbsd",
            target_os = "openbsd",
            target_os = "cygwin",
        )))]
        {
            let (socket, addr) = self.accept_raw()?;
            let socket = set_common_accept_flags(socket)?;
            // `set_common_flags` does not disable inheritance on Windows because `Socket::new`
            // unlike `accept` is able to create the socket with inheritance disabled.
            #[cfg(windows)]
            socket._set_no_inherit(true)?;
            Ok((socket, addr))
        }
    }

    /// Accept a new incoming connection from this listener.
    ///
    /// This function directly corresponds to the `accept(2)` function on
    /// Windows and Unix.
    pub fn accept_raw(&self) -> io::Result<(Socket, SockAddr)> {
        sys::accept(self.as_raw()).map(|(inner, addr)| (Socket::from_raw(inner), addr))
    }

    /// Returns the socket address of the local half of this socket.
    ///
    /// This function directly corresponds to the `getsockname(2)` function on
    /// Windows and Unix.
    #[doc = man_links!(getsockname(2))]
    ///
    /// # Notes
    ///
    /// Depending on the OS this may return an error if the socket is not
    /// [bound].
    ///
    /// [bound]: Socket::bind
    pub fn local_addr(&self) -> io::Result<SockAddr> {
        sys::getsockname(self.as_raw())
    }

    /// Returns the socket address of the remote peer of this socket.
    ///
    /// This function directly corresponds to the `getpeername(2)` function on
    /// Windows and Unix.
    #[doc = man_links!(getpeername(2))]
    ///
    /// # Notes
    ///
    /// This returns an error if the socket is not [`connect`ed].
    ///
    /// [`connect`ed]: Socket::connect
    pub fn peer_addr(&self) -> io::Result<SockAddr> {
        sys::getpeername(self.as_raw())
    }

    /// Returns the [`Type`] of this socket by checking the `SO_TYPE` option on
    /// this socket.
    pub fn r#type(&self) -> io::Result<Type> {
        unsafe { getsockopt::<c_int>(self.as_raw(), sys::SOL_SOCKET, sys::SO_TYPE).map(Type) }
    }

    /// Creates a new independently owned handle to the underlying socket.
    ///
    /// # Notes
    ///
    /// On Unix this uses `F_DUPFD_CLOEXEC` and thus sets the `FD_CLOEXEC` on
    /// the returned socket.
    ///
    /// On Windows this uses `WSA_FLAG_NO_HANDLE_INHERIT` setting inheriting to
    /// false.
    ///
    /// On Windows this can **not** be used function cannot be used on a
    /// QOS-enabled socket, see
    /// <https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsaduplicatesocketw>.
    #[cfg(not(target_os = "wasi"))]
    pub fn try_clone(&self) -> io::Result<Socket> {
        sys::try_clone(self.as_raw()).map(Socket::from_raw)
    }

    /// Returns true if this socket is set to nonblocking mode, false otherwise.
    ///
    /// # Notes
    ///
    /// On Unix this corresponds to calling `fcntl` returning the value of
    /// `O_NONBLOCK`.
    ///
    /// On Windows it is not possible retrieve the nonblocking mode status.
    #[cfg(all(
        feature = "all",
        any(unix, all(target_os = "wasi", not(target_env = "p1")))
    ))]
    pub fn nonblocking(&self) -> io::Result<bool> {
        sys::nonblocking(self.as_raw())
    }

    /// Moves this socket into or out of nonblocking mode.
    ///
    /// # Notes
    ///
    /// On Unix this corresponds to calling `fcntl` (un)setting `O_NONBLOCK`.
    ///
    /// On Windows this corresponds to calling `ioctlsocket` (un)setting
    /// `FIONBIO`.
    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        sys::set_nonblocking(self.as_raw(), nonblocking)
    }

    /// Shuts down the read, write, or both halves of this connection.
    ///
    /// This function will cause all pending and future I/O on the specified
    /// portions to return immediately with an appropriate value.
    #[doc = man_links!(shutdown(2))]
    pub fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        sys::shutdown(self.as_raw(), how)
    }

    /// Receives data on the socket from the remote address to which it is
    /// connected.
    ///
    /// The [`connect`] method will connect this socket to a remote address.
    /// This method might fail if the socket is not connected.
    #[doc = man_links!(recv(2))]
    ///
    /// [`connect`]: Socket::connect
    ///
    /// # Safety
    ///
    /// Normally casting a `&mut [u8]` to `&mut [MaybeUni…15077 tokens truncated…> io::Result<()> {
        unsafe {
            setsockopt(
                self.as_raw(),
                sys::IPPROTO_IPV6,
                sys::IPV6_UNICAST_HOPS,
                hops as c_int,
            )
        }
    }

    /// Get the value of the `IPV6_MINHOPCOUNT` option for this socket.
    ///
    /// For more information about this option, see [`set_min_hopcount_v6`].
    ///
    /// [`set_min_hopcount_v6`]: Socket::set_min_hopcount_v6
    #[cfg(all(feature = "all", any(target_os = "linux", target_os = "illumos")))]
    pub fn min_hopcount_v6(&self) -> io::Result<u32> {
        unsafe {
            getsockopt::<c_int>(self.as_raw(), sys::IPPROTO_IPV6, sys::IPV6_MINHOPCOUNT)
                .map(|hops| hops as u32)
        }
    }

    /// Set the value of the `IPV6_MINHOPCOUNT` option for this socket.
    ///
    /// If enabled, received IPv6 packets are discarded if the value of the
    /// hop limit field of the IPv6 header is lower than the option value.
    #[cfg(all(feature = "all", any(target_os = "linux", target_os = "illumos")))]
    pub fn set_min_hopcount_v6(&self, hops: u32) -> io::Result<()> {
        unsafe {
            setsockopt(
                self.as_raw(),
                sys::IPPROTO_IPV6,
                sys::IPV6_MINHOPCOUNT,
                hops as c_int,
            )
        }
    }

    /// Get the value of the `IPV6_V6ONLY` option for this socket.
    ///
    /// For more information about this option, see [`set_only_v6`].
    ///
    /// [`set_only_v6`]: Socket::set_only_v6
    pub fn only_v6(&self) -> io::Result<bool> {
        unsafe {
            getsockopt::<Bool>(self.as_raw(), sys::IPPROTO_IPV6, sys::IPV6_V6ONLY)
                .map(|only_v6| only_v6 != 0)
        }
    }

    /// Set the value for the `IPV6_V6ONLY` option on this socket.
    ///
    /// If this is set to `true` then the socket is restricted to sending and
    /// receiving IPv6 packets only. In this case two IPv4 and IPv6 applications
    /// can bind the same port at the same time.
    ///
    /// If this is set to `false` then the socket can be used to send and
    /// receive packets from an IPv4-mapped IPv6 address.
    pub fn set_only_v6(&self, only_v6: bool) -> io::Result<()> {
        unsafe {
            setsockopt(
                self.as_raw(),
                sys::IPPROTO_IPV6,
                sys::IPV6_V6ONLY,
                only_v6 as c_int,
            )
        }
    }

    /// Get the value of the `IPV6_RECVTCLASS` option for this socket.
    ///
    /// For more information about this option, see [`set_recv_tclass_v6`].
    ///
    /// [`set_recv_tclass_v6`]: Socket::set_recv_tclass_v6
    #[cfg(not(any(
        target_os = "dragonfly",
        target_os = "fuchsia",
        target_os = "illumos",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "redox",
        target_os = "solaris",
        target_os = "haiku",
        target_os = "hurd",
        target_os = "espidf",
        target_os = "nuttx",
        target_os = "vita",
        target_os = "wasi",
        target_os = "horizon"
    )))]
    pub fn recv_tclass_v6(&self) -> io::Result<bool> {
        unsafe {
            getsockopt::<c_int>(self.as_raw(), sys::IPPROTO_IPV6, sys::IPV6_RECVTCLASS)
                .map(|recv_tclass| recv_tclass > 0)
        }
    }

    /// Set the value of the `IPV6_RECVTCLASS` option for this socket.
    ///
    /// If enabled, the `IPV6_TCLASS` ancillary message is passed with incoming
    /// packets. It contains a byte which specifies the traffic class field of
    /// the packet header.
    #[cfg(not(any(
        target_os = "dragonfly",
        target_os = "fuchsia",
        target_os = "illumos",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "redox",
        target_os = "solaris",
        target_os = "haiku",
        target_os = "hurd",
        target_os = "espidf",
        target_os = "nuttx",
        target_os = "vita",
        target_os = "wasi",
        target_os = "horizon"
    )))]
    pub fn set_recv_tclass_v6(&self, recv_tclass: bool) -> io::Result<()> {
        unsafe {
            setsockopt(
                self.as_raw(),
                sys::IPPROTO_IPV6,
                sys::IPV6_RECVTCLASS,
                recv_tclass as c_int,
            )
        }
    }

    /// Get the value of the `IPV6_RECVHOPLIMIT` option for this socket.
    ///
    /// For more information about this option, see [`set_recv_hoplimit_v6`].
    ///
    /// [`set_recv_hoplimit_v6`]: Socket::set_recv_hoplimit_v6
    #[cfg(all(
        feature = "all",
        not(any(
            windows,
            target_os = "dragonfly",
            target_os = "fuchsia",
            target_os = "illumos",
            target_os = "netbsd",
            target_os = "openbsd",
            target_os = "redox",
            target_os = "solaris",
            target_os = "haiku",
            target_os = "hurd",
            target_os = "espidf",
            target_os = "vita",
            target_os = "cygwin",
            target_os = "wasi",
            target_os = "horizon"
        ))
    ))]
    pub fn recv_hoplimit_v6(&self) -> io::Result<bool> {
        unsafe {
            getsockopt::<c_int>(self.as_raw(), sys::IPPROTO_IPV6, sys::IPV6_RECVHOPLIMIT)
                .map(|recv_hoplimit| recv_hoplimit > 0)
        }
    }
    /// Set the value of the `IPV6_RECVHOPLIMIT` option for this socket.
    ///
    /// The received hop limit is returned as ancillary data by recvmsg()
    /// only if the application has enabled the IPV6_RECVHOPLIMIT socket
    /// option:
    #[cfg(all(
        feature = "all",
        not(any(
            windows,
            target_os = "dragonfly",
            target_os = "fuchsia",
            target_os = "illumos",
            target_os = "netbsd",
            target_os = "openbsd",
            target_os = "redox",
            target_os = "solaris",
            target_os = "haiku",
            target_os = "hurd",
            target_os = "espidf",
            target_os = "vita",
            target_os = "cygwin",
            target_os = "wasi",
            target_os = "horizon"
        ))
    ))]
    pub fn set_recv_hoplimit_v6(&self, recv_hoplimit: bool) -> io::Result<()> {
        unsafe {
            setsockopt(
                self.as_raw(),
                sys::IPPROTO_IPV6,
                sys::IPV6_RECVHOPLIMIT,
                recv_hoplimit as c_int,
            )
        }
    }

    /// Get the value for the `IP6T_SO_ORIGINAL_DST` option on this socket.
    #[cfg(all(
        feature = "all",
        any(target_os = "android", target_os = "linux", target_os = "windows")
    ))]
    pub fn original_dst_v6(&self) -> io::Result<SockAddr> {
        sys::original_dst_v6(self.as_raw())
    }
}

/// Socket options for TCP sockets, get/set using `IPPROTO_TCP`.
///
/// Additional documentation can be found in documentation of the OS.
/// * Linux: <https://man7.org/linux/man-pages/man7/tcp.7.html>
/// * Windows: <https://docs.microsoft.com/en-us/windows/win32/winsock/ipproto-tcp-socket-options>
impl Socket {
    /// Get the value of the `TCP_KEEPIDLE` option on this socket.
    ///
    /// This returns the value of `TCP_KEEPALIVE` on macOS and iOS and `TCP_KEEPIDLE` on all other
    /// supported Unix operating systems.
    #[cfg(all(
        feature = "all",
        not(any(
            windows,
            target_os = "haiku",
            target_os = "openbsd",
            target_os = "vita"
        ))
    ))]
    pub fn tcp_keepalive_time(&self) -> io::Result<Duration> {
        sys::tcp_keepalive_time(self.as_raw())
    }

    /// Get the value of the `TCP_KEEPINTVL` option on this socket.
    ///
    /// For more information about this option, see [`set_tcp_keepalive`].
    ///
    /// [`set_tcp_keepalive`]: Socket::set_tcp_keepalive
    #[cfg(all(
        feature = "all",
        any(
            target_os = "android",
            target_os = "dragonfly",
            target_os = "emscripten",
            target_os = "freebsd",
            target_os = "fuchsia",
            target_os = "illumos",
            target_os = "ios",
            target_os = "visionos",
            target_os = "linux",
            target_os = "macos",
            target_os = "netbsd",
            target_os = "tvos",
            target_os = "watchos",
            target_os = "cygwin",
            target_os = "nuttx",
            all(target_os = "wasi", not(target_env = "p1")),
        )
    ))]
    pub fn tcp_keepalive_interval(&self) -> io::Result<Duration> {
        unsafe {
            getsockopt::<c_int>(self.as_raw(), sys::IPPROTO_TCP, sys::TCP_KEEPINTVL)
                .map(|secs| Duration::from_secs(secs as u64))
        }
    }

    /// Get the value of the `TCP_KEEPCNT` option on this socket.
    ///
    /// For more information about this option, see [`set_tcp_keepalive`].
    ///
    /// [`set_tcp_keepalive`]: Socket::set_tcp_keepalive
    #[cfg(all(
        feature = "all",
        any(
            target_os = "android",
            target_os = "dragonfly",
            target_os = "emscripten",
            target_os = "freebsd",
            target_os = "fuchsia",
            target_os = "illumos",
            target_os = "ios",
            target_os = "visionos",
            target_os = "linux",
            target_os = "macos",
            target_os = "netbsd",
            target_os = "tvos",
            target_os = "watchos",
            target_os = "cygwin",
            target_os = "windows",
            target_os = "nuttx",
            all(target_os = "wasi", not(target_env = "p1")),
        )
    ))]
    pub fn tcp_keepalive_retries(&self) -> io::Result<u32> {
        unsafe {
            getsockopt::<c_int>(self.as_raw(), sys::IPPROTO_TCP, sys::TCP_KEEPCNT)
                .map(|retries| retries as u32)
        }
    }

    /// Set parameters configuring TCP keepalive probes for this socket.
    ///
    /// The supported parameters depend on the operating system, and are
    /// configured using the [`TcpKeepalive`] struct. At a minimum, all systems
    /// support configuring the [keepalive time]: the time after which the OS
    /// will start sending keepalive messages on an idle connection.
    ///
    /// [keepalive time]: TcpKeepalive::with_time
    ///
    /// # Notes
    ///
    /// * This will enable `SO_KEEPALIVE` on this socket, if it is not already
    ///   enabled.
    /// * On some platforms, such as Windows, any keepalive parameters *not*
    ///   configured by the `TcpKeepalive` struct passed to this function may be
    ///   overwritten with their default values. Therefore, this function should
    ///   either only be called once per socket, or the same parameters should
    ///   be passed every time it is called.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::time::Duration;
    ///
    /// use socket2::{Socket, TcpKeepalive, Domain, Type};
    ///
    /// # fn main() -> std::io::Result<()> {
    /// let socket = Socket::new(Domain::IPV4, Type::STREAM, None)?;
    /// let keepalive = TcpKeepalive::new()
    ///     .with_time(Duration::from_secs(4));
    ///     // Depending on the target operating system, we may also be able to
    ///     // configure the keepalive probe interval and/or the number of
    ///     // retries here as well.
    ///
    /// socket.set_tcp_keepalive(&keepalive)?;
    /// # Ok(()) }
    /// ```
    ///
    pub fn set_tcp_keepalive(&self, params: &TcpKeepalive) -> io::Result<()> {
        self.set_keepalive(true)?;
        sys::set_tcp_keepalive(self.as_raw(), params)
    }

    /// Get the value of the `TCP_NODELAY` option on this socket.
    ///
    /// For more information about this option, see [`set_tcp_nodelay`].
    ///
    /// [`set_tcp_nodelay`]: Socket::set_tcp_nodelay
    pub fn tcp_nodelay(&self) -> io::Result<bool> {
        unsafe {
            getsockopt::<Bool>(self.as_raw(), sys::IPPROTO_TCP, sys::TCP_NODELAY)
                .map(|nodelay| nodelay != 0)
        }
    }

    /// Set the value of the `TCP_NODELAY` option on this socket.
    ///
    /// If set, this option disables the Nagle algorithm. This means that
    /// segments are always sent as soon as possible, even if there is only a
    /// small amount of data. When not set, data is buffered until there is a
    /// sufficient amount to send out, thereby avoiding the frequent sending of
    /// small packets.
    pub fn set_tcp_nodelay(&self, nodelay: bool) -> io::Result<()> {
        unsafe {
            setsockopt(
                self.as_raw(),
                sys::IPPROTO_TCP,
                sys::TCP_NODELAY,
                nodelay as c_int,
            )
        }
    }

    /// On Windows this invokes the `SIO_TCP_SET_ACK_FREQUENCY` IOCTL which
    /// configures the number of TCP segments that must be received before
    /// the delayed ACK timer is ignored.
    #[cfg(all(feature = "all", windows))]
    pub fn set_tcp_ack_frequency(&self, frequency: u8) -> io::Result<()> {
        sys::set_tcp_ack_frequency(self.as_raw(), frequency)
    }
}

impl Read for Socket {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // Safety: the `recv` implementation promises not to write uninitialised
        // bytes to the `buf`fer, so this casting is safe.
        let buf = unsafe { &mut *(buf as *mut [u8] as *mut [MaybeUninit<u8>]) };
        self.recv(buf)
    }

    #[cfg(not(any(target_os = "redox", target_os = "wasi", target_os = "horizon")))]
    fn read_vectored(&mut self, bufs: &mut [IoSliceMut<'_>]) -> io::Result<usize> {
        // Safety: both `IoSliceMut` and `MaybeUninitSlice` promise to have the
        // same layout, that of `iovec`/`WSABUF`. Furthermore, `recv_vectored`
        // promises to not write uninitialised bytes to the `bufs` and pass it
        // directly to the `recvmsg` system call, so this is safe.
        let bufs = unsafe { &mut *(bufs as *mut [IoSliceMut<'_>] as *mut [MaybeUninitSlice<'_>]) };
        self.recv_vectored(bufs).map(|(n, _)| n)
    }
}

impl<'a> Read for &'a Socket {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // Safety: see other `Read::read` impl.
        let buf = unsafe { &mut *(buf as *mut [u8] as *mut [MaybeUninit<u8>]) };
        self.recv(buf)
    }

    #[cfg(not(any(target_os = "redox", target_os = "wasi", target_os = "horizon")))]
    fn read_vectored(&mut self, bufs: &mut [IoSliceMut<'_>]) -> io::Result<usize> {
        // Safety: see other `Read::read` impl.
        let bufs = unsafe { &mut *(bufs as *mut [IoSliceMut<'_>] as *mut [MaybeUninitSlice<'_>]) };
        self.recv_vectored(bufs).map(|(n, _)| n)
    }
}

impl Write for Socket {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.send(buf)
    }

    #[cfg(not(any(target_os = "redox", target_os = "wasi", target_os = "horizon")))]
    fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        self.send_vectored(bufs)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> Write for &'a Socket {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.send(buf)
    }

    #[cfg(not(any(target_os = "redox", target_os = "wasi", target_os = "horizon")))]
    fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        self.send_vectored(bufs)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl fmt::Debug for Socket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Socket")
            .field("raw", &self.as_raw())
            .field("local_addr", &self.local_addr().ok())
            .field("peer_addr", &self.peer_addr().ok())
            .finish()
    }
}

from!(net::TcpStream, Socket);
from!(net::TcpListener, Socket);
from!(net::UdpSocket, Socket);
from!(Socket, net::TcpStream);
from!(Socket, net::TcpListener);
from!(Socket, net::UdpSocket);
