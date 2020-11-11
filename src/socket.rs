// Copyright 2015 The Rust Project Developers.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::fmt;
use std::io::{self, Read, Write};
#[cfg(not(target_os = "redox"))]
use std::io::{IoSlice, IoSliceMut};
use std::net::{self, Ipv4Addr, Ipv6Addr, Shutdown};
#[cfg(all(feature = "all", unix))]
use std::os::unix::net::{UnixDatagram, UnixListener, UnixStream};
use std::time::Duration;

use crate::sys;
#[cfg(not(target_os = "redox"))]
use crate::RecvFlags;
use crate::{Domain, Protocol, SockAddr, Type};

/// Owned wrapper around a system socket.
///
/// This type simply wraps an instance of a file descriptor (`c_int`) on Unix
/// and an instance of `SOCKET` on Windows. This is the main type exported by
/// this crate and is intended to mirror the raw semantics of sockets on
/// platforms as closely as possible. Almost all methods correspond to
/// precisely one libc or OS API call which is essentially just a "Rustic
/// translation" of what's below.
///
/// This type can be freely converted into the network primitives provided by
/// the standard library, such as [`TcpStream`] or [`UdpSocket`], using the
/// [`Into`] trait, see the example below.
///
/// [`TcpStream`]: std::net::TcpStream
/// [`UdpSocket`]: std::net::UdpSocket
///
/// # Notes
///
/// Some methods that set options on `Socket` require two system calls to set
/// there options without overwriting previously set options. We do this by
/// first getting the current settings, applying the desired changes and than
/// updating the settings. This means that the operation is **not** atomic. This
/// can lead to a data race when two threads are changing options in parallel.
///
/// # Examples
///
/// Creating a new socket setting all advisable flags.
///
#[cfg_attr(feature = "all", doc = "```")] // Protocol::cloexec requires the `all` feature.
#[cfg_attr(not(feature = "all"), doc = "```ignore")]
/// # fn main() -> std::io::Result<()> {
/// use socket2::{Protocol, Domain, Type, Socket};
///
/// let domain = Domain::IPV4;
/// let ty = Type::STREAM;
/// let protocol = Protocol::TCP;
///
/// // On platforms that support it set `SOCK_CLOEXEC`.
/// #[cfg(any(target_os = "android", target_os = "dragonfly", target_os = "freebsd", target_os = "linux", target_os = "netbsd", target_os = "openbsd"))]
/// let ty = ty.cloexec();
///
/// // On windows set `WSA_FLAG_NO_HANDLE_INHERIT`.
/// #[cfg(windows)]
/// let ty = ty.no_inherit();
///
/// let socket = Socket::new(domain, ty, Some(protocol))?;
///
/// // On platforms that don't support `SOCK_CLOEXEC`, use `FD_CLOEXEC`.
/// #[cfg(all(not(windows), not(any(target_os = "android", target_os = "dragonfly", target_os = "freebsd", target_os = "linux", target_os = "netbsd", target_os = "openbsd"))))]
/// socket.set_cloexec(true)?;
///
/// // On macOS and iOS set `NOSIGPIPE`.
/// #[cfg(target_vendor = "apple")]
/// socket.set_nosigpipe(true)?;
///
/// # drop(socket);
/// # Ok(())
/// # }
/// ```
///
/// ```no_run
/// # fn main() -> std::io::Result<()> {
/// use std::net::{SocketAddr, TcpListener};
/// use socket2::{Socket, Domain, Type};
///
/// // create a TCP listener bound to two addresses
/// let socket = Socket::new(Domain::IPV4, Type::STREAM, None)?;
///
/// let address: SocketAddr = "[::1]:12345".parse().unwrap();
/// let address = address.into();
/// socket.bind(&address)?;
/// socket.bind(&address)?;
/// socket.listen(128)?;
///
/// let listener: TcpListener = socket.into();
/// // ...
/// # drop(listener);
/// # Ok(()) }
/// ```
pub struct Socket {
    // The `sys` module most have access to the socket.
    pub(crate) inner: sys::SysSocket,
}

impl Socket {
    /// Creates a new socket ready to be configured.
    ///
    /// This function corresponds to `socket(2)` on Unix and `WSASocketW` on
    /// Windows and simply creates a new socket, no other configuration is done
    /// and further functions must be invoked to configure this socket.
    ///
    /// # Notes
    ///
    /// The standard library sets the `CLOEXEC` flag on Unix on sockets, this
    /// function does **not** do this, but its advisable. On supported platforms
    /// [`Type::cloexec`] can be used for this, or by using
    /// [`Socket::set_cloexec`].
    ///
    /// Furthermore on macOS and iOS `NOSIGPIPE` is not set, this can be done
    /// using [`Socket::set_nosigpipe`].
    ///
    /// Similarly on Windows the `HANDLE_FLAG_INHERIT` is **not** set to zero,
    /// but again in most cases its advisable to do so. This can be doing using
    /// [`Socket::set_no_inherit`].
    ///
    /// See the `Socket` documentation for a full example of setting all the
    /// above mentioned flags.
    pub fn new(domain: Domain, ty: Type, protocol: Option<Protocol>) -> io::Result<Socket> {
        let protocol = protocol.map(|p| p.0).unwrap_or(0);
        sys::socket(domain.0, ty.0, protocol).map(|inner| Socket { inner })
    }

    /// Creates a pair of sockets which are connected to each other.
    ///
    /// This function corresponds to `socketpair(2)`.
    ///
    /// # Notes
    ///
    /// Much like [`Socket::new`] this doesn't set any flags, which might be
    /// advisable.
    ///
    /// This function is only available on Unix.
    #[cfg(all(feature = "all", unix))]
    pub fn pair(
        domain: Domain,
        ty: Type,
        protocol: Option<Protocol>,
    ) -> io::Result<(Socket, Socket)> {
        let protocol = protocol.map(|p| p.0).unwrap_or(0);
        sys::socketpair(domain.0, ty.0, protocol)
            .map(|fds| (Socket { inner: fds[0] }, Socket { inner: fds[1] }))
    }

    /// Binds this socket to the specified address.
    ///
    /// This function directly corresponds to the `bind(2)` function on Windows
    /// and Unix.
    pub fn bind(&self, address: &SockAddr) -> io::Result<()> {
        sys::bind(self.inner, address)
    }

    /// Initiate a connection on this socket to the specified address.
    ///
    /// This function directly corresponds to the `connect(2)` function on
    /// Windows and Unix.
    ///
    /// An error will be returned if `listen` or `connect` has already been
    /// called on this builder.
    ///
    /// # Notes
    ///
    /// When using a non-blocking connect (by setting the socket into
    /// non-blocking mode before calling this function), socket option can't be
    /// set *while connecting*. This will cause errors on Windows. Socket
    /// options can be safely set before and after connecting the socket.
    pub fn connect(&self, address: &SockAddr) -> io::Result<()> {
        sys::connect(self.inner, address)
    }

    /// Mark a socket as ready to accept incoming connection requests using
    /// [`Socket::accept()`].
    ///
    /// This function directly corresponds to the `listen(2)` function on
    /// Windows and Unix.
    ///
    /// An error will be returned if `listen` or `connect` has already been
    /// called on this builder.
    pub fn listen(&self, backlog: i32) -> io::Result<()> {
        sys::listen(self.inner, backlog)
    }

    /// Accept a new incoming connection from this listener.
    ///
    /// This function directly corresponds to the `accept(2)` function on
    /// Windows and Unix.
    ///
    /// This function will block the calling thread until a new connection is
    /// established. When established, the corresponding `Socket` and the
    /// remote peer's address will be returned.
    ///
    /// # Notes
    ///
    /// Like [`Socket::new`] this will not set any flags. If that is desirable,
    /// e.g. setting `CLOEXEC`, [`Socket::accept4`] can be used on supported
    /// OSes or [`Socket::set_cloexec`] can be called.
    pub fn accept(&self) -> io::Result<(Socket, SockAddr)> {
        sys::accept(self.inner).map(|(inner, addr)| (Socket { inner }, addr))
    }

    /// Returns the socket address of the local half of this socket.
    ///
    /// # Notes
    ///
    /// Depending on the OS this may return an error if the socket is not
    /// [bound].
    ///
    /// [bound]: Socket::bind
    pub fn local_addr(&self) -> io::Result<SockAddr> {
        sys::getsockname(self.inner)
    }

    /// Returns the socket address of the remote peer of this socket.
    ///
    /// # Notes
    ///
    /// This returns an error if the socket is not [`connect`ed].
    ///
    /// [`connect`ed]: Socket::connect
    pub fn peer_addr(&self) -> io::Result<SockAddr> {
        sys::getpeername(self.inner)
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
    pub fn try_clone(&self) -> io::Result<Socket> {
        sys::try_clone(self.inner).map(|inner| Socket { inner })
    }

    /// Get the value of the `SO_ERROR` option on this socket.
    ///
    /// This will retrieve the stored error in the underlying socket, clearing
    /// the field in the process. This can be useful for checking errors between
    /// calls.
    pub fn take_error(&self) -> io::Result<Option<io::Error>> {
        sys::take_error(self.inner)
    }

    /// Moves this TCP stream into or out of nonblocking mode.
    ///
    /// # Notes
    ///
    /// On Unix this corresponds to calling `fcntl` (un)setting `O_NONBLOCK`.
    ///
    /// On Windows this corresponds to calling `ioctlsocket` (un)setting
    /// `FIONBIO`.
    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        sys::set_nonblocking(self.inner, nonblocking)
    }

    /// Shuts down the read, write, or both halves of this connection.
    ///
    /// This function will cause all pending and future I/O on the specified
    /// portions to return immediately with an appropriate value.
    pub fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        sys::shutdown(self.inner, how)
    }

    /// Receives data on the socket from the remote address to which it is
    /// connected.
    ///
    /// The [`connect`] method will connect this socket to a remote address.
    /// This method might fail if the socket is not connected.
    ///
    /// [`connect`]: Socket::connect
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.recv_with_flags(buf, 0)
    }

    /// Receives out-of-band (OOB) data on the socket from the remote address to
    /// which it is connected by setting the `MSG_OOB` flag for this call.
    ///
    /// For more information, see [`recv`], [`out_of_band_inline`].
    ///
    /// [`recv`]: Socket::recv
    /// [`out_of_band_inline`]: Socket::out_of_band_inline
    #[cfg(all(feature = "all", not(target_os = "redox")))]
    pub fn recv_out_of_band(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.recv_with_flags(buf, sys::MSG_OOB)
    }

    /// Identical to [`recv`] but allows for specification of arbitrary flags to
    /// the underlying `recv` call.
    ///
    /// [`recv`]: Socket::recv
    pub fn recv_with_flags(&self, buf: &mut [u8], flags: sys::c_int) -> io::Result<usize> {
        sys::recv(self.inner, buf, flags)
    }

    /// Receives data on the socket from the remote address to which it is
    /// connected. Unlike [`recv`] that allows passing multiple buffers.
    ///
    /// The [`connect`] method will connect this socket to a remote address.
    /// This method might fail if the socket is not connected.
    ///
    /// In addition to the number of bytes read, this function returns the flags
    /// for the received message. See [`RecvFlags`] for more information about
    /// the returned flags.
    ///
    /// [`recv`]: Socket::recv
    /// [`connect`]: Socket::connect
    #[cfg(not(target_os = "redox"))]
    pub fn recv_vectored(&self, bufs: &mut [IoSliceMut<'_>]) -> io::Result<(usize, RecvFlags)> {
        self.recv_vectored_with_flags(bufs, 0)
    }

    /// Identical to [`recv_vectored`] but allows for specification of arbitrary
    /// flags to the underlying `recvmsg`/`WSARecv` call.
    ///
    /// [`recv_vectored`]: Socket::recv_vectored
    #[cfg(not(target_os = "redox"))]
    pub fn recv_vectored_with_flags(
        &self,
        bufs: &mut [IoSliceMut<'_>],
        flags: i32,
    ) -> io::Result<(usize, RecvFlags)> {
        sys::recv_vectored(self.inner, bufs, flags)
    }

    /// Receives data on the socket from the remote adress to which it is
    /// connected, without removing that data from the queue. On success,
    /// returns the number of bytes peeked.
    ///
    /// Successive calls return the same data. This is accomplished by passing
    /// `MSG_PEEK` as a flag to the underlying `recv` system call.
    pub fn peek(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.recv_with_flags(buf, sys::MSG_PEEK)
    }

    /// Receives data from the socket. On success, returns the number of bytes
    /// read and the address from whence the data came.
    pub fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SockAddr)> {
        self.recv_from_with_flags(buf, 0)
    }

    /// Identical to [`recv_from`] but allows for specification of arbitrary
    /// flags to the underlying `recvfrom` call.
    ///
    /// [`recv_from`]: Socket::recv_from
    pub fn recv_from_with_flags(
        &self,
        buf: &mut [u8],
        flags: i32,
    ) -> io::Result<(usize, SockAddr)> {
        sys::recv_from(self.inner, buf, flags)
    }

    /// Identical to [`recv_from_with_flags`] but reads into a slice of buffers.
    ///
    /// In addition to the number of bytes read, this function returns the flags for the received message.
    /// See [`RecvFlags`] for more information about the flags.
    ///
    /// [`recv_from_with_flags`]: #method.recv_from_with_flags
    #[cfg(not(target_os = "redox"))]
    pub fn recv_from_vectored(
        &self,
        bufs: &mut [IoSliceMut<'_>],
        flags: i32,
    ) -> io::Result<(usize, RecvFlags, SockAddr)> {
        self.inner().recv_from_vectored(bufs, flags)
    }

    /// Receives data from the socket, without removing it from the queue.
    ///
    /// Successive calls return the same data. This is accomplished by passing
    /// `MSG_PEEK` as a flag to the underlying `recvfrom` system call.
    ///
    /// On success, returns the number of bytes peeked and the address from
    /// whence the data came.
    pub fn peek_from(&self, buf: &mut [u8]) -> io::Result<(usize, SockAddr)> {
        self.inner().peek_from(buf)
    }

    /// Sends data on the socket to a connected peer.
    ///
    /// This is typically used on TCP sockets or datagram sockets which have
    /// been connected.
    ///
    /// On success returns the number of bytes that were sent.
    pub fn send(&self, buf: &[u8]) -> io::Result<usize> {
        self.inner().send(buf, 0)
    }

    /// Identical to [`send`] but allows for specification of arbitrary flags to the underlying
    /// `send` call.
    ///
    /// [`send`]: #method.send
    pub fn send_with_flags(&self, buf: &[u8], flags: i32) -> io::Result<usize> {
        self.inner().send(buf, flags)
    }

    /// Identical to [`send_with_flags`] but writes from a slice of buffers.
    ///
    /// [`send_with_flags`]: #method.send_with_flags
    #[cfg(not(target_os = "redox"))]
    pub fn send_vectored(&self, bufs: &[IoSlice<'_>], flags: i32) -> io::Result<usize> {
        self.inner().send_vectored(bufs, flags)
    }

    /// Sends out-of-band (OOB) data on the socket to connected peer
    /// by setting the `MSG_OOB` flag for this call.
    ///
    /// For more information, see [`send`], [`out_of_band_inline`].
    ///
    /// [`send`]: #method.send
    /// [`out_of_band_inline`]: #method.out_of_band_inline
    #[cfg(all(feature = "all", not(target_os = "redox")))]
    pub fn send_out_of_band(&self, buf: &[u8]) -> io::Result<usize> {
        self.inner().send(buf, sys::MSG_OOB)
    }

    /// Sends data on the socket to the given address. On success, returns the
    /// number of bytes written.
    ///
    /// This is typically used on UDP or datagram-oriented sockets. On success
    /// returns the number of bytes that were sent.
    pub fn send_to(&self, buf: &[u8], addr: &SockAddr) -> io::Result<usize> {
        self.inner().send_to(buf, 0, addr)
    }

    /// Identical to [`send_to`] but allows for specification of arbitrary flags to the underlying
    /// `sendto` call.
    ///
    /// [`send_to`]: #method.send_to
    pub fn send_to_with_flags(&self, buf: &[u8], addr: &SockAddr, flags: i32) -> io::Result<usize> {
        self.inner().send_to(buf, flags, addr)
    }

    /// Identical to [`send_with_flags`] but writes from a slice of buffers.
    ///
    /// [`send_with_flags`]: #method.send_with_flags
    #[cfg(not(target_os = "redox"))]
    pub fn send_to_vectored(
        &self,
        bufs: &[IoSlice<'_>],
        addr: &SockAddr,
        flags: i32,
    ) -> io::Result<usize> {
        self.inner().send_to_vectored(bufs, flags, addr)
    }

    // ================================================

    /// Gets the value of the `IP_TTL` option for this socket.
    ///
    /// For more information about this option, see [`set_ttl`][link].
    ///
    /// [link]: #method.set_ttl
    pub fn ttl(&self) -> io::Result<u32> {
        self.inner().ttl()
    }

    /// Sets the value for the `IP_TTL` option on this socket.
    ///
    /// This value sets the time-to-live field that is used in every packet sent
    /// from this socket.
    pub fn set_ttl(&self, ttl: u32) -> io::Result<()> {
        self.inner().set_ttl(ttl)
    }

    /// Sets the value for the `SO_MARK` option on this socket.
    ///
    /// This value sets the socket mark field for each packet sent through
    /// this socket. Changing the mark can be used for mark-based routing
    /// without netfilter or for packet filtering.
    ///
    /// This function is only available on Unix and requires the
    /// `CAP_NET_ADMIN` capability.
    #[cfg(target_os = "linux")]
    pub fn set_mark(&self, mark: u32) -> io::Result<()> {
        self.inner().set_mark(mark)
    }

    /// Gets the value of the `IPV6_UNICAST_HOPS` option for this socket.
    ///
    /// Specifies the hop limit for ipv6 unicast packets
    pub fn unicast_hops_v6(&self) -> io::Result<u32> {
        self.inner().unicast_hops_v6()
    }

    /// Sets the value for the `IPV6_UNICAST_HOPS` option on this socket.
    ///
    /// Specifies the hop limit for ipv6 unicast packets
    pub fn set_unicast_hops_v6(&self, ttl: u32) -> io::Result<()> {
        self.inner().set_unicast_hops_v6(ttl)
    }

    /// Gets the value of the `IPV6_V6ONLY` option for this socket.
    ///
    /// For more information about this option, see [`set_only_v6`][link].
    ///
    /// [link]: #method.set_only_v6
    pub fn only_v6(&self) -> io::Result<bool> {
        self.inner().only_v6()
    }

    /// Sets the value for the `IPV6_V6ONLY` option on this socket.
    ///
    /// If this is set to `true` then the socket is restricted to sending and
    /// receiving IPv6 packets only. In this case two IPv4 and IPv6 applications
    /// can bind the same port at the same time.
    ///
    /// If this is set to `false` then the socket can be used to send and
    /// receive packets from an IPv4-mapped IPv6 address.
    pub fn set_only_v6(&self, only_v6: bool) -> io::Result<()> {
        self.inner().set_only_v6(only_v6)
    }

    /// Returns the read timeout of this socket.
    ///
    /// If the timeout is `None`, then `read` calls will block indefinitely.
    pub fn read_timeout(&self) -> io::Result<Option<Duration>> {
        self.inner().read_timeout()
    }

    /// Sets the read timeout to the timeout specified.
    ///
    /// If the value specified is `None`, then `read` calls will block
    /// indefinitely. It is an error to pass the zero `Duration` to this
    /// method.
    pub fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.inner().set_read_timeout(dur)
    }

    /// Returns the write timeout of this socket.
    ///
    /// If the timeout is `None`, then `write` calls will block indefinitely.
    pub fn write_timeout(&self) -> io::Result<Option<Duration>> {
        self.inner().write_timeout()
    }

    /// Sets the write timeout to the timeout specified.
    ///
    /// If the value specified is `None`, then `write` calls will block
    /// indefinitely. It is an error to pass the zero `Duration` to this
    /// method.
    pub fn set_write_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.inner().set_write_timeout(dur)
    }

    /// Gets the value of the `TCP_NODELAY` option on this socket.
    ///
    /// For more information about this option, see [`set_nodelay`][link].
    ///
    /// [link]: #method.set_nodelay
    pub fn nodelay(&self) -> io::Result<bool> {
        self.inner().nodelay()
    }

    /// Sets the value of the `TCP_NODELAY` option on this socket.
    ///
    /// If set, this option disables the Nagle algorithm. This means that
    /// segments are always sent as soon as possible, even if there is only a
    /// small amount of data. When not set, data is buffered until there is a
    /// sufficient amount to send out, thereby avoiding the frequent sending of
    /// small packets.
    pub fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        self.inner().set_nodelay(nodelay)
    }

    /// Sets the value of the `SO_BROADCAST` option for this socket.
    ///
    /// When enabled, this socket is allowed to send packets to a broadcast
    /// address.
    pub fn broadcast(&self) -> io::Result<bool> {
        self.inner().broadcast()
    }

    /// Gets the value of the `SO_BROADCAST` option for this socket.
    ///
    /// For more information about this option, see
    /// [`set_broadcast`][link].
    ///
    /// [link]: #method.set_broadcast
    pub fn set_broadcast(&self, broadcast: bool) -> io::Result<()> {
        self.inner().set_broadcast(broadcast)
    }

    /// Gets the value of the `IP_MULTICAST_LOOP` option for this socket.
    ///
    /// For more information about this option, see
    /// [`set_multicast_loop_v4`][link].
    ///
    /// [link]: #method.set_multicast_loop_v4
    pub fn multicast_loop_v4(&self) -> io::Result<bool> {
        self.inner().multicast_loop_v4()
    }

    /// Sets the value of the `IP_MULTICAST_LOOP` option for this socket.
    ///
    /// If enabled, multicast packets will be looped back to the local socket.
    /// Note that this may not have any affect on IPv6 sockets.
    pub fn set_multicast_loop_v4(&self, multicast_loop_v4: bool) -> io::Result<()> {
        self.inner().set_multicast_loop_v4(multicast_loop_v4)
    }

    /// Gets the value of the `IP_MULTICAST_TTL` option for this socket.
    ///
    /// For more information about this option, see
    /// [`set_multicast_ttl_v4`][link].
    ///
    /// [link]: #method.set_multicast_ttl_v4
    pub fn multicast_ttl_v4(&self) -> io::Result<u32> {
        self.inner().multicast_ttl_v4()
    }

    /// Sets the value of the `IP_MULTICAST_TTL` option for this socket.
    ///
    /// Indicates the time-to-live value of outgoing multicast packets for
    /// this socket. The default value is 1 which means that multicast packets
    /// don't leave the local network unless explicitly requested.
    ///
    /// Note that this may not have any affect on IPv6 sockets.
    pub fn set_multicast_ttl_v4(&self, multicast_ttl_v4: u32) -> io::Result<()> {
        self.inner().set_multicast_ttl_v4(multicast_ttl_v4)
    }

    /// Gets the value of the `IPV6_MULTICAST_HOPS` option for this socket
    ///
    /// For more information about this option, see
    /// [`set_multicast_hops_v6`][link].
    ///
    /// [link]: #method.set_multicast_hops_v6
    pub fn multicast_hops_v6(&self) -> io::Result<u32> {
        self.inner().multicast_hops_v6()
    }

    /// Sets the value of the `IPV6_MULTICAST_HOPS` option for this socket
    ///
    /// Indicates the number of "routers" multicast packets will transit for
    /// this socket. The default value is 1 which means that multicast packets
    /// don't leave the local network unless explicitly requested.
    pub fn set_multicast_hops_v6(&self, hops: u32) -> io::Result<()> {
        self.inner().set_multicast_hops_v6(hops)
    }

    /// Gets the value of the `IP_MULTICAST_IF` option for this socket.
    ///
    /// For more information about this option, see
    /// [`set_multicast_if_v4`][link].
    ///
    /// [link]: #method.set_multicast_if_v4
    ///
    /// Returns the interface to use for routing multicast packets.
    pub fn multicast_if_v4(&self) -> io::Result<Ipv4Addr> {
        self.inner().multicast_if_v4()
    }

    /// Sets the value of the `IP_MULTICAST_IF` option for this socket.
    ///
    /// Specifies the interface to use for routing multicast packets.
    pub fn set_multicast_if_v4(&self, interface: &Ipv4Addr) -> io::Result<()> {
        self.inner().set_multicast_if_v4(interface)
    }

    /// Gets the value of the `IPV6_MULTICAST_IF` option for this socket.
    ///
    /// For more information about this option, see
    /// [`set_multicast_if_v6`][link].
    ///
    /// [link]: #method.set_multicast_if_v6
    ///
    /// Returns the interface to use for routing multicast packets.
    pub fn multicast_if_v6(&self) -> io::Result<u32> {
        self.inner().multicast_if_v6()
    }

    /// Sets the value of the `IPV6_MULTICAST_IF` option for this socket.
    ///
    /// Specifies the interface to use for routing multicast packets. Unlike ipv4, this
    /// is generally required in ipv6 contexts where network routing prefixes may
    /// overlap.
    pub fn set_multicast_if_v6(&self, interface: u32) -> io::Result<()> {
        self.inner().set_multicast_if_v6(interface)
    }

    /// Gets the value of the `IPV6_MULTICAST_LOOP` option for this socket.
    ///
    /// For more information about this option, see
    /// [`set_multicast_loop_v6`][link].
    ///
    /// [link]: #method.set_multicast_loop_v6
    pub fn multicast_loop_v6(&self) -> io::Result<bool> {
        self.inner().multicast_loop_v6()
    }

    /// Sets the value of the `IPV6_MULTICAST_LOOP` option for this socket.
    ///
    /// Controls whether this socket sees the multicast packets it sends itself.
    /// Note that this may not have any affect on IPv4 sockets.
    pub fn set_multicast_loop_v6(&self, multicast_loop_v6: bool) -> io::Result<()> {
        self.inner().set_multicast_loop_v6(multicast_loop_v6)
    }

    /// Executes an operation of the `IP_ADD_MEMBERSHIP` type.
    ///
    /// This function specifies a new multicast group for this socket to join.
    /// The address must be a valid multicast address, and `interface` is the
    /// address of the local interface with which the system should join the
    /// multicast group. If it's equal to `INADDR_ANY` then an appropriate
    /// interface is chosen by the system.
    pub fn join_multicast_v4(&self, multiaddr: &Ipv4Addr, interface: &Ipv4Addr) -> io::Result<()> {
        self.inner().join_multicast_v4(multiaddr, interface)
    }

    /// Executes an operation of the `IPV6_ADD_MEMBERSHIP` type.
    ///
    /// This function specifies a new multicast group for this socket to join.
    /// The address must be a valid multicast address, and `interface` is the
    /// index of the interface to join/leave (or 0 to indicate any interface).
    pub fn join_multicast_v6(&self, multiaddr: &Ipv6Addr, interface: u32) -> io::Result<()> {
        self.inner().join_multicast_v6(multiaddr, interface)
    }

    /// Executes an operation of the `IP_DROP_MEMBERSHIP` type.
    ///
    /// For more information about this option, see
    /// [`join_multicast_v4`][link].
    ///
    /// [link]: #method.join_multicast_v4
    pub fn leave_multicast_v4(&self, multiaddr: &Ipv4Addr, interface: &Ipv4Addr) -> io::Result<()> {
        self.inner().leave_multicast_v4(multiaddr, interface)
    }

    /// Executes an operation of the `IPV6_DROP_MEMBERSHIP` type.
    ///
    /// For more information about this option, see
    /// [`join_multicast_v6`][link].
    ///
    /// [link]: #method.join_multicast_v6
    pub fn leave_multicast_v6(&self, multiaddr: &Ipv6Addr, interface: u32) -> io::Result<()> {
        self.inner().leave_multicast_v6(multiaddr, interface)
    }

    /// Reads the linger duration for this socket by getting the SO_LINGER
    /// option
    pub fn linger(&self) -> io::Result<Option<Duration>> {
        self.inner().linger()
    }

    /// Sets the linger duration of this socket by setting the SO_LINGER option
    pub fn set_linger(&self, dur: Option<Duration>) -> io::Result<()> {
        self.inner().set_linger(dur)
    }

    /// Check the `SO_REUSEADDR` option on this socket.
    pub fn reuse_address(&self) -> io::Result<bool> {
        self.inner().reuse_address()
    }

    /// Set value for the `SO_REUSEADDR` option on this socket.
    ///
    /// This indicates that futher calls to `bind` may allow reuse of local
    /// addresses. For IPv4 sockets this means that a socket may bind even when
    /// there's a socket already listening on this port.
    pub fn set_reuse_address(&self, reuse: bool) -> io::Result<()> {
        self.inner().set_reuse_address(reuse)
    }

    /// Gets the value of the `SO_RCVBUF` option on this socket.
    ///
    /// For more information about this option, see
    /// [`set_recv_buffer_size`][link].
    ///
    /// [link]: #method.set_recv_buffer_size
    pub fn recv_buffer_size(&self) -> io::Result<usize> {
        self.inner().recv_buffer_size()
    }

    /// Sets the value of the `SO_RCVBUF` option on this socket.
    ///
    /// Changes the size of the operating system's receive buffer associated
    /// with the socket.
    pub fn set_recv_buffer_size(&self, size: usize) -> io::Result<()> {
        self.inner().set_recv_buffer_size(size)
    }

    /// Gets the value of the `SO_SNDBUF` option on this socket.
    ///
    /// For more information about this option, see [`set_send_buffer`][link].
    ///
    /// [link]: #method.set_send_buffer
    pub fn send_buffer_size(&self) -> io::Result<usize> {
        self.inner().send_buffer_size()
    }

    /// Sets the value of the `SO_SNDBUF` option on this socket.
    ///
    /// Changes the size of the operating system's send buffer associated with
    /// the socket.
    pub fn set_send_buffer_size(&self, size: usize) -> io::Result<()> {
        self.inner().set_send_buffer_size(size)
    }

    /// Returns whether keepalive messages are enabled on this socket, and if so
    /// the duration of time between them.
    ///
    /// For more information about this option, see [`set_keepalive`][link].
    ///
    /// [link]: #method.set_keepalive
    pub fn keepalive(&self) -> io::Result<Option<Duration>> {
        self.inner().keepalive()
    }

    /// Sets whether keepalive messages are enabled to be sent on this socket.
    ///
    /// On Unix, this option will set the `SO_KEEPALIVE` as well as the
    /// `TCP_KEEPALIVE` or `TCP_KEEPIDLE` option (depending on your platform).
    /// On Windows, this will set the `SIO_KEEPALIVE_VALS` option.
    ///
    /// If `None` is specified then keepalive messages are disabled, otherwise
    /// the duration specified will be the time to remain idle before sending a
    /// TCP keepalive probe.
    ///
    /// Some platforms specify this value in seconds, so sub-second
    /// specifications may be omitted.
    pub fn set_keepalive(&self, keepalive: Option<Duration>) -> io::Result<()> {
        self.inner().set_keepalive(keepalive)
    }

    /// Returns the value of the `SO_OOBINLINE` flag of the underlying socket.
    /// For more information about this option, see [`set_out_of_band_inline`][link].
    ///
    /// [link]: #method.set_out_of_band_inline
    #[cfg(all(feature = "all", not(target_os = "redox")))]
    pub fn out_of_band_inline(&self) -> io::Result<bool> {
        self.inner().out_of_band_inline()
    }

    /// Sets the `SO_OOBINLINE` flag of the underlying socket.
    /// as per RFC6093, TCP sockets using the Urgent mechanism
    /// are encouraged to set this flag.
    ///
    /// If this flag is not set, the `MSG_OOB` flag is needed
    /// while `recv`ing to aquire the out-of-band data.
    #[cfg(all(feature = "all", not(target_os = "redox")))]
    pub fn set_out_of_band_inline(&self, oob_inline: bool) -> io::Result<()> {
        self.inner().set_out_of_band_inline(oob_inline)
    }

    /// Check the value of the `SO_REUSEPORT` option on this socket.
    ///
    /// This function is only available on Unix.
    #[cfg(all(
        feature = "all",
        not(any(windows, target_os = "solaris", target_os = "illumos"))
    ))]
    pub fn reuse_port(&self) -> io::Result<bool> {
        self.inner().reuse_port()
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
        not(any(windows, target_os = "solaris", target_os = "illumos"))
    ))]
    pub fn set_reuse_port(&self, reuse: bool) -> io::Result<()> {
        self.inner().set_reuse_port(reuse)
    }

    fn inner(&self) -> &sys::Socket {
        // Safety: this is safe because `sys::Socket` has the
        // `repr(transparent)` attribute.
        unsafe { &*(&self.inner as *const sys::SysSocket as *const sys::Socket) }
    }
}

impl Read for Socket {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner().read(buf)
    }
}

impl<'a> Read for &'a Socket {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner().read(buf)
    }
}

impl Write for Socket {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner().write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner().flush()
    }
}

impl<'a> Write for &'a Socket {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner().write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner().flush()
    }
}

impl fmt::Debug for Socket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.inner().fmt(f)
    }
}

impl From<net::TcpStream> for Socket {
    fn from(socket: net::TcpStream) -> Socket {
        Socket {
            inner: sys::Socket::from(socket).inner(),
        }
    }
}

impl From<net::TcpListener> for Socket {
    fn from(socket: net::TcpListener) -> Socket {
        Socket {
            inner: sys::Socket::from(socket).inner(),
        }
    }
}

impl From<net::UdpSocket> for Socket {
    fn from(socket: net::UdpSocket) -> Socket {
        Socket {
            inner: sys::Socket::from(socket).inner(),
        }
    }
}

#[cfg(all(feature = "all", unix))]
impl From<UnixStream> for Socket {
    fn from(socket: UnixStream) -> Socket {
        Socket {
            inner: sys::Socket::from(socket).inner(),
        }
    }
}

#[cfg(all(feature = "all", unix))]
impl From<UnixListener> for Socket {
    fn from(socket: UnixListener) -> Socket {
        Socket {
            inner: sys::Socket::from(socket).inner(),
        }
    }
}

#[cfg(all(feature = "all", unix))]
impl From<UnixDatagram> for Socket {
    fn from(socket: UnixDatagram) -> Socket {
        Socket {
            inner: sys::Socket::from(socket).inner(),
        }
    }
}

impl From<Socket> for net::TcpStream {
    fn from(socket: Socket) -> net::TcpStream {
        sys::Socket::from_inner(socket.inner).into()
    }
}

impl From<Socket> for net::TcpListener {
    fn from(socket: Socket) -> net::TcpListener {
        sys::Socket::from_inner(socket.inner).into()
    }
}

impl From<Socket> for net::UdpSocket {
    fn from(socket: Socket) -> net::UdpSocket {
        sys::Socket::from_inner(socket.inner).into()
    }
}

#[cfg(all(feature = "all", unix))]
impl From<Socket> for UnixStream {
    fn from(socket: Socket) -> UnixStream {
        sys::Socket::from_inner(socket.inner).into()
    }
}

#[cfg(all(feature = "all", unix))]
impl From<Socket> for UnixListener {
    fn from(socket: Socket) -> UnixListener {
        sys::Socket::from_inner(socket.inner).into()
    }
}

#[cfg(all(feature = "all", unix))]
impl From<Socket> for UnixDatagram {
    fn from(socket: Socket) -> UnixDatagram {
        sys::Socket::from_inner(socket.inner).into()
    }
}

impl Drop for Socket {
    fn drop(&mut self) {
        sys::close(self.inner);
    }
}

#[cfg(test)]
mod test {
    use std::net::SocketAddr;

    use super::*;

    #[test]
    #[cfg(all(feature = "all", unix))]
    fn pair() {
        let (mut a, mut b) = Socket::pair(Domain::UNIX, Type::STREAM, None).unwrap();
        a.write_all(b"hello world").unwrap();
        let mut buf = [0; 11];
        b.read_exact(&mut buf).unwrap();
        assert_eq!(buf, &b"hello world"[..]);
    }

    #[test]
    #[cfg(all(feature = "all", unix))]
    fn unix() {
        use tempdir::TempDir;

        let dir = TempDir::new("unix").unwrap();
        let addr = SockAddr::unix(dir.path().join("sock")).unwrap();

        let listener = Socket::new(Domain::UNIX, Type::STREAM, None).unwrap();
        listener.bind(&addr).unwrap();
        listener.listen(10).unwrap();

        let mut a = Socket::new(Domain::UNIX, Type::STREAM, None).unwrap();
        a.connect(&addr).unwrap();

        let mut b = listener.accept().unwrap().0;

        a.write_all(b"hello world").unwrap();
        let mut buf = [0; 11];
        b.read_exact(&mut buf).unwrap();
        assert_eq!(buf, &b"hello world"[..]);
    }

    #[test]
    fn keepalive() {
        let socket = Socket::new(Domain::IPV4, Type::STREAM, None).unwrap();
        socket.set_keepalive(Some(Duration::from_secs(7))).unwrap();
        // socket.keepalive() doesn't work on Windows #24
        #[cfg(unix)]
        assert_eq!(socket.keepalive().unwrap(), Some(Duration::from_secs(7)));
        socket.set_keepalive(None).unwrap();
        #[cfg(unix)]
        assert_eq!(socket.keepalive().unwrap(), None);
    }

    #[test]
    fn nodelay() {
        let socket = Socket::new(Domain::IPV4, Type::STREAM, None).unwrap();

        assert!(socket.set_nodelay(true).is_ok());

        let result = socket.nodelay();

        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    #[cfg(all(feature = "all", not(target_os = "redox")))]
    fn out_of_band_inline() {
        let socket = Socket::new(Domain::IPV4, Type::STREAM, None).unwrap();

        assert_eq!(socket.out_of_band_inline().unwrap(), false);

        socket.set_out_of_band_inline(true).unwrap();
        assert_eq!(socket.out_of_band_inline().unwrap(), true);
    }

    #[test]
    #[cfg(all(feature = "all", any(target_os = "windows", target_os = "linux")))]
    fn out_of_band_send_recv() {
        let s1 = Socket::new(Domain::IPV4, Type::STREAM, None).unwrap();
        s1.bind(&"127.0.0.1:0".parse::<SocketAddr>().unwrap().into())
            .unwrap();
        let s1_addr = s1.local_addr().unwrap();
        s1.listen(1).unwrap();

        let s2 = Socket::new(Domain::IPV4, Type::STREAM, None).unwrap();
        s2.connect(&s1_addr).unwrap();

        let (s3, _) = s1.accept().unwrap();

        let mut buf = [0; 10];
        // send some plain inband data
        s2.send(&mut buf).unwrap();
        // send a single out of band byte
        assert_eq!(s2.send_out_of_band(&mut [b"!"[0]]).unwrap(), 1);
        // recv the OOB data first
        assert_eq!(s3.recv_out_of_band(&mut buf).unwrap(), 1);
        assert_eq!(buf[0], b"!"[0]);
        assert_eq!(s3.recv(&mut buf).unwrap(), 10);
    }

    #[test]
    fn tcp() {
        let s1 = Socket::new(Domain::IPV4, Type::STREAM, None).unwrap();
        s1.bind(&"127.0.0.1:0".parse::<SocketAddr>().unwrap().into())
            .unwrap();
        let s1_addr = s1.local_addr().unwrap();
        s1.listen(1).unwrap();

        let s2 = Socket::new(Domain::IPV4, Type::STREAM, None).unwrap();
        s2.connect(&s1_addr).unwrap();

        let (s3, _) = s1.accept().unwrap();

        let mut buf = [0; 11];
        assert_eq!(s2.send(&mut buf).unwrap(), 11);
        assert_eq!(s3.recv(&mut buf).unwrap(), 11);
    }
}
