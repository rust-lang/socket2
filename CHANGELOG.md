# 0.4.0

## Added

* New `all` feature: enables API that is not available on all tier 1 platforms.
* `SockRef` type: used to create a reference to an existing socket, e.g.
  `std::net::TcpStream`, making all methods of `Socket` available on it.
* Support for vectored I/O:
  * `Socket::recv_vectored`, `Socket::recv_with_flags`.
  * `Socket::recv_from_vectored`, `Socket::recv_from_vectored_with_flags`.
  * `Socket::send_vectored`, `Socket::send_vectored_with_flags`.
  * `Socket::send_to_vectored`, `Socket::send_to_vectored_with_flags`.
  * In the `Read` and `Write` implementations.
* `Socket::new_raw`, `Socket::pair_raw` and `Socket::accept_raw` methods
  that don't set common flags, such as the close-on-exec flag.
* `Socket::accept4`: `accept4(2)` system call.
* `Socket::set_cloexec`: set the close-on-exec flag on Unix.
* `Socket::set_no_inherit`: set inherit handle flag on Windows.
* `Socket::set_nosigpipe`: set `SO_NOSIGPIPE` on Apple targets.
* `Socket::set_mark` and `Socket::mark`, setting/getting the `SO_MARK` socket
  option.
* `Socket::set_mss` and `Socket::mss`, setting/getting the `TCP_MAXSEG` socket
  option.
* `Socket::set_freebind` and `Socket::freebind`, setting/getting the
  `IP_FREEBIND` socket option.
* `Socket::bind_device` and `Socket::device`, setting/getting the
  `SO_BINDTODEVICE` socket option.
* Adopted Mio's TCP keepalive API:
  * `Socket::keepalive_time`,
  * `Socket::keepalive_interval`,
  * `Socket::keepalive_retries`,
  * `Socket::set_tcp_keepalive`.
* `Domain::for_address`: the correct `Domain` for a `std::net::SocketAddr`.
* `Type::nonblocking`: set `SOCK_NONBLOCK`.
* `Type::cloexec`: set `SOCK_CLOEXEC`.
* `Type::no_inherit`: set `HANDLE_FLAG_INHERIT`.
* `SockAddr::init`: initialises a `SockAddr`.
* `MaybeUninitSlice` type: a version of `IoSliceMut` that allows the buffer to
  be uninitialised, used in `Socket::recv_vectored` and related functions.
* `RecvFlags` type: provides additional information about incoming messages,
  returned by `Socket::recv_vectored` and related functions.
* `TcpKeepalive` type: configuration type for a socket's TCP keepalive
  parameters.


## Changed

* Repository moved to <https://github.com/rust-lang/socket2>.
* **BREAKING:** Changed constructor functions into constants:
  * `Domain::ipv4` => `Domain::IPV4`.
  * `Domain::ipv6` => `Domain::IPV4`.
  * `Domain::unix` => `Domain::UNIX`.
  * `Domain::packet` => `Domain::PACKET`.
  * `Type::stream`    => `Type::STREAM`.
  * `Type::dgram`     => `Type::DGRAM`.
  * `Type::seqpacket` => `Type::SEQPACKET`.
  * `Type::raw`       => `Type::RAW`.
  * `Protocol::icmpv4` => `Protocol::ICMPV4`.
  * `Protocol::icmpv6` => `Protocol::ICMPV6`.
  * `Protocol::tcp` => `Protocol::TCP`.
  * `Protocol::udp` => `Protocol::UDP`.
* **BREAKING:** Changed the signature of `Socket::recv`, `Socket::recv_vectored`
  and related methods to accept unitialised buffers. The `Read` implementation
  can be used to read into initialised buffers.
* **BREAKING:** Renamed `SockAddr::as_std` to `as_socket`.
* **BREAKING:** Renamed `SockAddr::as_inet` to `as_socket_ipv4`.
* **BREAKING:** Renamed `SockAddr::as_inet6` to `as_socket_ipv6`.
* **BREAKING:** Replace all previously existing features (reuseport, pair, unix)
  with a new all features (see above for description of the all feature).
* Use `accept4(2)` with `SOCK_CLOEXEC` in `Socket::accept`, reducing the amount
  of system calls required.
* Marked many functions as constant.
* The `Read` implementation now calls `recv(2)` rather than `read(2)`.
* Split the `impl` block for the `Socket` type to create groupings for setting
  and getting different level socket options using
  `setsockopt(2)`/`getsockopt(2)`.
* Updated `winapi` depdency to version 0.3.9 and dropped unused features.

## Removed

* Removed the `-rs` suffix from the repository name.
* **BREAKING:** Removed `SockAddr::from_raw_parts`, use `SockAddr::init` instead.
* **BREAKING:** Removed `Socket::into_*` functions and replaced them with a `From`
  implementation:
    * `Socket::into_tcp_stream` => `TcpStream::from(socket)`.
    * `Socket::into_tcp_listener` => `TcpListener::from(socket)`.
    * `Socket::into_udp_socket` => `UdpSocket::from(socket)`.
    * `Socket::into_unix_stream` => `UnixStream::from(socket)`.
    * `Socket::into_unix_listener` => `UnixListener::from(socket)`.
    * `Socket::into_unix_datagram` => `UnixDatagram::from(socket)`.
* Removed `cfg-if` dependency.
* Remove `redox_syscall` depdency.

## Fixes

* Fixes the Andoid, Fuchsia, Haiku, iOS, illumos, NetBSD and Redox (nightly
  only) targets.
* Correctly call `recv_from` in `Socket::recv_from_with_flags` (called `recv`
  previously).
* Correctly call `send_to` in `Socket::send_to_with_flags` (called `recv`
  previously).
* Use correct inmutable references in `Socket::send_with_flags` and
  `Socket::send_out_of_band`.
* Use `IPPROTO_IPV6` in `Socket::join_multicast_v6` on Windows.
* Don't assume the memory layout of `std::net::SocketAddr`.
* Use `c_int` instead of `i32` where appropriate.

## From v0.4.0-alpha.1 to v0.4.0-alpha.2

* Fixes the Fuchsia target.
* `Socket::device` now returns a `Vec<u8>` rather then `CString`.
* `Socket::bind_device` now accepts a `&[u8]` rather then `&CStr`.
