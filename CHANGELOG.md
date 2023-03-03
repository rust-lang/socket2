# 0.4.9

* Fixed compilation on Windows
  (https://github.com/rust-lang/socket2/pull/409).

# 0.4.8 (yanked)

This release was broken for Windows.

* Add `Socket::peek_sender` (backport)
  (https://github.com/rust-lang/socket2/pull/404).

# 0.4.7

* Fixes compilation on OpenBSD
  (https://github.com/rust-lang/socket2/pull/344).
* Fixes compilation on DragonFlyBSD
  (https://github.com/rust-lang/socket2/pull/342).

# 0.4.6

* Reverted back to the `winapi` dependency as switch to `windows-sys` was a
  breaking change (https://github.com/rust-lang/socket2/pull/340).
  Note that we'll will switch to `windows-sys` in v0.5 .
* Disable RECVTOS on OpenBSD
  (https://github.com/rust-lang/socket2/pull/307).
* Derive Clone for SockAddr
  (https://github.com/rust-lang/socket2/pull/311).
* Fix cfg attributes for Fuchsia
  (https://github.com/rust-lang/socket2/pull/314).

# 0.4.5 (yanked)

## Changed

* Replace `winapi` dependency with `windows-sys`
  (https://github.com/rust-lang/socket2/pull/303).

## Added

* `Socket::join_ssm_v4` and `Socket::leave_ssm_v4`
  (https://github.com/rust-lang/socket2/pull/298).
* `Socket::set_recv_tos` and `Socket::recv_tos`
  (https://github.com/rust-lang/socket2/pull/299).

## Fixed

* Fix OpenBSD build
  (https://github.com/rust-lang/socket2/pull/291).
* Fix OpenBSD build
  (https://github.com/rust-lang/socket2/pull/291).

# 0.4.4

## Fixed

* Libc v0.2.114 fixed an issue where `ip_mreqn` where was not defined for Linux
  s390x.

# 0.4.3 (yanked)

## Added

* `Socket::set_fib`: sets `SO_SETFIB` (https://github.com/rust-lang/socket2/pull/271).
* `Socket::attach_filter`, `SO_ATTACH_FILTER` (https://github.com/rust-lang/socket2/commit/6601ed132b37d6e9d178b34918bfb0b236800232).
* `Socket::detach_filter`, `SO_DETACH_FILTER` (https://github.com/rust-lang/socket2/commit/6601ed132b37d6e9d178b34918bfb0b236800232).
* `Socket::{header_included, set_header_included}`: sets or gets `IP_HDRINCL`
  (https://github.com/rust-lang/socket2/commit/f9e882ee53c0b4e89c5043b6d709af95c9db5599).
* `Socket::{cork, set_cork}`: sets or gets `TCP_CORK`
  (https://github.com/rust-lang/socket2/commit/50f31f18aac8fd6ef277df2906adeeed9fa391de).
* `Socket::{quickack, set_quickack}`: sets or gets `TCP_QUICKACK`
  (https://github.com/rust-lang/socket2/commit/849eee2abc5d5170d2d3bc635386a2ba13b04530).
* `Socket::{thin_linear_timeouts, set_thin_linear_timeouts}`: sets or gets
  `TCP_THIN_LINEAR_TIMEOUTS`
  (https://github.com/rust-lang/socket2/commit/24c231ca463a17f51e53e7a554c7915a95bdbcc7).
* `Socket::{join_multicast_v4_n, leave_multicast_v4_n}`: extends the existing
  multicast API by allowing an index to be used (in addition to an address)
  (https://github.com/rust-lang/socket2/commit/750f83618b967c620bbfdf6ca04de7362bdb42b5).

# 0.4.2

## Added

* `Socket::(set_)freebind_ipv6`, getter and setter for `IPV6_FREEBIND`.

## Fixed

* Compilation on OpenBSD.
* Usage of incorrect flag in `Socket::(set_)freebind`.

# 0.4.1

## Added

* Add `SockAddr::new`
* Support for `TCP_USER_TIMEOUT`.
* Support for `IP_BOUND_IF`.
* Support for `IP_TRANSPARENT`.
* Enable `Socket::type` on all platforms.
* Support for uclibc (for Haiku support).
* Add DragonFly support for TCP keepalive (`KEEPINTVL`/`KEEPCNT`).
* Documentation for proper use of `SockRef::from`, and the improper use.
* Assertion in `SockRef::from` to ensure the raw socket valid.

## Fixed

* Compilation on Haiku.
* Setting TCP keepalive on Haiku and OpenBSD (by not setting it as it's not
  supported).
* Size check for abstract namespaces in `SockAddr::unix`.
* Set noinherit on accepted sockets on Windows when opening sockets.

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
* `Socket::sendfile`: the `sendfile(2)` system call.
* `Socket::set_cloexec`: set the close-on-exec flag on Unix.
* `Socket::set_no_inherit`: set inherit handle flag on Windows.
* `Socket::set_nosigpipe`: set `SO_NOSIGPIPE` on Apple targets.
* `Socket::set_mark` and `Socket::mark`, setting/getting the `SO_MARK` socket
  option.
* `Socket::set_cpu_affinity` and `Socket::cpu_affinity`, setting/getting the
  `SO_INCOMING_CPU` socket option.
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
* `Socket::is_listener` getting the `SO_ACCEPTCONN` socket option.
* `Socket::domain` getting the `SO_DOMAIN` socket option.
* `Socket::protocol` getting the `SO_PROTOCOL` socket option.
* `Socket::type` getting the `SO_TYPE` socket option.
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
* Use `c_int` instead of `i32` where appropriate.

## From v0.4.0-alpha.1 to v0.4.0-alpha.2

* Fixes the Fuchsia target.
* `Socket::device` now returns a `Vec<u8>` rather than `CString`.
* `Socket::bind_device` now accepts a `&[u8]` rather than `&CStr`.

## From v0.4.0-alpha.2 to v0.4.0-alpha.3

* `Socket::connect_timeout` was added back.

## From v0.4.0-alpha.4 to v0.4.0-alpha.5

* Changed `Socket::set_cpu_affinity` and `Socket::cpu_affinity` to use an
  immutable reference.

## From v0.4.0-alpha.5 to v0.4.0

* Use `SO_LINGER_SEC` on macOS for `Socket::get/set_linger`.

# 0.3.16

* Don't assume the memory layout of `std::net::SocketAddr`.
* Other changes omited
