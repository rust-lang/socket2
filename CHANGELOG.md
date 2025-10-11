# 0.6.1

## Added

* Added support for Windows Registered I/O (RIO)
  (https://github.com/rust-lang/socket2/pull/604).
* Added support for `TCP_NOTSENT_LOWAT` on Linux via `Socket::(set_)tcp_notsent_lowat`
  (https://github.com/rust-lang/socket2/pull/611).
* Added support for `SO_BUSY_POLL` on Linux via `Socket::set_busy_poll`
  (https://github.com/rust-lang/socket2/pull/607).
* `SockFilter::new` is now a const function
  (https://github.com/rust-lang/socket2/pull/609).

## Changed

* Updated the windows-sys dependency to version 0.60
  (https://github.com/rust-lang/socket2/pull/605).

# 0.6.0

## Breaking changes

All IPv4 methods now have a `_v4` suffix, IPv6 uses `_v6`. TCP methods have a
`tcp_` prefix (looked better than a suffix).

Furthermore we removed all types from external libraries (i.e. libc or
windows-sys) from the public API, allowing us to update those without breaking
the API.

* Renamed `Socket::freebind_ipv6` to `freebind_v6`
  (https://github.com/rust-lang/socket2/pull/592).
* Renamed `Socket::freebind` to `freebind_v4`
  (https://github.com/rust-lang/socket2/pull/592).
* Renamed `Socket::original_dst` to `original_dst_v4`
  (https://github.com/rust-lang/socket2/pull/592).
* Renamed `Socket::original_dst_ipv6` to `original_dst_v6`
  (https://github.com/rust-lang/socket2/pull/592).
* Bump MSRV to 1.70
  (https://github.com/rust-lang/socket2/pull/597).
* Use `c_int` from `std::ffi` instead of from libc
  (https://github.com/rust-lang/socket2/pull/599,
  https://github.com/rust-lang/socket2/pull/595).
* `SockAddr`'s methods now accept/return `SockAddrStorage` instead of
  `sockaddr_storage`/`SOCKADDR_STORAGE`
  (https://github.com/rust-lang/socket2/pull/576):
  * `new`
  * `try_init`
  * `as_ptr`
  * `as_storage`
* Add `SockFilter`, wrapper around `libc::sock_filter`, argument to
  `Socket::attach_filter`
  (https://github.com/rust-lang/socket2/pull/581).
* Various renames of TCP methods on `Socket`
  (https://github.com/rust-lang/socket2/pull/592):
  * `keepalive_time` -> `tcp_keepalive_time`
  * `keepalive_interval` -> `tcp_keepalive_interval`
  * `keepalive_retries` -> `tcp_keepalive_retries`
  * `nodelay` -> `tcp_nodelay`
  * `set_nodelay` -> `set_tcp_nodelay`
  * `tcp_mss` -> `mss`
  * `tcp_set_mss` -> `set_mss`
  * `tcp_cork` -> `cork`
  * `tcp_set_cork` -> `set_cork`
  * `tcp_quickack` -> `quickack`
  * `tcp_set_quickack` -> `set_quickack`
  * `thin_linear_timeouts` -> `tcp_thin_linear_timeouts`.

## Non-breaking changes

* Added `Socket::(set_)priority`
  (https://github.com/rust-lang/socket2/pull/588).
* Added TCP retries on Windows
  (https://github.com/rust-lang/socket2/pull/557).
* Added `SockAddrStorage`, wrapper around `sockaddr_storage`/`SOCKADDR_STORAGE`
  for usage with `SockAddr` (instead of the types from libc/windows-sys)
  (https://github.com/rust-lang/socket2/pull/576).
* Implemented `Socket::bind_device_by_index_{v4,v6}` on Android and Linux
  (https://github.com/rust-lang/socket2/pull/572).
* Implemented `Copy` and `Clone` for `InterfaceIndexOrAddress`
  (https://github.com/rust-lang/socket2/pull/571).
* Updated to Windows-sys v0.59
  (https://github.com/rust-lang/socket2/pull/579).
* We now use `OwnedFd`/`OwnedSocket` internally for `Socket`
  (https://github.com/rust-lang/socket2/pull/600).

# 0.5.10

* Add cygwin support
  (https://github.com/rust-lang/socket2/pull/568,
  https://github.com/rust-lang/socket2/pull/578).

# 0.5.9

* Enable `IP_BOUND_IF` on illumos and Solaris
  (https://github.com/rust-lang/socket2/pull/561,
  https://github.com/rust-lang/socket2/pull/566).

# 0.5.8

* Added `Socket::(set_)header_included_v4` and
  `Socket::(set_)header_included_v6`
  (https://github.com/rust-lang/socket2/pull/518).
* Added support for `Socket::original_dst` and
  `Socket::original_dst_ipv6` on Windows
  (https://github.com/rust-lang/socket2/pull/529).

# 0.5.7

* Added `Socket::(set_)passcred`
  (https://github.com/rust-lang/socket2/pull/506).
* Added `RecvFlags::is_confirm` and `RecvFlags::is_dontroute`
  (https://github.com/rust-lang/socket2/pull/499).
* Added `MsgHdrMut::control_len`
  (https://github.com/rust-lang/socket2/pull/505).

# 0.5.6

* Added `Socket::(set_)multicast_all_v{4,6}`
  (https://github.com/rust-lang/socket2/pull/485 and
   https://github.com/rust-lang/socket2/pull/486).
* Added support for GNU/Hurd
  (https://github.com/rust-lang/socket2/pull/474).
* Fixes compilation on Haiku
  (https://github.com/rust-lang/socket2/pull/479 and
   https://github.com/rust-lang/socket2/pull/482).
* Fixes compilation on OpenHarmony
  (https://github.com/rust-lang/socket2/pull/491).
* Update to window-sys v0.52
  (https://github.com/rust-lang/socket2/pull/480).

# 0.5.5

* Added support for Vita
  (https://github.com/rust-lang/socket2/pull/465).

# 0.5.4

* Deprecated `Socket::(bind_)device_by_index`, replaced by
  `Socket::(bind_)device_by_index_v4` for IPv4 sockets
  (https://github.com/rust-lang/socket2/pull/432).
* Added `Socket::(bind_)device_by_index_v6`
  (https://github.com/rust-lang/socket2/pull/432).
* Added experimental support for the ESP-IDF framework
  (https://github.com/rust-lang/socket2/pull/452)
* Added `Socket::{send,recv}msg` and `MsgHdr(Mut)` types, wrapping `sendmsg(2)`
  and `recvmsg(2)`
  (https://github.com/rust-lang/socket2/pull/447).
* Added `Socket::(set_)reuse_port_lb` to retrieve or set `SO_REUSEPORT_LB` on
  FreeBSD
  (https://github.com/rust-lang/socket2/pull/442).
* Added `Protocol::DIVERT` on FreeBSD and OpenBSD
  (https://github.com/rust-lang/socket2/pull/448).
* Added `Socket::protocol` for Windows (using `WSAPROTOCOL_INFOW`)
  (https://github.com/rust-lang/socket2/pull/470).
* `From<SocketAddrV{4,6}>` for `SockAddr ` nows sets `ss_len` on platforms that
  have the fields (most BSDs)
  (https://github.com/rust-lang/socket2/pull/469).
* Change Windows to use `ADDRESS_FAMILY` for `sa_family_t`, this shouldn't
  affect anything in practice
  (https://github.com/rust-lang/socket2/pull/463).

# 0.5.3

* Added support for two new Android targets `armv7-linux-androideabi` and
  `i686-linux-android` (https://github.com/rust-lang/socket2/pull/434).
* Added `Socket::cookie` to retrieve `SO_COOKIE` on Linux
  (https://github.com/rust-lang/socket2/pull/437).

# 0.5.2

* Added Unix socket methods to `SockAddr`
  (https://github.com/rust-lang/socket2/pull/403 and
  https://github.com/rust-lang/socket2/pull/429).
* Added `SockAddr::as_storage`
  (https://github.com/rust-lang/socket2/pull/417).
* Added `SockAddr::set_length`
  (https://github.com/rust-lang/socket2/pull/428).
* Added `Protocol::UDPLITE`
  (https://github.com/rust-lang/socket2/pull/427).
* Update windows-sys to 0.48
  (https://github.com/rust-lang/socket2/pull/422).
* Fixes Fuchsia target after it changes in 1.68, see
  <https://github.com/rust-lang/rust/blob/master/RELEASES.md#version-1680-2023-03-09>
  (https://github.com/rust-lang/socket2/pull/423).
* Fixes musl target and adds it to the CI
  (https://github.com/rust-lang/socket2/pull/426).

# 0.5.1

## Added

* `Type::cloexec` for Redox and Solaris
  (https://github.com/rust-lang/socket2/pull/398).
* Generate documentation for more targets on docs.rs
  (https://github.com/rust-lang/socket2/pull/398).

## Fixed

* Generatation of documentation on docs.rs
  (https://github.com/rust-lang/socket2/pull/398).

# 0.5.0

## Changed

* **BREAKING** `SockAddr::init` is renamed to `try_init` to indicate it can fail
  (https://github.com/rust-lang/socket2/pull/328).
* **BREAKING** Remove the returned `Result` from `SockAddr::vsock`, it can't
  fail (https://github.com/rust-lang/socket2/pull/328).
* **BREAKING** `From<S>` is now implemented using the I/O traits `AsFd` and
  `AsRawSocket`
  (https://github.com/rust-lang/socket2/pull/325):
* **BREAKING** renamed `SockAddr::vsock_addr` `SockAddr::as_vsock_addr` to match
  the IPv4 and IPv6 methods
  (https://github.com/rust-lang/socket2/pull/334).
* Redox now works on a stable compiler
  (https://github.com/rust-lang/socket2/pull/326).
* Remove copy from `From<SocketAddrV{4,6}>` implementation for `SockAddr`
  (https://github.com/rust-lang/socket2/pull/335).
* Marked function as constant where possible.
* Updated to Rust edition 2021
  (https://github.com/rust-lang/socket2/pull/393).

## Added

* Links to OS documentation to a lot of methods
  (https://github.com/rust-lang/socket2/pull/319).
* I/O-safety traits (https://github.com/rust-lang/socket2/pull/325):
  * `AsFd` for `Socket` (Unix only).
  * `From<OwnedFd>` for `Socket` (Unix only).
  * `From<Socket>` for `OwnedFd` (Unix only).
  * `AsSocket` for `Socket` (Windows only).
  * `From<OwnedSocket>` for `Socket` (Windows only).
  * `From<Socket>` for `OwnedSocket` (Windows only).
* Unix socket support on Windows
  (https://github.com/rust-lang/socket2/pull/249).
* `SockAddr::is_ipv{4,6}` and `SockAddr::domain`
  (https://github.com/rust-lang/socket2/pull/334).
* `Socket::nonblocking`
  (https://github.com/rust-lang/socket2/pull/348).
* `Socket::original_dst(_ipv6)`
  (https://github.com/rust-lang/socket2/pull/360).
* `Socket::(set_)recv_tclass_v6` and `Socket::(set_)tclass_v6`
  (https://github.com/rust-lang/socket2/pull/364).
* `Socket::(set_)tcp_congestion`
  (https://github.com/rust-lang/socket2/pull/371).
* Support for various DCCP socket options in the form of
  (https://github.com/rust-lang/socket2/pull/359):
  * `Socket::(set_)dccp_service`
  * `Socket::dccp_available_ccids`
  * `Socket::dccp_qpolicy_txqlen`
  * `Socket::dccp_recv_cscov`
  * `Socket::dccp_send_cscov`
  * `Socket::dccp_server_timewait`
  * `Socket::dccp_server_timewait`
  * `Socket::dccp_tx_ccid`
  * `Socket::dccp_xx_ccid`
  * `Socket::set_dccp_ccid`
  * `Socket::set_dccp_qpolicy_txqlen`
  * `Socket::set_dccp_recv_cscov`
  * `Socket::set_dccp_send_cscov`
  * `Socket::set_dccp_server_timewait`
  * `Socket::dccp_cur_mps`
* `Socket::peek_send`
  (https://github.com/rust-lang/socket2/pull/389).
* `Protocol::MPTCP`
  (https://github.com/rust-lang/socket2/pull/349).
* `Protocol::SCTP`
  (https://github.com/rust-lang/socket2/pull/356).
* `Protocol::DCCP`
  (https://github.com/rust-lang/socket2/pull/359).
* `Type::DCCP`
  (https://github.com/rust-lang/socket2/pull/359).
* Implement `Eq` and `Hash` for `SockAddr`
  (https://github.com/rust-lang/socket2/pull/374).
* Support for QNX Neutrino
  (https://github.com/rust-lang/socket2/pull/380).
* Support for AIX
  (https://github.com/rust-lang/socket2/pull/351).

# 0.4.10

* Fixed compilation with the `all` on QNX Neutrino
  (https://github.com/rust-lang/socket2/pull/419).
* Added support for ESP-IDF
  (https://github.com/rust-lang/socket2/pull/455).
* Added support for Vita
  (https://github.com/rust-lang/socket2/pull/475).

# 0.4.9

* Fixed compilation on Windows
  (https://github.com/rust-lang/socket2/pull/409).

# 0.4.8 (yanked)

This release was broken for Windows.

* Added `Socket::peek_sender` (backport)
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
* Fixes cfg attributes for Fuchsia
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

* OpenBSD build
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

* Added `SockAddr::new`
* Support for `TCP_USER_TIMEOUT`.
* Support for `IP_BOUND_IF`.
* Support for `IP_TRANSPARENT`.
* Enable `Socket::type` on all platforms.
* Support for uclibc (for Haiku support).
* Added DragonFly support for TCP keepalive (`KEEPINTVL`/`KEEPCNT`).
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
