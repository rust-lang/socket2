// Copyright 2015 The Rust Project Developers.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

// # Source code structure.
//
// All types and methods that are available on tier 1 all platforms are defined
// in the first level of the source, i.e. `src/*.rs` files. Additional API that
// is platform specific, e.g. `Domain::UNIX`, is defined in `src/sys/*.rs` and
// only for the platforms that support it.

//! Utilities for creating and using sockets.
//!
//! The goal of this crate is to create and use a socket using advanced
//! configuration options (those that are not available in the types in the
//! standard library) without using any unsafe code.
//!
//! This crate provides as direct as possible access to the system's
//! functionality for sockets, this means **no** effort to provide
//! cross-platform utilities, no extra goodies, no creature comforts. It is up
//! to the user to know how to use sockets when using this crate. *If you don't
//! know how to create a socket using libc/system calls then this crate is not
//! for you*. Most, if not all, functions directly relate to the equivalent
//! system call with no error handling applied, so no handling errors such as
//! [`EINTR`]. As a result using this crate can be a little wordy, but it should
//! give you maximal flexibility over configuration of sockets.
//!
//! [`EINTR`]: std::io::ErrorKind::Interrupted
//!
//! # Examples
//!
//! ```no_run
//! # fn main() -> std::io::Result<()> {
//! use std::net::{SocketAddr, TcpListener};
//! use socket2::{Socket, Domain, Type};
//!
//! // Create a TCP listener bound to two addresses.
//! let socket = Socket::new(Domain::IPV6, Type::STREAM, None)?;
//!
//! let address: SocketAddr = "[::1]:12345".parse().unwrap();
//! socket.bind(&address.into())?;
//! socket.set_only_v6(false)?;
//! socket.listen(128)?;
//!
//! let listener: TcpListener = socket.into();
//! // ...
//! # drop(listener);
//! # Ok(()) }
//! ```
//!
//! ## Features
//!
//! This crate has a single feature `all`, which enables all functions even ones
//! that are not available on all OSes.

#![doc(html_root_url = "https://docs.rs/socket2/0.3")]
#![deny(missing_docs, missing_debug_implementations, rust_2018_idioms)]
// Show required OS/features on docs.rs.
#![cfg_attr(docsrs, feature(doc_cfg))]
// Disallow warnings when running tests.
#![cfg_attr(test, deny(warnings))]
// Disallow warnings in examples.
#![doc(test(attr(deny(warnings))))]

use std::net::SocketAddr;

/// Macro to implement `fmt::Debug` for a type, printing the constant names
/// rather than a number.
///
/// Note this is used in the `sys` module and thus must be defined before
/// defining the modules.
macro_rules! impl_debug {
    (
        // Type name for which to implement `fmt::Debug`.
        $type: path,
        $(
            $(#[$target: meta])*
            // The flag(s) to check.
            // Need to specific the libc crate because Windows doesn't use
            // `libc` but `winapi`.
            $libc: ident :: $flag: ident
        ),+ $(,)*
    ) => {
        impl std::fmt::Debug for $type {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                let string = match self.0 {
                    $(
                        $(#[$target])*
                        $libc :: $flag => stringify!($flag),
                    )+
                    n => return write!(f, "{}", n),
                };
                f.write_str(string)
            }
        }
    };
}

mod sockaddr;
mod socket;
mod sockref;

#[cfg(test)]
mod tests;

#[cfg(unix)]
#[path = "sys/unix.rs"]
mod sys;
#[cfg(windows)]
#[path = "sys/windows.rs"]
mod sys;

use sys::c_int;

pub use sockaddr::SockAddr;
pub use socket::Socket;
pub use sockref::SockRef;

/// Specification of the communication domain for a socket.
///
/// This is a newtype wrapper around an integer which provides a nicer API in
/// addition to an injection point for documentation. Convenience constants such
/// as [`Domain::IPV4`], [`Domain::IPV6`], etc, are provided to avoid reaching
/// into libc for various constants.
///
/// This type is freely interconvertible with C's `int` type, however, if a raw
/// value needs to be provided.
#[derive(Copy, Clone, Eq, PartialEq)]
pub struct Domain(c_int);

impl Domain {
    /// Domain for IPv4 communication, corresponding to `AF_INET`.
    pub const IPV4: Domain = Domain(sys::AF_INET);

    /// Domain for IPv6 communication, corresponding to `AF_INET6`.
    pub const IPV6: Domain = Domain(sys::AF_INET6);

    /// Returns the correct domain for `address`.
    pub const fn for_address(address: SocketAddr) -> Domain {
        match address {
            SocketAddr::V4(_) => Domain::IPV4,
            SocketAddr::V6(_) => Domain::IPV6,
        }
    }
}

impl From<c_int> for Domain {
    fn from(d: c_int) -> Domain {
        Domain(d)
    }
}

impl From<Domain> for c_int {
    fn from(d: Domain) -> c_int {
        d.0
    }
}

/// Specification of communication semantics on a socket.
///
/// This is a newtype wrapper around an integer which provides a nicer API in
/// addition to an injection point for documentation. Convenience constants such
/// as [`Type::STREAM`], [`Type::DGRAM`], etc, are provided to avoid reaching
/// into libc for various constants.
///
/// This type is freely interconvertible with C's `int` type, however, if a raw
/// value needs to be provided.
#[derive(Copy, Clone, Eq, PartialEq)]
pub struct Type(c_int);

impl Type {
    /// Type corresponding to `SOCK_STREAM`.
    ///
    /// Used for protocols such as TCP.
    pub const STREAM: Type = Type(sys::SOCK_STREAM);

    /// Type corresponding to `SOCK_DGRAM`.
    ///
    /// Used for protocols such as UDP.
    pub const DGRAM: Type = Type(sys::SOCK_DGRAM);

    /// Type corresponding to `SOCK_SEQPACKET`.
    #[cfg(feature = "all")]
    pub const SEQPACKET: Type = Type(sys::SOCK_SEQPACKET);

    /// Type corresponding to `SOCK_RAW`.
    #[cfg(all(feature = "all", not(target_os = "redox")))]
    pub const RAW: Type = Type(sys::SOCK_RAW);
}

impl From<c_int> for Type {
    fn from(t: c_int) -> Type {
        Type(t)
    }
}

impl From<Type> for c_int {
    fn from(t: Type) -> c_int {
        t.0
    }
}

/// Protocol specification used for creating sockets via `Socket::new`.
///
/// This is a newtype wrapper around an integer which provides a nicer API in
/// addition to an injection point for documentation.
///
/// This type is freely interconvertible with C's `int` type, however, if a raw
/// value needs to be provided.
#[derive(Copy, Clone, Eq, PartialEq)]
pub struct Protocol(c_int);

impl Protocol {
    /// Protocol corresponding to `ICMPv4`.
    pub const ICMPV4: Protocol = Protocol(sys::IPPROTO_ICMP);

    /// Protocol corresponding to `ICMPv6`.
    pub const ICMPV6: Protocol = Protocol(sys::IPPROTO_ICMPV6);

    /// Protocol corresponding to `TCP`.
    pub const TCP: Protocol = Protocol(sys::IPPROTO_TCP);

    /// Protocol corresponding to `UDP`.
    pub const UDP: Protocol = Protocol(sys::IPPROTO_UDP);
}

impl From<c_int> for Protocol {
    fn from(p: c_int) -> Protocol {
        Protocol(p)
    }
}

impl From<Protocol> for c_int {
    fn from(p: Protocol) -> c_int {
        p.0
    }
}

/// Flags for incoming messages.
///
/// Flags provide additional information about incoming messages.
#[cfg(not(target_os = "redox"))]
#[derive(Copy, Clone, Eq, PartialEq)]
pub struct RecvFlags(c_int);

#[cfg(not(target_os = "redox"))]
impl RecvFlags {
    /// Check if the message contains a truncated datagram.
    ///
    /// This flag is only used for datagram-based sockets,
    /// not for stream sockets.
    ///
    /// On Unix this corresponds to the `MSG_TRUNC` flag.
    /// On Windows this corresponds to the `WSAEMSGSIZE` error code.
    pub const fn is_truncated(self) -> bool {
        self.0 & sys::MSG_TRUNC != 0
    }
}
