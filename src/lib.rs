// Copyright 2015 The Rust Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution and at
// http://rust-lang.org/COPYRIGHT.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Utilities for handling sockets
//!
//! This crate is sort of an evolution of the `net2` crate after seeing the
//! issues on it over time. The intention of this crate is to provide as direct
//! as possible access to the system's functionality for sockets as possible. No
//! extra fluff (e.g. multiple syscalls or builders) provided in this crate. As
//! a result using this crate can be a little wordy, but it should give you
//! maximal flexibility over configuration of sockets.
//!
//! # Examples
//!
//! ```no_run
//! use std::net::SocketAddr;
//! use socket2::{Socket, Domain, Type};
//!
//! // create a TCP listener bound to two addresses
//! let socket = Socket::new(Domain::ipv6(), Type::stream(), None).unwrap();
//!
//! socket.bind(&"[::1]:12345".parse::<SocketAddr>().unwrap().into()).unwrap();
//! socket.set_only_v6(false);
//! socket.listen(128).unwrap();
//!
//! let listener = socket.into_tcp_listener();
//! // ...
//! ```

#![doc(html_root_url = "https://docs.rs/socket2/0.3")]
#![deny(missing_docs)]

use crate::utils::NetInt;

mod sockaddr;
mod socket;
mod utils;

#[cfg(unix)]
#[path = "sys/unix.rs"]
mod sys;
#[cfg(windows)]
#[path = "sys/windows.rs"]
mod sys;

use sys::c_int;

pub use sockaddr::SockAddr;
pub use socket::Socket;

/// Specification of the communication domain for a socket.
///
/// This is a newtype wrapper around an integer which provides a nicer API in
/// addition to an injection point for documentation. Convenience constructors
/// such as `Domain::ipv4`, `Domain::ipv6`, etc, are provided to avoid reaching
/// into libc for various constants.
///
/// This type is freely interconvertible with the `i32` type, however, if a raw
/// value needs to be provided.
#[derive(Copy, Clone)]
pub struct Domain(i32);

impl Domain {
    /// Domain for IPv4 communication, corresponding to `AF_INET`.
    pub fn ipv4() -> Domain {
        Domain(sys::AF_INET)
    }

    /// Domain for IPv6 communication, corresponding to `AF_INET6`.
    pub fn ipv6() -> Domain {
        Domain(sys::AF_INET6)
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
/// addition to an injection point for documentation. Convenience constructors
/// such as `Type::stream`, `Type::dgram`, etc, are provided to avoid reaching
/// into libc for various constants.
///
/// This type is freely interconvertible with the `i32` type, however, if a raw
/// value needs to be provided.
#[derive(Copy, Clone)]
pub struct Type(i32);

/// Protocol specification used for creating sockets via `Socket::new`.
///
/// This is a newtype wrapper around an integer which provides a nicer API in
/// addition to an injection point for documentation.
///
/// This type is freely interconvertible with the `i32` type, however, if a raw
/// value needs to be provided.
#[derive(Copy, Clone)]
pub struct Protocol(i32);

fn hton<I: NetInt>(i: I) -> I {
    i.to_be()
}

fn ntoh<I: NetInt>(i: I) -> I {
    I::from_be(i)
}
