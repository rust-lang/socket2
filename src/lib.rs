// Copyright 2015 The Rust Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution and at
// http://rust-lang.org/COPYRIGHT.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![doc(html_logo_url = "https://www.rust-lang.org/logos/rust-logo-128x128-blk-v2.png",
       html_favicon_url = "https://doc.rust-lang.org/favicon.ico",
       html_root_url = "https://doc.rust-lang.org/net2-rs")]

#[cfg(unix)] extern crate libc;
#[cfg(unix)] #[macro_use] extern crate cfg_if;

#[cfg(windows)] extern crate kernel32;
#[cfg(windows)] extern crate winapi;
#[cfg(windows)] extern crate ws2_32;


use utils::NetInt;

mod socket;
mod utils;

#[cfg(unix)] #[path = "sys/unix/mod.rs"] mod sys;
#[cfg(windows)] #[path = "sys/windows.rs"] mod sys;

pub struct Socket {
    inner: sys::Socket,
}

pub struct Domain(i32);

pub struct Type(i32);

pub struct Protocol(i32);

fn hton<I: NetInt>(i: I) -> I { i.to_be() }

fn ntoh<I: NetInt>(i: I) -> I { I::from_be(i) }
