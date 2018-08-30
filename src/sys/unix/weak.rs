// Copyright 2016 The Rust Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution and at
// http://rust-lang.org/COPYRIGHT.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::marker;
use std::mem;
use std::sync::atomic::{AtomicUsize, Ordering};

use libc;

macro_rules! weak {
    (fn $name:ident($($t:ty),*) -> $ret:ty) => (
        #[allow(bad_style)]
        static $name: ::sys::weak::Weak<unsafe extern fn($($t),*) -> $ret> =
            ::sys::weak::Weak {
                name: concat!(stringify!($name), "\0"),
                addr: ::std::sync::atomic::ATOMIC_USIZE_INIT,
                _marker: ::std::marker::PhantomData,
            };
    )
}

pub struct Weak<F> {
    pub name: &'static str,
    pub addr: AtomicUsize,
    pub _marker: marker::PhantomData<F>,
}

impl<F> Weak<F> {
    pub fn get(&self) -> Option<&F> {
        assert_eq!(mem::size_of::<F>(), mem::size_of::<usize>());
        unsafe {
            if self.addr.load(Ordering::SeqCst) == 0 {
                let ptr = match fetch(self.name) {
                    1 => 1,
                    n => n,
                };
                self.addr.store(ptr, Ordering::SeqCst);
            }
            if self.addr.load(Ordering::SeqCst) == 0 {
                None
            } else {
                mem::transmute::<&AtomicUsize, Option<&F>>(&self.addr)
            }
        }
    }
}

unsafe fn fetch(name: &str) -> usize {
    let name = name.as_bytes();
    assert_eq!(name[name.len() - 1], 0);
    libc::dlsym(libc::RTLD_DEFAULT, name.as_ptr() as *const _) as usize
}
