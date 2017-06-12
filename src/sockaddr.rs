use std::net::{SocketAddrV4, SocketAddrV6, SocketAddr};
use std::mem;
use std::ptr;
use std::fmt;

#[cfg(unix)]
use libc::{sockaddr, sockaddr_storage, sa_family_t, socklen_t, AF_INET, AF_INET6};
#[cfg(windows)]
use winapi::{SOCKADDR as sockaddr, SOCKADDR_STORAGE as sockaddr_storage,
             ADDRESS_FAMILY as sa_family_t, socklen_t, AF_INET, AF_INET6};

use SockAddr;

impl fmt::Debug for SockAddr {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let mut builder = fmt.debug_struct("SockAddr");
        builder.field("family", &self.family());
        if let Some(addr) = self.as_inet() {
            builder.field("inet", &addr);
        } else if let Some(addr) = self.as_inet6() {
            builder.field("inet6", &addr);
        }
        builder.finish()
    }
}

impl SockAddr {
    /// Constructs a `SockAddr` from its raw components.
    pub unsafe fn from_raw_parts(addr: *const sockaddr, len: socklen_t) -> SockAddr {
        let mut storage = mem::uninitialized::<sockaddr_storage>();
        ptr::copy_nonoverlapping(addr as *const _ as *const u8,
                                 &mut storage as *mut _ as *mut u8,
                                 len as usize);

        SockAddr {
            storage: storage,
            len: len,
        }
    }

    unsafe fn as_<T>(&self, family: sa_family_t) -> Option<T> {
        if self.storage.ss_family != family {
            return None;
        }

        Some(mem::transmute_copy(&self.storage))
    }

    /// Returns this address as a `SocketAddrV4` if it is in the `AF_INET`
    /// family.
    pub fn as_inet(&self) -> Option<SocketAddrV4> {
        unsafe { self.as_(AF_INET as sa_family_t) }
    }

    /// Returns this address as a `SocketAddrV4` if it is in the `AF_INET6`
    /// family.
    pub fn as_inet6(&self) -> Option<SocketAddrV6> {
        unsafe { self.as_(AF_INET6 as sa_family_t) }
    }

    /// Returns this address's family.
    pub fn family(&self) -> sa_family_t {
        self.storage.ss_family
    }

    /// Returns the size of this address in bytes.
    pub fn len(&self) -> socklen_t {
        self.len
    }

    /// Returns a raw pointer to the address.
    pub fn as_ptr(&self) -> *const sockaddr {
        &self.storage as *const _ as *const _
    }
}

// SocketAddrV4 and SocketAddrV6 are just wrappers around sockaddr_in and sockaddr_in6

impl From<SocketAddrV4> for SockAddr {
    fn from(addr: SocketAddrV4) -> SockAddr {
        unsafe {
            SockAddr::from_raw_parts(&addr as *const _ as *const _,
                                     mem::size_of::<SocketAddrV4>() as socklen_t)
        }
    }
}


impl From<SocketAddrV6> for SockAddr {
    fn from(addr: SocketAddrV6) -> SockAddr {
        unsafe {
            SockAddr::from_raw_parts(&addr as *const _ as *const _,
                                     mem::size_of::<SocketAddrV6>() as socklen_t)
        }
    }
}

impl From<SocketAddr> for SockAddr {
    fn from(addr: SocketAddr) -> SockAddr {
        match addr {
            SocketAddr::V4(addr) => addr.into(),
            SocketAddr::V6(addr) => addr.into(),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn inet() {
        let raw = "127.0.0.1:80".parse::<SocketAddrV4>().unwrap();
        let addr = SockAddr::from(raw);
        assert!(addr.as_inet6().is_none());
        let addr = addr.as_inet().unwrap();
        assert_eq!(raw, addr);
    }

    #[test]
    fn inet6() {
        let raw = "[2001:db8::ff00:42:8329]:80"
            .parse::<SocketAddrV6>()
            .unwrap();
        let addr = SockAddr::from(raw);
        assert!(addr.as_inet().is_none());
        let addr = addr.as_inet6().unwrap();
        assert_eq!(raw, addr);
    }
}
