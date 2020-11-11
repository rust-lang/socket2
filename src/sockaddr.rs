use std::mem::{self, MaybeUninit};
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};
use std::{fmt, ptr};

use crate::sys::{
    sa_family_t, sockaddr, sockaddr_in, sockaddr_in6, sockaddr_storage, socklen_t, AF_INET,
    AF_INET6,
};
#[cfg(windows)]
use winapi::shared::ws2ipdef::SOCKADDR_IN6_LH_u;

/// The address of a socket.
///
/// `SockAddr`s may be constructed directly to and from the standard library
/// `SocketAddr`, `SocketAddrV4`, and `SocketAddrV6` types.
pub struct SockAddr {
    storage: sockaddr_storage,
    len: socklen_t,
}

impl SockAddr {
    /// Constructs a `SockAddr` from its raw components.
    ///
    /// # Safety
    ///
    /// It is up to the user to ensure the `addr` pointer and `len` length are
    /// correct.
    pub unsafe fn from_raw_parts(addr: *const sockaddr, len: socklen_t) -> SockAddr {
        let mut storage = MaybeUninit::<sockaddr_storage>::zeroed();
        ptr::copy_nonoverlapping(
            addr as *const _ as *const u8,
            storage.as_mut_ptr() as *mut u8,
            len as usize,
        );
        SockAddr {
            // This is safe as we written the address to `storage` above.
            storage: storage.assume_init(),
            len,
        }
    }

    /// Constructs a `SockAddr` from its raw components.
    pub(crate) const fn from_raw(storage: sockaddr_storage, len: socklen_t) -> SockAddr {
        SockAddr { storage, len }
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

    /// Returns this address as a `SocketAddr` if it is in the `AF_INET` (IP v4)
    /// or `AF_INET6` (IP v6) family, otherwise returns `None`.
    pub fn as_std(&self) -> Option<SocketAddr> {
        if self.storage.ss_family == AF_INET as sa_family_t {
            // Safety: if the ss_family field is AF_INET then storage must be a sockaddr_in.
            let addr = unsafe { &*(&self.storage as *const _ as *const sockaddr_in) };

            let ip = crate::sys::from_in_addr(addr.sin_addr);
            let port = u16::from_be(addr.sin_port);
            Some(SocketAddr::V4(SocketAddrV4::new(ip, port)))
        } else if self.storage.ss_family == AF_INET6 as sa_family_t {
            // Safety: if the ss_family field is AF_INET6 then storage must be a sockaddr_in6.
            let addr = unsafe { &*(&self.storage as *const _ as *const sockaddr_in6) };

            let ip = crate::sys::from_in6_addr(addr.sin6_addr);
            let port = u16::from_be(addr.sin6_port);
            Some(SocketAddr::V6(SocketAddrV6::new(
                ip,
                port,
                addr.sin6_flowinfo,
                #[cfg(unix)]
                addr.sin6_scope_id,
                #[cfg(windows)]
                unsafe {
                    *addr.u.sin6_scope_id()
                },
            )))
        } else {
            None
        }
    }

    /// Returns this address as a `SocketAddrV4` if it is in the `AF_INET`
    /// family.
    pub fn as_inet(&self) -> Option<SocketAddrV4> {
        match self.as_std() {
            Some(SocketAddr::V4(addr)) => Some(addr),
            _ => None,
        }
    }

    /// Returns this address as a `SocketAddrV6` if it is in the `AF_INET6`
    /// family.
    pub fn as_inet6(&self) -> Option<SocketAddrV6> {
        match self.as_std() {
            Some(SocketAddr::V6(addr)) => Some(addr),
            _ => None,
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

impl From<SocketAddrV4> for SockAddr {
    fn from(addr: SocketAddrV4) -> SockAddr {
        let sockaddr_in = sockaddr_in {
            sin_family: AF_INET as sa_family_t,
            sin_port: addr.port().to_be(),
            sin_addr: crate::sys::to_in_addr(&addr.ip()),
            sin_zero: [0; 8],
            #[cfg(any(
                target_os = "dragonfly",
                target_os = "freebsd",
                target_os = "ios",
                target_os = "macos",
                target_os = "netbsd",
                target_os = "openbsd"
            ))]
            sin_len: 0,
        };
        let mut storage = MaybeUninit::<sockaddr_storage>::zeroed();
        // Safety: A `sockaddr_in` is memory compatible with a `sockaddr_storage`
        unsafe { (storage.as_mut_ptr() as *mut sockaddr_in).write(sockaddr_in) };
        SockAddr {
            storage: unsafe { storage.assume_init() },
            len: mem::size_of::<sockaddr_in>() as socklen_t,
        }
    }
}

impl From<SocketAddrV6> for SockAddr {
    fn from(addr: SocketAddrV6) -> SockAddr {
        #[cfg(windows)]
        let u = unsafe {
            let mut u = mem::zeroed::<SOCKADDR_IN6_LH_u>();
            *u.sin6_scope_id_mut() = addr.scope_id();
            u
        };

        let sockaddr_in6 = sockaddr_in6 {
            sin6_family: AF_INET6 as sa_family_t,
            sin6_port: addr.port().to_be(),
            sin6_addr: crate::sys::to_in6_addr(addr.ip()),
            sin6_flowinfo: addr.flowinfo(),
            #[cfg(unix)]
            sin6_scope_id: addr.scope_id(),
            #[cfg(windows)]
            u,
            #[cfg(any(
                target_os = "dragonfly",
                target_os = "freebsd",
                target_os = "ios",
                target_os = "macos",
                target_os = "netbsd",
                target_os = "openbsd"
            ))]
            sin6_len: 0,
            #[cfg(any(target_os = "solaris", target_os = "illumos"))]
            __sin6_src_id: 0,
        };
        let mut storage = MaybeUninit::<sockaddr_storage>::zeroed();
        // Safety: A `sockaddr_in6` is memory compatible with a `sockaddr_storage`
        unsafe { (storage.as_mut_ptr() as *mut sockaddr_in6).write(sockaddr_in6) };
        SockAddr {
            storage: unsafe { storage.assume_init() },
            len: mem::size_of::<sockaddr_in6>() as socklen_t,
        }
    }
}

impl fmt::Debug for SockAddr {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut f = fmt.debug_struct("SockAddr");
        #[cfg(any(
            target_os = "dragonfly",
            target_os = "freebsd",
            target_os = "haiku",
            target_os = "hermit",
            target_os = "ios",
            target_os = "macos",
            target_os = "netbsd",
            target_os = "openbsd",
            target_os = "vxworks",
        ))]
        f.field("ss_len", &self.storage.ss_len);
        f.field("ss_family", &self.storage.ss_family)
            .field("len", &self.len)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn conversion_v4() {
        let addr = SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 9876);
        let sockaddr = SockAddr::from(addr);
        assert_eq!(sockaddr.family(), AF_INET as sa_family_t);
        assert!(sockaddr.as_inet6().is_none());
        assert_eq!(sockaddr.as_inet(), Some(addr));
        assert_eq!(sockaddr.as_std(), Some(SocketAddr::V4(addr)));
    }

    #[test]
    fn conversion_v6() {
        let addr = SocketAddrV6::new(Ipv6Addr::new(1, 2, 3, 4, 5, 6, 7, 8), 9876, 11, 12);
        let sockaddr = SockAddr::from(addr);
        assert_eq!(sockaddr.family(), AF_INET6 as sa_family_t);
        assert!(sockaddr.as_inet().is_none());
        assert_eq!(sockaddr.as_inet6(), Some(addr));
        assert_eq!(sockaddr.as_std(), Some(SocketAddr::V6(addr)));
    }
}
