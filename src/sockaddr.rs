use std::mem::{self, MaybeUninit};
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};
use std::{fmt, ptr};

use crate::sys::{
    c_int, sa_family_t, sockaddr, sockaddr_in, sockaddr_in6, sockaddr_storage, socklen_t, AF_INET,
    AF_INET6,
};

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
        let mut storage = MaybeUninit::<sockaddr_storage>::uninit();
        ptr::copy_nonoverlapping(
            addr as *const _ as *const u8,
            storage.as_mut_ptr() as *mut u8,
            len as usize,
        );
        SockAddr {
            // This is safe as we written the address to `storage` above.
            storage: storage.assume_init(),
            len: len,
        }
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
        self.as_inet()
            .map(|a| a.into())
            .or_else(|| self.as_inet6().map(|a| a.into()))
    }

    /// Returns this address as a `SocketAddrV4` if it is in the `AF_INET`
    /// family.
    pub fn as_inet(&self) -> Option<SocketAddrV4> {
        if self.storage.ss_family as c_int == AF_INET {
            let storage: *const sockaddr_storage = (&self.storage) as *const _;
            Some(unsafe { *(storage as *const sockaddr_in as *const _) })
        } else {
            None
        }
    }

    /// Returns this address as a `SocketAddrV6` if it is in the `AF_INET6`
    /// family.
    pub fn as_inet6(&self) -> Option<SocketAddrV6> {
        if self.storage.ss_family as c_int == AF_INET6 {
            let storage: *const sockaddr_storage = (&self.storage) as *const _;
            Some(unsafe { *(storage as *const sockaddr_in6 as *const _) })
        } else {
            None
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
        unsafe {
            SockAddr::from_raw_parts(
                &addr as *const _ as *const _,
                mem::size_of::<SocketAddrV4>() as socklen_t,
            )
        }
    }
}

impl From<SocketAddrV6> for SockAddr {
    fn from(addr: SocketAddrV6) -> SockAddr {
        unsafe {
            SockAddr::from_raw_parts(
                &addr as *const _ as *const _,
                mem::size_of::<SocketAddrV6>() as socklen_t,
            )
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
