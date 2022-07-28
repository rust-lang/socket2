use std::convert::TryInto as _;
use std::io::IoSlice;
use std::mem;

#[derive(Debug, Clone)]
struct MsgHdrWalker<B> {
    buffer: B,
    position: Option<usize>,
}

impl<B: AsRef<[u8]>> MsgHdrWalker<B> {
    fn next_ptr(&mut self) -> Option<*const libc::cmsghdr> {
        // Build a msghdr so we can use the functionality in libc.
        let mut msghdr: libc::msghdr = unsafe { std::mem::zeroed() };
        let buffer = self.buffer.as_ref();
        // SAFETY: We're giving msghdr a mutable pointer to comply with the C
        // API. We'll only allow mutation of `cmsghdr`, however if `B` is
        // AsMut<[u8]>.
        msghdr.msg_control = buffer.as_ptr() as *mut _;
        msghdr.msg_controllen = buffer.len().try_into().expect("buffer is too long");

        let nxt_hdr = if let Some(position) = self.position {
            if position >= buffer.len() {
                return None;
            }
            let cur_hdr = &buffer[position] as *const u8 as *const _;
            // Safety: msghdr is a valid pointer and cur_hdr is not null.
            unsafe { libc::CMSG_NXTHDR(&msghdr, cur_hdr) }
        } else {
            // Safety: msghdr is a valid pointer.
            unsafe { libc::CMSG_FIRSTHDR(&msghdr) }
        };

        if nxt_hdr.is_null() {
            self.position = Some(buffer.len());
            return None;
        }

        // SAFETY: nxt_hdr always points to data within the buffer, they must be
        // part of the same allocation.
        let distance = unsafe { (nxt_hdr as *const u8).offset_from(buffer.as_ptr()) };
        // nxt_hdr is always ahead of the buffer and not null if we're here,
        // meaning the distance is always positive.
        self.position = Some(distance.try_into().unwrap());
        Some(nxt_hdr)
    }

    fn next(&mut self) -> Option<(&libc::cmsghdr, &[u8])> {
        self.next_ptr().map(|cmsghdr| {
            // SAFETY: cmsghdr is a valid pointer given to us by `next_ptr`.
            let data = unsafe { libc::CMSG_DATA(cmsghdr) };
            let cmsghdr = unsafe { &*cmsghdr };
            // SAFETY: Only copied values; need to grab the baseline for length.
            let hdr_len = unsafe { libc::CMSG_LEN(0) } as usize;
            // SAFETY: data points to buffer and is controlled by control
            // message length.
            let data = unsafe {
                std::slice::from_raw_parts(
                    data,
                    (cmsghdr.cmsg_len as usize).saturating_sub(hdr_len),
                )
            };
            (cmsghdr, data)
        })
    }
}

impl<B: AsRef<[u8]> + AsMut<[u8]>> MsgHdrWalker<B> {
    fn next_mut(&mut self) -> Option<(&mut libc::cmsghdr, &mut [u8])> {
        match self.next_ptr() {
            Some(cmsghdr) => {
                // SAFETY: cmsghdr is a valid pointer given to us by `next_ptr`.
                let data = unsafe { libc::CMSG_DATA(cmsghdr) };
                // SAFETY: The mutable pointer is safe because we're not going to
                // vend any concurrent access to the same memory region and B is
                // AsMut<[u8]> guaranteeing we have exclusive access to the buffer.
                let cmsghdr = cmsghdr as *mut libc::cmsghdr;
                let cmsghdr = unsafe { &mut *cmsghdr };

                // We'll always yield the entirety of the rest of the buffer.
                let distance = unsafe { data.offset_from(self.buffer.as_ref().as_ptr()) };
                // The data pointer is always part of the buffer, can't be before
                // it.
                let distance: usize = distance.try_into().unwrap();
                Some((cmsghdr, &mut self.buffer.as_mut()[distance..]))
            }
            None => None,
        }
    }
}

/// A wrapper around a buffer that can be used to write ancillary control
/// messages.
#[derive(Debug)]
pub struct CmsgWriter<'a> {
    walker: MsgHdrWalker<&'a mut [u8]>,
    last_push: usize,
}

impl<'a> CmsgWriter<'a> {
    /// Creates a new [`CmsgBuffer`] backed by the bytes in `buffer`.
    pub fn new(buffer: &'a mut [u8]) -> Self {
        Self {
            walker: MsgHdrWalker {
                buffer,
                position: None,
            },
            last_push: 0,
        }
    }

    /// Pushes a new control message `m` to the buffer.
    ///
    /// # Panics
    ///
    /// Panics if the contained buffer does not have enough space to fit `m`.
    pub fn push(&mut self, m: &Cmsg) {
        let (cmsg_level, cmsg_type, size) = m.level_type_size();
        let (nxt_hdr, data) = self
            .walker
            .next_mut()
            .unwrap_or_else(|| panic!("can't fit message {:?}", m));
        // Safety: All values are passed by copy.
        let cmsg_len = unsafe { libc::CMSG_LEN(size) }.try_into().unwrap();
        nxt_hdr.cmsg_len = cmsg_len;
        nxt_hdr.cmsg_level = cmsg_level;
        nxt_hdr.cmsg_type = cmsg_type;
        m.write(&mut data[..size as usize]);
        // Always store the space required for the last push because the walker
        // maintains its position cursor at the currently written option, we
        // must always add the space for the last control message when returning
        // the consolidated buffer.
        self.last_push = unsafe { libc::CMSG_SPACE(size) } as usize;
    }

    pub(crate) fn io_slice(&self) -> IoSlice<'_> {
        IoSlice::new(self.buffer())
    }

    pub(crate) fn buffer(&self) -> &[u8] {
        if let Some(position) = self.walker.position {
            &self.walker.buffer.as_ref()[..position + self.last_push]
        } else {
            &[]
        }
    }
}

impl<'a, C: std::borrow::Borrow<Cmsg>> Extend<C> for CmsgWriter<'a> {
    fn extend<T: IntoIterator<Item = C>>(&mut self, iter: T) {
        for cmsg in iter {
            self.push(cmsg.borrow())
        }
    }
}

/// A buffer for receiving control messages.
///
/// Used as a control message target in [`crate::Socket::recv_msg`].
#[derive(Debug)]
pub struct CmsgBuffer<'a> {
    buffer: &'a mut [mem::MaybeUninit<u8>],
}

impl<'a> CmsgBuffer<'a> {
    /// Creates a new buffer to receive ancillary data in.
    pub fn new(buffer: &'a mut [mem::MaybeUninit<u8>]) -> Self {
        Self { buffer }
    }

    pub(crate) fn into_buffer(self) -> &'a mut [mem::MaybeUninit<u8>] {
        self.buffer
    }
}

/// An iterator over received control messages.
#[derive(Debug, Clone)]
pub struct CmsgIter<'a> {
    walker: MsgHdrWalker<&'a [u8]>,
}

impl<'a> CmsgIter<'a> {
    pub(crate) fn new(buffer: &'a [u8]) -> Self {
        Self {
            walker: MsgHdrWalker {
                buffer,
                position: None,
            },
        }
    }
}

impl<'a> Iterator for CmsgIter<'a> {
    type Item = Cmsg;

    fn next(&mut self) -> Option<Self::Item> {
        self.walker.next().map(
            |(
                libc::cmsghdr {
                    cmsg_len: _,
                    cmsg_level,
                    cmsg_type,
                    ..
                },
                data,
            )| Cmsg::from_raw(*cmsg_level, *cmsg_type, data),
        )
    }
}

/// An unknown control message.
#[derive(Debug, Eq, PartialEq)]
pub struct UnknownCmsg {
    cmsg_level: libc::c_int,
    cmsg_type: libc::c_int,
}

/// Control messages.
#[derive(Debug, Eq, PartialEq)]
pub enum Cmsg {
    /// The `IP_TOS` control message.
    #[cfg(not(any(target_os = "solaris", target_os = "illumos")))]
    IpTos(u8),
    /// The `IPV6_PKTINFO` control message.
    #[cfg(not(any(target_os = "fuchsia", target_os = "solaris", target_os = "illumos")))]
    Ipv6PktInfo {
        /// The address the packet is destined to/received from. Equivalent to
        /// `in6_pktinfo.ipi6_addr`.
        addr: std::net::Ipv6Addr,
        /// The interface index the packet is destined to/received from.
        /// Equivalent to `in6_pktinfo.ipi6_ifindex`.
        ifindex: u32,
    },
    /// An unrecognized control message.
    Unknown(UnknownCmsg),
}

impl Cmsg {
    /// Returns the amount of buffer space required to hold this option.
    pub fn space(&self) -> usize {
        let (_, _, size) = self.level_type_size();
        // Safety: All values are passed by copy.
        let size = unsafe { libc::CMSG_SPACE(size) };
        size as usize
    }

    fn level_type_size(&self) -> (libc::c_int, libc::c_int, libc::c_uint) {
        match self {
            #[cfg(not(any(target_os = "solaris", target_os = "illumos")))]
            Cmsg::IpTos(_) => {
                #[cfg(not(target_os = "macos"))]
                let len = mem::size_of::<u8>();
                #[cfg(target_os = "macos")]
                let len = mem::size_of::<i32>();
                (libc::IPPROTO_IP, libc::IP_TOS, len as libc::c_uint)
            }
            #[cfg(not(any(target_os = "fuchsia", target_os = "solaris", target_os = "illumos")))]
            Cmsg::Ipv6PktInfo { .. } => (
                libc::IPPROTO_IPV6,
                libc::IPV6_PKTINFO,
                mem::size_of::<libc::in6_pktinfo>() as libc::c_uint,
            ),
            Cmsg::Unknown(UnknownCmsg {
                cmsg_level,
                cmsg_type,
            }) => (*cmsg_level, *cmsg_type, 0),
        }
    }

    fn write(&self, buffer: &mut [u8]) {
        match self {
            #[cfg(not(any(target_os = "solaris", target_os = "illumos")))]
            Cmsg::IpTos(tos) => {
                #[cfg(not(target_os = "macos"))]
                {
                    buffer[0] = *tos;
                }
                #[cfg(target_os = "macos")]
                {
                    let value = *tos as i32;
                    buffer.copy_from_slice(&value.to_ne_bytes()[..])
                }
            }
            #[cfg(not(any(target_os = "fuchsia", target_os = "solaris", target_os = "illumos")))]
            Cmsg::Ipv6PktInfo { addr, ifindex } => {
                let pktinfo = libc::in6_pktinfo {
                    ipi6_addr: crate::sys::to_in6_addr(addr),
                    ipi6_ifindex: *ifindex as _,
                };
                let size = mem::size_of::<libc::in6_pktinfo>();
                assert_eq!(buffer.len(), size);
                // Safety: `pktinfo` is valid for reads for its size in bytes.
                // `buffer` is valid for write for the same length, as
                // guaranteed by the assertion above. Copy unit is byte, so
                // alignment is okay. The two regions do not overlap.
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        &pktinfo as *const libc::in6_pktinfo as *const _,
                        buffer.as_mut_ptr(),
                        size,
                    )
                }
            }
            Cmsg::Unknown(_) => {
                // NOTE: We don't actually allow users of the public API
                // serialize unknown control messages, but we use this code path
                // for testing.
                debug_assert_eq!(buffer.len(), 0);
            }
        }
    }

    fn from_raw(cmsg_level: libc::c_int, cmsg_type: libc::c_int, bytes: &[u8]) -> Self {
        match (cmsg_level, cmsg_type) {
            #[cfg(not(any(target_os = "solaris", target_os = "illumos")))]
            (libc::IPPROTO_IP, libc::IP_TOS) => {
                // Different systems encode received TOS as char or int.
                match bytes {
                    [b] => Cmsg::IpTos(*b),
                    [a, b, c, d] => Cmsg::IpTos(i32::from_ne_bytes([*a, *b, *c, *d]) as u8),
                    other => panic!("unexpected length for IP_TOS: {:?}", other),
                }
            }
            #[cfg(any(target_os = "freebsd", target_os = "macos"))]
            (libc::IPPROTO_IP, libc::IP_RECVTOS) => {
                // Some systems use IP_RECVTOS on the receive path.
                Self::from_raw(libc::IPPROTO_IP, libc::IP_TOS, bytes)
            }
            #[cfg(not(any(target_os = "fuchsia", target_os = "solaris", target_os = "illumos")))]
            (libc::IPPROTO_IPV6, libc::IPV6_PKTINFO) => {
                let mut pktinfo = unsafe { std::mem::zeroed::<libc::in6_pktinfo>() };
                let size = mem::size_of::<libc::in6_pktinfo>();
                assert!(bytes.len() >= size, "{:?}", bytes);
                // Safety: `pktinfo` is valid for writes for its size in bytes.
                // `buffer` is valid for read for the same length, as
                // guaranteed by the assertion above. Copy unit is byte, so
                // alignment is okay. The two regions do not overlap.
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        bytes.as_ptr(),
                        &mut pktinfo as *mut libc::in6_pktinfo as *mut _,
                        size,
                    )
                }
                Cmsg::Ipv6PktInfo {
                    addr: crate::sys::from_in6_addr(pktinfo.ipi6_addr),
                    ifindex: pktinfo.ipi6_ifindex as _,
                }
            }
            (cmsg_level, cmsg_type) => {
                let _ = bytes;
                Cmsg::Unknown(UnknownCmsg {
                    cmsg_level,
                    cmsg_type,
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ser_deser() {
        let cmsgs = [
            #[cfg(not(any(target_os = "solaris", target_os = "illumos")))]
            Cmsg::IpTos(2),
            #[cfg(not(any(target_os = "fuchsia", target_os = "solaris", target_os = "illumos")))]
            Cmsg::Ipv6PktInfo {
                addr: std::net::Ipv6Addr::new(1, 2, 3, 4, 5, 6, 7, 8),
                ifindex: 13,
            },
            Cmsg::Unknown(UnknownCmsg {
                cmsg_level: 12345678,
                cmsg_type: 87654321,
            }),
        ];
        let mut buffer = [0u8; 256];
        let mut writer = CmsgWriter::new(&mut buffer[..]);
        writer.extend(cmsgs.iter());
        let deser = CmsgIter::new(writer.buffer()).collect::<Vec<_>>();
        assert_eq!(&cmsgs[..], &deser[..]);
    }

    #[test]
    #[should_panic]
    #[cfg(not(any(target_os = "solaris", target_os = "illumos")))]
    fn ser_insufficient_space_panics() {
        let mut buffer = CmsgWriter::new(&mut []);
        buffer.push(&Cmsg::IpTos(2));
    }

    #[test]
    fn empty_deser() {
        assert_eq!(CmsgIter::new(&[]).next(), None);
    }
}
