use std::fmt;
use std::mem;

/// Returns the space required in a control message buffer for a single message
/// with `data_len` bytes of ancillary data.
///
/// Returns `None` if `data_len` does not fit in `libc::c_uint`.
///
/// Corresponds to `CMSG_SPACE(3)`.
pub fn cmsg_space(data_len: usize) -> Option<usize> {
    let len = libc::c_uint::try_from(data_len).ok()?;
    // SAFETY: pure arithmetic.
    usize::try_from(unsafe { libc::CMSG_SPACE(len) }).ok()
}

/// A control message parsed from a `recvmsg(2)` control buffer.
///
/// Returned by [`ControlMessages`].
pub struct ControlMessage<'a> {
    cmsg_level: i32,
    cmsg_type: i32,
    data: &'a [u8],
}

impl<'a> ControlMessage<'a> {
    /// Corresponds to `cmsg_level` in `cmsghdr`.
    pub fn cmsg_level(&self) -> i32 {
        self.cmsg_level
    }

    /// Corresponds to `cmsg_type` in `cmsghdr`.
    pub fn cmsg_type(&self) -> i32 {
        self.cmsg_type
    }

    /// The ancillary data payload.
    ///
    /// Corresponds to the data portion following the `cmsghdr`.
    pub fn data(&self) -> &'a [u8] {
        self.data
    }
}

impl<'a> fmt::Debug for ControlMessage<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        "ControlMessage".fmt(fmt)
    }
}

/// Iterator over control messages in a `recvmsg(2)` control buffer.
///
/// See [`crate::MsgHdrMut::with_control`] and [`crate::MsgHdrMut::control_len`].
pub struct ControlMessages<'a> {
    buf: &'a [u8],
    offset: usize,
}

impl<'a> ControlMessages<'a> {
    /// Create a new `ControlMessages` from the filled control buffer.
    ///
    /// Pass `&raw_buf[..msg.control_len()]` where `raw_buf` is the slice
    /// passed to [`crate::MsgHdrMut::with_control`] before calling `recvmsg(2)`.
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, offset: 0 }
    }
}

impl<'a> Iterator for ControlMessages<'a> {
    type Item = ControlMessage<'a>;

    #[allow(clippy::useless_conversion)]
    fn next(&mut self) -> Option<Self::Item> {
        let hdr_size = mem::size_of::<libc::cmsghdr>();
        // SAFETY: pure arithmetic; gives CMSG_ALIGN(sizeof(cmsghdr)).
        let data_offset: usize =
            usize::try_from(unsafe { libc::CMSG_LEN(0) }).unwrap_or(usize::MAX);

        if self.offset + hdr_size > self.buf.len() {
            return None;
        }

        // SAFETY: range is within `buf`; read_unaligned handles any alignment.
        let cmsg: libc::cmsghdr = unsafe {
            std::ptr::read_unaligned(self.buf.as_ptr().add(self.offset) as *const libc::cmsghdr)
        };

        let total_len = usize::try_from(cmsg.cmsg_len).unwrap_or(0);
        if total_len < data_offset {
            return None;
        }
        let data_len = total_len - data_offset;

        let data_abs_start = self.offset + data_offset;
        let data_abs_end = data_abs_start.saturating_add(data_len);
        if data_abs_end > self.buf.len() {
            return None;
        }

        let item = ControlMessage {
            cmsg_level: cmsg.cmsg_level,
            cmsg_type: cmsg.cmsg_type,
            data: &self.buf[data_abs_start..data_abs_end],
        };

        // SAFETY: pure arithmetic; CMSG_SPACE(data_len) == CMSG_ALIGN(total_len).
        let advance = match libc::c_uint::try_from(data_len) {
            Ok(dl) => usize::try_from(unsafe { libc::CMSG_SPACE(dl) }).unwrap_or(usize::MAX),
            Err(_) => return None,
        };
        self.offset = self.offset.saturating_add(advance);

        Some(item)
    }
}

impl<'a> fmt::Debug for ControlMessages<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        "ControlMessages".fmt(fmt)
    }
}

/// Builds a control message buffer for use with `sendmsg(2)`.
///
/// See [`crate::MsgHdr::with_control`] and [`cmsg_space`].
pub struct ControlMessageEncoder<'a> {
    buf: &'a mut [u8],
    len: usize,
}

impl<'a> ControlMessageEncoder<'a> {
    /// Create a new `ControlMessageEncoder` backed by `buf`.
    ///
    /// Zeroes `buf` on creation to ensure padding bytes are clean.
    /// Allocate `buf` with the sum of [`cmsg_space`] for each intended message.
    pub fn new(buf: &'a mut [u8]) -> Self {
        buf.fill(0);
        Self { buf, len: 0 }
    }

    /// Append a control message carrying `data`.
    ///
    /// Returns `Err` if `data` exceeds `c_uint::MAX` or the buffer is too small.
    pub fn push(&mut self, cmsg_level: i32, cmsg_type: i32, data: &[u8]) -> std::io::Result<()> {
        let data_len_uint = libc::c_uint::try_from(data.len()).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "ancillary data payload too large (exceeds c_uint::MAX)",
            )
        })?;
        // SAFETY: pure arithmetic.
        let space: usize =
            usize::try_from(unsafe { libc::CMSG_SPACE(data_len_uint) }).unwrap_or(usize::MAX);
        if self.len + space > self.buf.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "control message buffer too small",
            ));
        }
        // SAFETY: pure arithmetic.
        let cmsg_len = unsafe { libc::CMSG_LEN(data_len_uint) };
        unsafe {
            // SAFETY: offset is within buf; write_unaligned handles alignment 1.
            // Use zeroed() + field assignment to handle platform-specific padding
            // (e.g. musl adds __pad1); buf is pre-zeroed but the write must be
            // self-contained for correctness.
            let cmsg_ptr = self.buf.as_mut_ptr().add(self.len) as *mut libc::cmsghdr;
            let mut hdr: libc::cmsghdr = mem::zeroed();
            hdr.cmsg_len = cmsg_len as _;
            hdr.cmsg_level = cmsg_level;
            hdr.cmsg_type = cmsg_type;
            std::ptr::write_unaligned(cmsg_ptr, hdr);
            // SAFETY: CMSG_DATA gives the correct offset past alignment padding.
            let data_ptr = libc::CMSG_DATA(cmsg_ptr);
            std::ptr::copy_nonoverlapping(data.as_ptr(), data_ptr, data.len());
        }
        self.len += space;
        Ok(())
    }

    /// Returns the encoded bytes.
    ///
    /// Corresponds to the slice to pass to [`crate::MsgHdr::with_control`].
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    /// Returns the number of bytes written.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns `true` if no control messages have been pushed.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl<'a> fmt::Debug for ControlMessageEncoder<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        "ControlMessageEncoder".fmt(fmt)
    }
}
