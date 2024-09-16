# Socket2-plus

This is a superset of [`socket2`](https://crates.io/crates/socket2) that aims to provide some additional APIs currently missing from `socket2`. This library can be used by a dropped-in replacement for socket2.

The following APIs are added in the first version:

- `recv_from_initialized` to support `recv_from` with a regular initialized buffer.
- `recvmsg_initialized` to support `recvmsg` with `MsgHdrInit` that has initialized buffers.
- Also support Windows for `recvmsg_initialized`.

This first version is forked from `socket2` v0.5.7. We plan to rebase to the latest `socket2` stable release regularly.

# Minimum Supported Rust Version (MSRV)

Socket2 uses 1.63.0 as MSRV.

# License

This project is licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
   https://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or
   https://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this project by you, as defined in the Apache-2.0 license,
shall be dual licensed as above, without any additional terms or conditions.
