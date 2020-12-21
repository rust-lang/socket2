# Socket2

Socket2 is a crate that provides utilities for creating and using sockets.

The goal of this crate is to create and use a socket using advanced
configuration options (those that are not available in the types in the standard
library) without using any unsafe code.

This crate provides as direct as possible access to the system's functionality
for sockets, this means little effort to provide cross-platform utilities. It is
up to the user to know how to use sockets when using this crate. *If you don't
know how to create a socket using libc/system calls then this crate is not for
you*. Most, if not all, functions directly relate to the equivalent system call
with no error handling applied, so no handling errors such as `EINTR`. As a
result using this crate can be a little wordy, but it should give you maximal
flexibility over configuration of sockets.

See the [API documentation] for more.

[API documentation]: https://docs.rs/socket2

# License

This project is licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
   http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or
   http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this project by you, as defined in the Apache-2.0 license,
shall be dual licensed as above, without any additional terms or conditions.
