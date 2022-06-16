# Contributing to Socket2

There are many ways to contribute to Socket2, including (but not limited to)
answering questions, adding new features, fixing bugs or expanding the
documentation. This document will focus on adding new features and fixing bugs.

If you're adding a new feature please first [open an issue] laying out what
would be added and a design you're proposing. Doing this before actually writing
the code will save you time if others suggest improvements to the design. Once
there is some consensus on 1) the feature is a good addition to Socket2 and 2)
the proposed design is the right one, open a [pull request] with the changes.

If you're working on fixing a bug please say so on the specific issue so that
two people don't work on fixing the same bug. For more complex bugs or fixes
please also share your proposed design on the issue tracker, same as for new
features.

Once you're working on the code it's useful to understand where the code is (or
should) be located, the [code structure section] describes how the code of
Socket2 is organised.

To make sure we don't create the same bug again, or to ensure that new features
keep working, please add (regression) test for the changes you've made to the
code. The [testing section] below describes how to run the tests and where to
add new tests.

[open an issue]: https://github.com/rust-lang/socket2/issues/new
[pull request]: https://github.com/rust-lang/socket2/compare
[code structure section]: #code-structure
[testing section]: #testing

# Code structure

All types and methods that are available on all tier 1 platforms are defined in
the first level of the source, i.e. `src/*.rs` files. Additional API that is
platform specific, e.g. `Domain::UNIX`, is defined in `src/sys/*.rs` and only
for the platforms that support it. For API that is not available on all tier 1
platforms the `all` feature is used, to indicate to the user that they're using
API that might is not available on all platforms.

The main `Socket` type is defined in `src/socket.rs` with additional methods
defined on in the the `src/sys/*.rs` files, as per above. The methods on
`Socket` are split into multiple `impl` blocks. The first `impl` block contains
a collection of system calls for creating and using the socket, e.g.
`socket(2)`, `bind(2)`, `listen(2)`, etc. The other implementation blocks are
for getting and setting socket options on various levels, e.g. `SOL_SOCKET`,
where each block contains a single level. The methods in these block are sorted
based on the option name, e.g. `IP_ADD_MEMBERSHIP` rather than
`join_multicast_v4`. Finally the last block contains platforms specific methods
such as `Socket::freebind` which is (at the time of writing) only available on
Android, Linux and Fuchsia, which is defined in the `src/sys/*.rs` files.

Other types are mostly defined in `src/lib.rs`, except for `SockAddr` and
`SockRef` which have there own file. These types follow the same structure as
`Socket`, where OS specific methods are defined in `src/sys/*.rs`, e.g.
`Type::cloexec`.

# Testing

Testing Socket2 is as simple as running `cargo test --all-features`.

However Socket2 supports a good number of OSs and features. If you want to
test/check all those combinations it's easier to use the [Makefile]. Using `make
test_all` it will check all supported OS targets and all combinations of
supported features. Note that this requires [cargo-hack] and various rustup
targets to be installed. Cargo-hack must be installed manually, the various
targets can be installed automatically using `make install_targets` (which uses
[rustup]).

[Makefile]: ./Makefile
[cargo-hack]: https://crates.io/crates/cargo-hack
[rustup]: https://rustup.rs

## Adding a test

Tests should be added to `tests/socket.rs`, following (roughly) the same order
in which the methods are defined on a type. At the bottom of this file it has a
macro to create a simple get/set socket option test, more complex API however
needs a manually written test.

Tests that need to use internal API can be defined directly at the bottom of the
source file. No need for a test module since we intend on keeping the number of
internal tests low.
