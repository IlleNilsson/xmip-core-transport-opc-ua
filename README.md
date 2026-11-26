# xmip-core-transport-opc-ua

OPC UA transport: one node's value is one Stream — the binary encoding over TCP, a secure channel with security policy None, an anonymous session, a Read and a Write of a ByteString, against a server or the in-process one this crate carries. A technology of [xmip-core-transport](https://github.com/IlleNilsson/xmip-core-transport).

A Send Location writes on a session activated once per endpoint and kept (`transport::Pool`), let go before its channel token nears the end of its lifetime. Until 2026-09-27 every write opened a channel and a session and closed both.

A Receive Location reads its node on the same kept session. Until 2026-09-28 every receive opened a channel and a session and closed both.

A send target is read by `net::Target` in [xmip-core-library-net](https://github.com/IlleNilsson/xmip-core-library-net), the one reading of a URI every technology calls. Until 2026-09-28 this technology stripped its scheme by hand.

## Acknowledgement

A receive is a `Read` of the node's value, which consumes nothing at the
server. Its verdict therefore has nothing to tell the server, whichever it is:
a receive cycle that did not complete loses nothing, and the next read finds
the value again. The value arrives whole.

## The declaration

What a Location of this technology is configured with is two `const`s in its `declaration` module, `src/declaration.rs`, beside the code, which `Configured` reads (ADR-0064, amendment 2026-11-26): `declaration::SETTINGS`, `node` and `timeout`, and `SCHEMES`, `opc.tcp`. Built with its `declaration` feature alone (`--no-default-features --features declaration`), the crate is those and nothing more: its code and every crate the code is built on are behind the default feature. So the library the surfaces load carries it without the code, through the gathering crate xmip-core-declaration (open problem 48), and the language server and the desktop suggest and check an OPC UA Location's settings though no node in their process loaded the technology. `test/Declaration.Test.ps1` in the estate holds that the declaration builds nothing the transport capability does not.

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
