# xmip-core-transport-opc-ua

OPC UA transport: one node's value is one Stream — the binary encoding over TCP, a secure channel with security policy None, an anonymous session, a Read and a Write of a ByteString, against a server or the in-process one this crate carries. A technology of [xmip-core-transport](https://github.com/IlleNilsson/xmip-core-transport).

A Send Location writes on a session activated once per endpoint and kept (`transport::Pool`), let go before its channel token nears the end of its lifetime. Until 2026-09-27 every write opened a channel and a session and closed both.

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
