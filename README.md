# Ghost - The Encrypted DNS Server Tools

An easy to install, high-performance, zero maintenance proxy to run an encrypted DNS server.


## Protocols

The proxy supports the following protocols:

- [DNSCrypt v2]
- [Anonymized DNSCrypt]
- DNS-over-HTTP (DoH) forwarding

All of these can be served simultaneously, on the same port (usually port 443). The proxy automatically detects what protocol is being used by each client.

## Installation

### Option 1: precompiled x86_64 binary

Debian packages, archives for Linux and Windows [can be downloaded here]

Nothing else has to be installed. The server doesn't require any external dependencies.

In the Debian package, the example configuration file can be found in `/usr/share/doc/encrypted-dns/`.

### Option 2: compilation from source code

The proxy requires rust >= 1.0.39 or rust-nightly.

Rust can installed with:

```sh
curl -sSf https://sh.rustup.rs | bash -s -- -y --default-toolchain nightly
source $HOME/.cargo/env
```

Once rust is installed, the proxy can be compiled and installed as follows:

```sh
cargo install encrypted-dns
strip ~/.cargo/bin/encrypted-dns
```

The executable file will be copied to `~/.cargo/bin/encrypted-dns` by default.

### Options 3: Docker

[dnscrypt-server-docker] is the most popular way to deploy an encrypted DNS server.

This Docker image that includes a caching DNS resolver, the encrypted DNS proxy, and scripts to automatically configure everything.

