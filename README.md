# Clash2sing-box

Convert [Clash](https://github.com/MetaCubeX/mihomo) configurations to [sing-box](https://sing-box.sagernet.org/) configurations.

## About

### Features

#### Protocols

| Clash type  | Status | Note                                                                 |
| ----------- | ------ | -------------------------------------------------------------------- |
| `anytls`    | O      |                                                                      |
| `direct`    | O      |                                                                      |
| `http`      | O      | sing-box limitation: layer tls not supported                         |
| `hysteria`  | O      | sing-box limitation: protocol `faketcp`/`wechat-video` not supported |
| `hysteria2` | O      |                                                                      |
| `openvpn`   | ?      | TLS mode only, as an `endpoints` entry; TAP devices unsupported      |
| `reject`    | O      | Becomes a `block` outbound                                           |
| `snell`     | ?      | Only version 4: sing-box implements 4 and 6, mihomo speaks 1-5       |
| `socks5`    | O      | sing-box limitation: layer tls not supported                         |
| `ss`        | O      | Including `plugin: shadow-tls` — see below                           |
| `ssh`       | O      |                                                                      |
| `tailscale` | O      | Emitted as an `endpoints` entry — see below                          |
| `trojan`    | ?      | Trojan-Go features not implemented                                   |
| `tuic`      | O      |                                                                      |
| `vmess`     | O      | sing-box limitation: protocol tcp not supported                      |
| `vless`     | O      | sing-box limitation: protocol tcp not supported                      |
| `wireguard` | O      | Emitted as an `endpoints` entry — see below                          |

That is every mihomo proxy type sing-box can express. The rest have no counterpart:
`mieru`, `sudoku`, `shadowquic`, `masque`, `trusttunnel`, `gost-relay`, `zerotier`,
`rematch`, plus two sing-box removed outright — `ssr` (removed in 1.6.0) and `dns`
(removed in 1.13.0 in favour of route rule actions).

`direct` and `reject` stay selectable but are kept out of the generated URLTest group:
URLTest picks the lowest-latency member, and `direct` would always win the race while
`block` would always lose it.

A proxy that cannot be converted — an unknown protocol, an unsupported option, or a
malformed entry — is skipped with a warning on stderr. The rest of the subscription is
still converted.

##### Two protocols that do not map one-to-one

**ShadowTLS** is a protocol-agnostic TLS masquerade that carries no encryption of its
own, so sing-box models it as a standalone outbound that the inner proxy reaches through
`detour`, while Clash folds it into the inner proxy as a SIP003-style plugin. One
`ss` proxy with `plugin: shadow-tls` therefore becomes **two** outbounds. Only the inner
one is offered in proxy groups: selecting a bare ShadowTLS shell would give you a tunnel
with nothing inside it.

**WireGuard**, **Tailscale** and **OpenVPN** become top-level `endpoints` entries rather
than outbounds — that is where sing-box puts them (WireGuard's outbound was deprecated in
1.11.0 and removed in 1.13.0; Tailscale arrived in 1.12.0 and OpenVPN in 1.14.0). They are
still ordinary proxy targets, so groups reference them. The `endpoints` section is only
emitted when one of these is actually present.

OpenVPN carries a few judgement calls worth knowing about: mihomo's legacy `cipher` maps
to `data_ciphers_fallback` (an explicit `data-ciphers-fallback` wins), the default
`key-direction: bidirectional` is dropped because sing-box accepts only `server`/`client`,
and `dev: tap` is reported as unsupported since sing-box provides TUN only.

#### Options

| Name                               | Status | Note                                                                                  |
| ---------------------------------- | ------ | ------------------------------------------------------------------------------------- |
| Dial fields                        | O      | `udp`/`tfo`/`mptcp`/`interface-name`/`routing-mark`/`dialer-proxy`, on every protocol |
| Multiplex                          | O      | `smux` → `multiplex` (incl. `brutal-opts`), on `ss`/`trojan`/`vmess`/`vless`          |
| V2Ray transport                    | O      | `ws`/`h2`/`http`/`grpc`/`httpupgrade`, on `vmess`/`vless`/`trojan`                    |
| REALITY                            | O      | From `reality-opts`, on every TLS-capable protocol                                    |
| ECH                                | O      | From `ech-opts`                                                                       |
| uTLS fingerprint                   | O      | From `client-fingerprint`, falling back to `fingerprint`                              |
| UDP packet encoding                | O      | `packet-encoding` → `packet_encoding` (`packetaddr`/`xudp`)                           |
| IP Version                         | ?      | `ip-version` → `domain_resolver.strategy`, needs `--outbound-domainresolver-tag`      |
| TLS Certificate Pinning            | ?      | Implemented via proprietary option `x-clash2singbox-certificate`                      |
| TLS Certificate Public Key Pinning | ?      | Implemented via proprietary option `x-clash2singbox-certificate-public-key-sha256`    |

Targets the sing-box `testing` branch (1.14.0-alpha). `domain_strategy` is deliberately
not emitted: it was deprecated in 1.12.0 and removed in 1.14.0 in favour of
`domain_resolver`.

## Usage

### Command line

```shell
$ clash2sing-box convert --help
clash2sing-box convert v0.0.1 - Convert Clash and sing-box configurations into one sing-box config

Usage
  $ clash2sing-box convert <input...> [flags]

Parameters
  <input...>  Array<string>  Input files or http(s) URLs

Flags
  --output, -o                   String         Output file path (default: stdout)
  --outbound-domainresolver-tag  String         The name of the domain resolver, required for setting resolver strategy
  --outbound-selector-default    String         Use the n-th outbound as the default in the selector outbound (integer)
  --outbound-selector-tag        Array<String>  The name(s) of the selector outbound(s); repeatable, or comma-separated  [default: []]

Global Flags
  --help, -h     Boolean  Show help               [default: false]
  --version, -V  Boolean  Prints current version  [default: false]
```

Inputs may be local paths or `http(s)` URLs, and may be Clash YAML/JSON or sing-box JSON.
Each input is classified automatically: a document with `proxies` is treated as Clash, and
one with `log`/`dns`/`inbounds`/`outbounds`/`endpoints`/`route` as sing-box. Multiple inputs of the
same kind are deep-merged, so a sing-box config supplies the `dns`, `log` and `route`
sections that the generated outbounds are merged into.

`--outbound-selector-tag` takes one tag per occurrence, and each occurrence may also be a
comma-separated list — the two forms may be mixed.

```shell
$ clash2sing-box convert ./tests/clash.yaml -o ./sing-box.json
$ clash2sing-box convert https://example.com/subscription.yaml ./base.json -o ./sing-box.json
$ clash2sing-box convert ./tests/clash.yaml --outbound-selector-tag proxy,streaming
$ clash2sing-box convert ./tests/clash.yaml --outbound-selector-tag proxy --outbound-selector-tag streaming
```

### Library

```ts
import { convert } from '@mzwing/clash2sing-box'

const { config, warnings } = convert(clashConfig, singboxConfig, {
  outbound: { selector: { tag: ['proxy', 'streaming'] } },
})

for (const warning of warnings) console.warn(warning)
console.log(JSON.stringify(config, null, 2))
```

`convert` returns the config as an object and never writes to the console — skipped
proxies and normalized values are reported through `warnings`.

That is the whole public API, alongside the `Options`, `ConvertResult` and `SingboxConfig`
types. To convert a single proxy, pass a one-element `proxies` list: the schemas and the
per-protocol converters are internals, free to change between versions.

## Development

### Requirements

- [Node.js](https://nodejs.org/) >= 24.18
- [pnpm](https://pnpm.io/) (activated via [corepack](https://nodejs.org/api/corepack.html))
- [devenv](https://devenv.sh/) (optional, for a reproducible dev shell)

### Setup

```shell
           # Activate pnpm via corepack (version pinned by the packageManager field)
$ corepack enable
           # Install dependencies
$ pnpm install
```

With devenv (and direnv), the Node.js + corepack environment is provisioned automatically
on entering the project directory — see [`devenv.nix`](./devenv.nix).

### Tasks

```shell
$ pnpm start convert ./tests/clash.yaml   # run the CLI from source
$ pnpm test                               # run the test suite with coverage
$ pnpm typecheck                          # tsc --noEmit
$ pnpm lint                               # oxlint
$ pnpm format                             # oxfmt --write
$ pnpm build                              # bundle to dist/
```
