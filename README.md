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

| Name                | Status | Note                                                                                  |
| ------------------- | ------ | ------------------------------------------------------------------------------------- |
| Dial fields         | O      | `udp`/`tfo`/`mptcp`/`interface-name`/`routing-mark`/`dialer-proxy`, on every protocol |
| Multiplex           | O      | `smux` → `multiplex` (incl. `brutal-opts`), on `ss`/`trojan`/`vmess`/`vless`          |
| V2Ray transport     | O      | `ws`/`h2`/`http`/`grpc`/`httpupgrade`, on `vmess`/`vless`/`trojan`                    |
| REALITY             | O      | From `reality-opts`, on every TLS-capable protocol                                    |
| ECH                 | O      | `ech-opts.config` → `ech.config`, rewrapped as PEM                                    |
| uTLS fingerprint    | O      | From `client-fingerprint`                                                             |
| Client certificate  | O      | `certificate` + `private-key` → `client_certificate` + `client_key`                   |
| UDP packet encoding | O      | `packet-encoding` → `packet_encoding` (`packetaddr`/`xudp`)                           |
| IP Version          | ?      | `ip-version` → `domain_resolver.strategy`, needs `--outbound-domainresolver-tag`      |
| Certificate pinning | X      | `fingerprint` hashes the certificate, sing-box hashes the public key — see below      |

Targets the sing-box `testing` branch (1.14.0-alpha). `domain_strategy` is deliberately
not emitted: it was deprecated in 1.12.0 and removed in 1.14.0 in favour of
`domain_resolver`.

mihomo's `fingerprint` is not a browser profile — that is `client-fingerprint` — but the
SHA-256 of the whole server certificate. sing-box pins the SHA-256 of the _public key_
instead, so the two hashes are not interchangeable and `fingerprint` is dropped with a
warning. Pin from the command line instead — see below.

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
  --output, -o                                  String         Output file path (default: stdout)
  --outbound-domainresolver-tag                 String         The name of the domain resolver, required for setting resolver strategy
  --outbound-entry-geo-db                       String         Path to a MaxMind Country mmdb; appends |IN-<CC> for each proxy's entry address
  --outbound-group                              Array<String>  An extra proxy group as "tag=regex", matched against outbound tags; repeatable  [default: []]
  --outbound-no-urltest                         Array<String>  Tag(s) to keep out of every URLTest group, selectable by hand only; repeatable or comma-separated  [default: []]
  --outbound-selector-default                   String         Use the n-th outbound as the default in the selector outbound (integer)
  --outbound-selector-tag                       Array<String>  The name(s) of the selector outbound(s); repeatable, or comma-separated  [default: []]
  --outbound-tls-certificate                    Array<String>  Pin a certificate as "regex=path", matched against outbound tags; repeatable  [default: []]
  --outbound-tls-certificate-public-key-sha256  Array<String>  Pin a public key as "regex=base64", matched against outbound tags; repeatable  [default: []]

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

### Proxy groups

Every conversion emits a `proxy` selector over everything and a `urltest-proxy` racing the
latency-testable subset. `--outbound-group` adds groups on top, each collecting the
outbounds whose **tag** the regex accepts:

```shell
$ clash2sing-box convert ./nodes.yaml \
    --outbound-group 'hk=(?<!-)\bHK\b' \
    --outbound-group 'netflix=\bNF\b'
```

The flag is repeatable and is **not** comma-split, because a pattern may contain a comma.
It splits on the first `=`, so a pattern may contain one of those too. Patterns are
compiled without flags, which makes them case-sensitive and keeps `test()` from carrying
`lastIndex` between candidates.

Two behaviours are worth knowing before you point route rules at a group:

- A group whose regex matches nothing is still emitted, as a selector aliasing
  `urltest-proxy`. Deleting it would leave your route rules referencing an outbound that is
  not there, and sing-box rejects both that and a group with an empty member list.
- Groups appear in the `proxy` selector, ahead of the individual nodes, but never inside
  `urltest-proxy` — a race between races would skew the latency comparison the same way
  `direct` would.

A tag that collides with a node, a selector or `urltest-proxy` is an error rather than a
config sing-box will reject later.

`--outbound-no-urltest` keeps a tag selectable but out of every URLTest group, including
named ones — "not latency-testable" is a property of the outbound, not of one group:

```shell
$ clash2sing-box convert ./nodes.yaml ./warp-endpoint.json --outbound-no-urltest warp
```

This is for an outbound you pick deliberately rather than by latency. A WARP endpoint is
the usual case: it is fast enough to keep winning a race it has no business being in, and
whatever wins `urltest-proxy` is where unmatched traffic goes. Unlike `direct` and `block`
— excluded by type, because they structurally break a race — this is a judgement about a
specific node, so it is named by tag. A tag matching no outbound is reported as a warning
rather than ignored, since the alternative is a silent typo.

### Certificate pinning

mihomo pins with `fingerprint`, hashing the whole certificate; sing-box hashes the public
key. Neither hash can be computed from the other, so pinning is named on the command line
rather than converted. Both flags take `regex=value`, with the regex matched against
outbound tags, and both are repeatable:

```shell
$ clash2sing-box convert ./nodes.yaml \
    --outbound-tls-certificate '^home-=./my-ca.pem' \
    --outbound-tls-certificate-public-key-sha256 '^home-=uWYFLt/wd56CEm3/5oVkJHVMeTp7NDEPxWxGUrIqbmw='
```

The public key hash is base64, as `openssl x509 -in cert.pem -pubkey -noout | openssl pkey
-pubin -outform der | openssl dgst -sha256 -binary | base64` prints it.

Unlike `--outbound-group`, the regex is on the **left**, so write a literal `=` inside it as
`\x3d`: the split is on the first `=` either way, which keeps the value free to contain one
— base64 padding always does, and a path may.

Only outbounds that already carry TLS are eligible; sing-box rejects a `tls` block outright
on Shadowsocks, SOCKS, SSH and Snell. A pattern matching nothing is reported as a warning.

### Entry geolocation

Subscription checkers rename nodes after the address traffic **exits** from — the half you
cannot read off the config. The **entry** is the `server` field, sitting right there
ungeolocated, and the two differ whenever a node relays. `--outbound-entry-geo-db` fills
that half in, appending `|IN-<CC>` to each Clash proxy's name:

```
🇭🇰HK¹⁺_3|12.3MB/s|GPT⁺|YT|NF|0%|IN-JP
└──exit──┘                        └entry┘
```

Point it at any MaxMind Country `.mmdb`. Hostnames are resolved once each, in parallel,
with a short DNS timeout; a node whose entry cannot be located keeps its original name and
converts as usual, with a warning on stderr.

The hyphen in `IN-JP` is deliberate: it is what keeps an entry tag out of a region group
written as `(?<!-)\bJP\b`, the same guard that already skips exit-side qualifiers like
`TK-US` or `-US⁰`.

Only Clash input is annotated. sing-box fragments are hand-written, so their tags already
say what you meant, and rewriting them would mean chasing every `detour` and group
membership pointing at the old tag.

A record's `country` wins where present, falling back to `registered_country`. Anycast
ranges — Cloudflare's, and plenty of entry hosts sit behind those — carry no `country` at
all and would otherwise go unlabelled; but the two disagree often enough that the order
matters, an Alibaba Hong Kong address reading `country: HK, registered_country: US`.

Caveats: lookups go through the system resolver, so with a TUN interface up a hostname
resolves the way your proxy sees it; only the first address of a multi-record host is used;
and a Country database gives you a country, not a city or an ASN.

This is a command line tool, not a library: it exposes no importable entry point, and
everything under `src/` is an internal free to change between versions.

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
