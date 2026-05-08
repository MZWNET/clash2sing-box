# Clash2sing-box

## About

### Features

#### Protocols

| Name        | Status | Note                                                                |
| ----------- | ------ | ------------------------------------------------------------------- |
| AnyTLS      | O      |                                                                     |
| HTTP        | O      | sing-box limitation: layer tls not supported                        |
| Hysteria    | O      | sing-box limitation: protocol faketcp or wechat-video not supported |
| Shadowsocks | O      |                                                                     |
| Socks       | O      |                                                                     |
| Trojan      | ?      | Trojan-Go features not implemented                                  |
| TUIC        | O      |                                                                     |
| Vmess       | O      | sing-box limitation: protocol tcp not supported                     |
| VLESS       | O      | sing-box limitation: protocol tcp not supported                     |

#### Options

| Name                               | Status | Note                                                                               |
| ---------------------------------- | ------ | ---------------------------------------------------------------------------------- |
| TCP-only                           | O      |                                                                                    |
| IP Version                         | ?      | Only option `ip-version` is implemented                                            |
| TLS Certificate Pinning            | ?      | Implemented via proprietary option `x-clash2singbox-certificate`                   |
| TLS Certificate Public Key Pinning | ?      | Implemented via proprietary option `x-clash2singbox-certificate-public-key-sha256` |

## Usage

```shell
$ bun run src/mod.ts convert --help
Usage: clash2sing-box convert <input...>

Description:

  Convert configuration

Options:

  -h, --help                                - Show this help.
  -o, --output                   <string>   - Output file path
  --outbound.domainresolver.tag  <string>   - The name of the domain resolver, required for setting resolver strategy
  --outbound.selector.default    <integer>  - Use the n-th outbound as the default in the selector outbound
  --outbound.selector.tag        <string>   - The name(s) of the selector outbound(s)
```

### Install Bun

- BSD/Linux/macOS: `curl -fsSL https://bun.sh/install | bash`
- Windows: `powershell -c "irm bun.sh/install.ps1 | iex"`

### Convert Configuration

```shell
           # Install dependencies
$ bun install
           # Convert configuration file
$ bun run src/mod.ts convert \
           ./src/tests/clash.yaml \
           -o ./src/tests/sing-box.json
$ ls ./src/tests/
clash.yaml  sing-box.json
```
