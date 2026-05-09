import type { Options, SingboxConfig } from "../src/libs/utils.ts";
import { readFileSync } from "node:fs";
import * as yaml from "yaml";
import { convert, merge } from "../src/libs/utils.ts";
import {
  fullAnyTlsProxy,
  fullHttpProxy,
  fullHysteria2Proxy,
  fullHysteriaProxy,
  fullShadowsocksProxy,
  fullSocks5Proxy,
  fullSSHProxy,
  fullTrojanProxy,
  fullTUICProxy,
  fullVlessProxy,
  fullVmessProxy,
  minimalAnyTlsProxy,
  minimalClashConfig,
  minimalHttpProxy,
  minimalHysteria2Proxy,
  minimalHysteriaProxy,
  minimalShadowsocksProxy,
  minimalSingboxConfig,
  minimalSocks5Proxy,
  minimalSSHProxy,
  minimalTrojanProxy,
  minimalTUICProxy,
  minimalVlessProxy,
  minimalVmessProxy,
} from "./fixtures.ts";

describe("merge()", () => {
  it("merges two simple objects", () => {
    expect(merge({ a: 1 }, { b: 2 })).toEqual({ a: 1, b: 2 });
  });

  it("merges multiple objects", () => {
    expect(merge({ a: 1 }, { b: 2 }, { c: 3 })).toEqual({ a: 1, b: 2, c: 3 });
  });

  it("deep merges nested objects", () => {
    expect(merge({ a: { x: 1 } }, { a: { y: 2 } })).toEqual({ a: { x: 1, y: 2 } });
  });

  it("filters out empty objects", () => {
    expect(merge({ a: 1 }, {})).toEqual({ a: 1 });
  });

  it("returns empty object when all inputs are empty", () => {
    expect(merge({}, {})).toEqual({});
  });

  it("concatenates arrays (deepmerge default behavior)", () => {
    expect(merge({ a: [1] }, { a: [2] })).toEqual({ a: [1, 2] });
  });

  it("returns single object as-is (deepmerge behavior)", () => {
    expect(merge({ a: 1 })).toEqual({ a: 1 });
  });

  it("later values override earlier values for same key", () => {
    expect(merge({ a: 1 }, { a: 2 })).toEqual({ a: 2 });
  });
});

describe("convert()", () => {
  function parseConvert(
    clashInput: Record<string, unknown>,
    singboxInput: Record<string, unknown> = {},
    options: Options = {},
  ): SingboxConfig {
    return JSON.parse(convert(clashInput, singboxInput, options)) as SingboxConfig;
  }

  type OutboundElement = NonNullable<SingboxConfig["outbounds"]>[number];

  interface SelectorOutbound {
    type: "selector";
    tag: string;
    outbounds: string[];
    default?: string;
  }

  interface UrltestOutbound {
    type: "urltest";
    tag: string;
    outbounds: string[];
  }

  function isSelector(o: OutboundElement): o is SelectorOutbound {
    return "type" in o && o.type === "selector";
  }

  function isUrltest(o: OutboundElement): o is UrltestOutbound {
    return "type" in o && o.type === "urltest";
  }

  interface DomainResolver {
    server: string;
    strategy?: string;
  }

  interface ProxyOutboundWithResolver {
    tag: string;
    type: string;
    domain_resolver?: DomainResolver;
    [key: string]: unknown;
  }

  it("converts minimal Clash config with one proxy to valid sing-box JSON", () => {
    const clash = { proxies: [minimalShadowsocksProxy] };
    const result = parseConvert(clash);

    expect(result.outbounds).toBeDefined();
    expect(result.outbounds!.length).toBe(3);

    const proxyOut = result.outbounds!.find((o: { tag: string }) => o.tag === "ss-01") as
      | ProxyOutboundWithResolver
      | undefined;
    expect(proxyOut).toBeDefined();
    expect(proxyOut!.type).toBe("shadowsocks");
    expect(proxyOut!["server"]).toBe("198.51.100.5");
    expect(proxyOut!["server_port"]).toBe(8388);
    expect(proxyOut!["method"]).toBe("aes-256-gcm");
    expect(proxyOut!["password"]).toBe("ss-password-123");
  });

  it("handles mixed proxy types (ss + vmess together)", () => {
    const clash = {
      proxies: [minimalShadowsocksProxy, minimalVmessProxy],
    };
    const result = parseConvert(clash);

    const tags = result.outbounds!.map((o: { tag: string }) => o.tag);
    expect(tags).toContain("ss-01");
    expect(tags).toContain("vmess-01");

    const vmessOut = result.outbounds!.find((o: { tag: string }) => o.tag === "vmess-01") as
      | ProxyOutboundWithResolver
      | undefined;
    expect(vmessOut).toBeDefined();
    expect(vmessOut!.type).toBe("vmess");
    expect(vmessOut!["uuid"]).toBe("12345678-1234-1234-1234-123456789abc");
  });

  it('creates selector outbound with tag "proxy" and urltest outbound with tag "urltest-proxy"', () => {
    const clash = { proxies: [minimalShadowsocksProxy] };
    const result = parseConvert(clash);

    const selector = result.outbounds!.find(isSelector);
    const urltest = result.outbounds!.find(isUrltest);

    expect(selector).toBeDefined();
    expect(selector!.tag).toBe("proxy");
    expect(urltest).toBeDefined();
    expect(urltest!.tag).toBe("urltest-proxy");
  });

  it("selector includes all proxy tags + urltest tag", () => {
    const clash = {
      proxies: [minimalShadowsocksProxy, minimalVmessProxy],
    };
    const result = parseConvert(clash);

    const selector = result.outbounds!.find(isSelector);
    expect(selector!.outbounds).toContain("urltest-proxy");
    expect(selector!.outbounds).toContain("ss-01");
    expect(selector!.outbounds).toContain("vmess-01");
    expect(selector!.outbounds[0]).toBe("urltest-proxy");
  });

  it("urltest includes all proxy tags", () => {
    const clash = {
      proxies: [minimalShadowsocksProxy, minimalVmessProxy],
    };
    const result = parseConvert(clash);

    const urltest = result.outbounds!.find(isUrltest);
    expect(urltest!.outbounds).toContain("ss-01");
    expect(urltest!.outbounds).toContain("vmess-01");
    expect(urltest!.outbounds).not.toContain("urltest-proxy");
  });

  it("default selector is urltest-proxy", () => {
    const clash = { proxies: [minimalShadowsocksProxy] };
    const result = parseConvert(clash);

    const selector = result.outbounds!.find(isSelector);
    expect(selector!.default).toBe("urltest-proxy");
  });

  it("supports custom selector tags via options.outbound.selector.tag", () => {
    const clash = { proxies: [minimalShadowsocksProxy] };
    const options: Options = {
      outbound: { selector: { tag: ["my-selector", "another-selector"] } },
    };
    const result = parseConvert(clash, {}, options);

    const selectors = result.outbounds!.filter(isSelector);
    expect(selectors.length).toBe(2);
    expect(selectors[0]!.tag).toBe("my-selector");
    expect(selectors[1]!.tag).toBe("another-selector");

    for (const sel of selectors) {
      expect(sel.outbounds).toContain("urltest-proxy");
      expect(sel.outbounds).toContain("ss-01");
    }
  });

  it("supports custom default outbound via options.outbound.selector.default (ordinal 0)", () => {
    const clash = { proxies: [minimalShadowsocksProxy, minimalVmessProxy] };
    const options: Options = {
      outbound: { selector: { default: 0 } },
    };
    const result = parseConvert(clash, {}, options);

    const selector = result.outbounds!.find(isSelector);
    expect(selector!.default).toBe("ss-01");
  });

  it("throws error for invalid selector default ordinal (out of range)", () => {
    const clash = { proxies: [minimalShadowsocksProxy] };
    const options: Options = {
      outbound: { selector: { default: 99 } },
    };
    expect(() => convert(clash, {}, options)).toThrow("Invalid outbound ordinal number");
  });

  it('handles udp: false → network: "tcp" on the outbound', () => {
    const clash = {
      proxies: [{ ...minimalShadowsocksProxy, udp: false }],
    };
    const result = parseConvert(clash);

    const proxyOut = result.outbounds!.find((o: { tag: string }) => o.tag === "ss-01") as
      | ProxyOutboundWithResolver
      | undefined;
    expect(proxyOut).toBeDefined();
    expect(proxyOut!["network"]).toBe("tcp");
  });

  it("handles ip-version with domain resolver (options.outbound.domainresolver.tag)", () => {
    const clash = {
      proxies: [{ ...minimalShadowsocksProxy, "ip-version": "ipv6-prefer" as const }],
    };
    const options: Options = {
      outbound: { domainresolver: { tag: "dns-proxy" } },
    };
    const result = parseConvert(clash, {}, options);

    const proxyOut = result.outbounds!.find((o: { tag: string }) => o.tag === "ss-01") as
      | ProxyOutboundWithResolver
      | undefined;
    expect(proxyOut).toBeDefined();
    expect(proxyOut!.domain_resolver).toBeDefined();
    expect(proxyOut!.domain_resolver?.server).toBe("dns-proxy");
  });

  it('maps ip-version "ipv6-prefer" to strategy "prefer_ipv6"', () => {
    const clash = {
      proxies: [{ ...minimalShadowsocksProxy, "ip-version": "ipv6-prefer" as const }],
    };
    const options: Options = {
      outbound: { domainresolver: { tag: "dns-proxy" } },
    };
    const result = parseConvert(clash, {}, options);

    const proxyOut = result.outbounds!.find((o: { tag: string }) => o.tag === "ss-01") as
      | ProxyOutboundWithResolver
      | undefined;
    expect(proxyOut).toBeDefined();
    expect(proxyOut!.domain_resolver?.strategy).toBe("prefer_ipv6");
  });

  it('maps ip-version "ipv4" to strategy "ipv4_only"', () => {
    const clash = {
      proxies: [{ ...minimalShadowsocksProxy, "ip-version": "ipv4" as const }],
    };
    const options: Options = {
      outbound: { domainresolver: { tag: "dns-proxy" } },
    };
    const result = parseConvert(clash, {}, options);

    const proxyOut = result.outbounds!.find((o: { tag: string }) => o.tag === "ss-01") as
      | ProxyOutboundWithResolver
      | undefined;
    expect(proxyOut).toBeDefined();
    expect(proxyOut!.domain_resolver?.strategy).toBe("ipv4_only");
  });

  it("merges sing-box config (dns, log, etc.) from singboxInput", () => {
    const clash = { proxies: [minimalShadowsocksProxy] };
    const singboxInput = {
      dns: {
        servers: [{ tag: "google", address: "tls://8.8.8.8" }],
      },
      log: { level: "info" },
    };
    const result = parseConvert(clash, singboxInput);

    expect(result["dns"]).toBeDefined();
    expect((result["dns"] as { servers: Array<{ tag: string }> }).servers[0]!.tag).toBe("google");
    expect(result["log"]).toBeDefined();
    expect((result["log"] as { level: string }).level).toBe("info");
    expect(result.outbounds).toBeDefined();
    expect(result.outbounds!.length).toBe(3);
  });

  it("output is valid JSON string (JSON.parse succeeds)", () => {
    const clash = { proxies: [minimalShadowsocksProxy] };
    const raw = convert(clash, {}, {});
    expect(typeof raw).toBe("string");
    expect(() => JSON.parse(raw) as SingboxConfig).not.toThrow();
  });

  it("should match existing test fixture (tests/clash.yaml → tests/sing-box.json)", () => {
    const clash = yaml.parse(readFileSync("tests/clash.yaml", "utf-8")) as Record<string, unknown>;
    const expected = JSON.parse(readFileSync("tests/sing-box.json", "utf-8")) as SingboxConfig;
    const result = parseConvert(clash);
    expect(result).toEqual(expected);
  });

  it("converts all 11 proxy types from minimalClashConfig without error", () => {
    const result = parseConvert(minimalClashConfig);

    expect(result.outbounds!.length).toBe(13);

    const types = result.outbounds!.map((o: { type: string }) => o.type);
    expect(types).toContain("selector");
    expect(types).toContain("urltest");
    expect(types).toContain("shadowsocks");
    expect(types).toContain("vmess");
    expect(types).toContain("vless");
    expect(types).toContain("trojan");
    expect(types).toContain("tuic");
    expect(types).toContain("socks");
    expect(types).toContain("http");
    expect(types).toContain("ssh");
    expect(types).toContain("hysteria");
    expect(types).toContain("hysteria2");
    expect(types).toContain("anytls");
  });

  it("includes outbounds from singboxInput in the result", () => {
    const clash = { proxies: [minimalShadowsocksProxy] };
    const singboxInput = {
      outbounds: [
        {
          type: "direct" as const,
          tag: "direct-out",
        },
      ],
    };
    const result = parseConvert(clash, singboxInput);

    const tags = result.outbounds!.map((o: { tag: string }) => o.tag);
    expect(tags).toContain("direct-out");
    const selector = result.outbounds!.find(isSelector);
    expect(selector!.outbounds).toContain("direct-out");
  });

  it("converts minimal anytls proxy", () => {
    const clash = { proxies: [minimalAnyTlsProxy] };
    const result = parseConvert(clash);
    const proxyOut = result.outbounds!.find((o: { tag: string }) => o.tag === "anytls-01") as
      | ProxyOutboundWithResolver
      | undefined;
    expect(proxyOut).toBeDefined();
    expect(proxyOut!.type).toBe("anytls");
    expect(proxyOut!["server"]).toBe("198.51.100.1");
    expect(proxyOut!["server_port"]).toBe(443);
    expect(proxyOut!["password"]).toBe("test-password-123");
  });

  it("converts full anytls proxy with optional fields", () => {
    const clash = { proxies: [fullAnyTlsProxy] };
    const result = parseConvert(clash);
    const proxyOut = result.outbounds!.find((o: { tag: string }) => o.tag === "anytls-02") as
      | ProxyOutboundWithResolver
      | undefined;
    expect(proxyOut).toBeDefined();
    expect(proxyOut!.type).toBe("anytls");
    expect(proxyOut!["server"]).toBe("203.0.113.10");
    expect(proxyOut!["server_port"]).toBe(8443);
    expect(proxyOut!["password"]).toBe("secure-password-456");
    expect(proxyOut!["tls"]).toBeDefined();
    expect((proxyOut!["tls"] as { server_name: string }).server_name).toBe("example.com");
    expect(proxyOut!["idle_session_check_interval"]).toBe("60s");
    expect(proxyOut!["idle_session_timeout"]).toBe("300s");
    expect(proxyOut!["min_idle_session"]).toBe(2);
  });

  it("converts minimal http proxy", () => {
    const clash = { proxies: [minimalHttpProxy] };
    const result = parseConvert(clash);
    const proxyOut = result.outbounds!.find((o: { tag: string }) => o.tag === "http-01") as
      | ProxyOutboundWithResolver
      | undefined;
    expect(proxyOut).toBeDefined();
    expect(proxyOut!.type).toBe("http");
    expect(proxyOut!["server"]).toBe("198.51.100.2");
    expect(proxyOut!["server_port"]).toBe(8080);
  });

  it("converts full http proxy with optional fields", () => {
    const clash = { proxies: [fullHttpProxy] };
    const result = parseConvert(clash);
    const proxyOut = result.outbounds!.find((o: { tag: string }) => o.tag === "http-02") as
      | ProxyOutboundWithResolver
      | undefined;
    expect(proxyOut).toBeDefined();
    expect(proxyOut!.type).toBe("http");
    expect(proxyOut!["server"]).toBe("203.0.113.20");
    expect(proxyOut!["server_port"]).toBe(3128);
    expect(proxyOut!["username"]).toBe("proxy-user");
    expect(proxyOut!["password"]).toBe("proxy-pass");
    expect(proxyOut!["tls"]).toBeDefined();
  });

  it("converts minimal hysteria proxy", () => {
    const clash = { proxies: [minimalHysteriaProxy] };
    const result = parseConvert(clash);
    const proxyOut = result.outbounds!.find((o: { tag: string }) => o.tag === "hysteria-01") as
      | ProxyOutboundWithResolver
      | undefined;
    expect(proxyOut).toBeDefined();
    expect(proxyOut!.type).toBe("hysteria");
    expect(proxyOut!["server"]).toBe("198.51.100.3");
    expect(proxyOut!["server_port"]).toBe(36712);
    expect(proxyOut!["up"]).toBe("50 Mbps");
    expect(proxyOut!["down"]).toBe("200 Mbps");
  });

  it("converts full hysteria proxy with optional fields", () => {
    const clash = { proxies: [fullHysteriaProxy] };
    const result = parseConvert(clash);
    const proxyOut = result.outbounds!.find((o: { tag: string }) => o.tag === "hysteria-02") as
      | ProxyOutboundWithResolver
      | undefined;
    expect(proxyOut).toBeDefined();
    expect(proxyOut!.type).toBe("hysteria");
    expect(proxyOut!["server"]).toBe("203.0.113.30");
    expect(proxyOut!["server_port"]).toBe(443);
    expect(proxyOut!["auth_str"]).toBe("hysteria-auth-token");
    expect(proxyOut!["tls"]).toBeDefined();
  });

  it("converts minimal hysteria2 proxy", () => {
    const clash = { proxies: [minimalHysteria2Proxy] };
    const result = parseConvert(clash);
    const proxyOut = result.outbounds!.find((o: { tag: string }) => o.tag === "hysteria2-01") as
      | ProxyOutboundWithResolver
      | undefined;
    expect(proxyOut).toBeDefined();
    expect(proxyOut!.type).toBe("hysteria2");
    expect(proxyOut!["server"]).toBe("198.51.100.4");
    expect(proxyOut!["server_port"]).toBe(443);
    expect(proxyOut!["password"]).toBe("hy2-password-123");
  });

  it("converts full hysteria2 proxy with optional fields", () => {
    const clash = { proxies: [fullHysteria2Proxy] };
    const result = parseConvert(clash);
    const proxyOut = result.outbounds!.find((o: { tag: string }) => o.tag === "hysteria2-02") as
      | ProxyOutboundWithResolver
      | undefined;
    expect(proxyOut).toBeDefined();
    expect(proxyOut!.type).toBe("hysteria2");
    expect(proxyOut!["server"]).toBe("203.0.113.40");
    expect(proxyOut!["server_port"]).toBe(8443);
    expect(proxyOut!["password"]).toBe("hy2-secure-password");
    expect(proxyOut!["tls"]).toBeDefined();
    expect(proxyOut!["obfs"]).toBeDefined();
    expect(proxyOut!["up_mbps"]).toBe(80);
    expect(proxyOut!["down_mbps"]).toBe(400);
  });

  it("converts full shadowsocks proxy with optional fields", () => {
    const clash = { proxies: [fullShadowsocksProxy] };
    const result = parseConvert(clash);
    const proxyOut = result.outbounds!.find((o: { tag: string }) => o.tag === "ss-02") as
      | ProxyOutboundWithResolver
      | undefined;
    expect(proxyOut).toBeDefined();
    expect(proxyOut!.type).toBe("shadowsocks");
    expect(proxyOut!["server"]).toBe("203.0.113.50");
    expect(proxyOut!["server_port"]).toBe(443);
    expect(proxyOut!["method"]).toBe("2022-blake3-aes-256-gcm");
    expect(proxyOut!["password"]).toBe("ss-secure-password");
    expect(proxyOut!["plugin"]).toBe("v2ray-plugin");
  });

  it("converts minimal socks5 proxy", () => {
    const clash = { proxies: [minimalSocks5Proxy] };
    const result = parseConvert(clash);
    const proxyOut = result.outbounds!.find((o: { tag: string }) => o.tag === "socks5-01") as
      | ProxyOutboundWithResolver
      | undefined;
    expect(proxyOut).toBeDefined();
    expect(proxyOut!.type).toBe("socks");
    expect(proxyOut!["server"]).toBe("198.51.100.6");
    expect(proxyOut!["server_port"]).toBe(1080);
  });

  it("converts full socks5 proxy with optional fields", () => {
    const clash = { proxies: [fullSocks5Proxy] };
    // socks5 with tls: true throws "Unsupported layer tls"
    expect(() => convert(clash, {}, {})).toThrow("Unsupported layer tls");
  });

  it("converts minimal ssh proxy", () => {
    const clash = { proxies: [minimalSSHProxy] };
    const result = parseConvert(clash);
    const proxyOut = result.outbounds!.find((o: { tag: string }) => o.tag === "ssh-01") as
      | ProxyOutboundWithResolver
      | undefined;
    expect(proxyOut).toBeDefined();
    expect(proxyOut!.type).toBe("ssh");
    expect(proxyOut!["server"]).toBe("198.51.100.7");
    expect(proxyOut!["server_port"]).toBe(22);
    expect(proxyOut!["user"]).toBe("root");
  });

  it("converts full ssh proxy with optional fields", () => {
    const clash = { proxies: [fullSSHProxy] };
    const result = parseConvert(clash);
    const proxyOut = result.outbounds!.find((o: { tag: string }) => o.tag === "ssh-02") as
      | ProxyOutboundWithResolver
      | undefined;
    expect(proxyOut).toBeDefined();
    expect(proxyOut!.type).toBe("ssh");
    expect(proxyOut!["server"]).toBe("203.0.113.70");
    expect(proxyOut!["server_port"]).toBe(2222);
    expect(proxyOut!["user"]).toBe("admin");
    expect(proxyOut!["password"]).toBe("ssh-password");
    expect(proxyOut!["private_key"]).toBeDefined();
  });

  it("converts minimal trojan proxy", () => {
    const clash = { proxies: [minimalTrojanProxy] };
    const result = parseConvert(clash);
    const proxyOut = result.outbounds!.find((o: { tag: string }) => o.tag === "trojan-01") as
      | ProxyOutboundWithResolver
      | undefined;
    expect(proxyOut).toBeDefined();
    expect(proxyOut!.type).toBe("trojan");
    expect(proxyOut!["server"]).toBe("198.51.100.8");
    expect(proxyOut!["server_port"]).toBe(443);
    expect(proxyOut!["password"]).toBe("trojan-password-123");
  });

  it("converts full trojan proxy with optional fields", () => {
    const clash = { proxies: [fullTrojanProxy] };
    const result = parseConvert(clash);
    const proxyOut = result.outbounds!.find((o: { tag: string }) => o.tag === "trojan-02") as
      | ProxyOutboundWithResolver
      | undefined;
    expect(proxyOut).toBeDefined();
    expect(proxyOut!.type).toBe("trojan");
    expect(proxyOut!["server"]).toBe("203.0.113.80");
    expect(proxyOut!["server_port"]).toBe(8443);
    expect(proxyOut!["password"]).toBe("trojan-secure-password");
    expect(proxyOut!["tls"]).toBeDefined();
  });

  it("converts minimal tuic proxy", () => {
    const clash = { proxies: [minimalTUICProxy] };
    const result = parseConvert(clash);
    const proxyOut = result.outbounds!.find((o: { tag: string }) => o.tag === "tuic-01") as
      | ProxyOutboundWithResolver
      | undefined;
    expect(proxyOut).toBeDefined();
    expect(proxyOut!.type).toBe("tuic");
    expect(proxyOut!["server"]).toBe("198.51.100.9");
    expect(proxyOut!["server_port"]).toBe(443);
    expect(proxyOut!["uuid"]).toBe("12345678-1234-1234-1234-123456789abc");
  });

  it("converts full tuic proxy with optional fields", () => {
    const clash = { proxies: [fullTUICProxy] };
    const result = parseConvert(clash);
    const proxyOut = result.outbounds!.find((o: { tag: string }) => o.tag === "tuic-02") as
      | ProxyOutboundWithResolver
      | undefined;
    expect(proxyOut).toBeDefined();
    expect(proxyOut!.type).toBe("tuic");
    expect(proxyOut!["server"]).toBe("203.0.113.90");
    expect(proxyOut!["server_port"]).toBe(8443);
    expect(proxyOut!["uuid"]).toBe("abcdefab-cdef-abcd-efab-cdefabcdefab");
    expect(proxyOut!["password"]).toBe("tuic-password");
    expect(proxyOut!["tls"]).toBeDefined();
  });

  it("converts full vmess proxy with optional fields", () => {
    const clash = { proxies: [fullVmessProxy] };
    const result = parseConvert(clash);
    const proxyOut = result.outbounds!.find((o: { tag: string }) => o.tag === "vmess-02") as
      | ProxyOutboundWithResolver
      | undefined;
    expect(proxyOut).toBeDefined();
    expect(proxyOut!.type).toBe("vmess");
    expect(proxyOut!["server"]).toBe("203.0.113.100");
    expect(proxyOut!["server_port"]).toBe(8443);
    expect(proxyOut!["uuid"]).toBe("abcdefab-cdef-abcd-efab-cdefabcdefab");
    expect(proxyOut!["security"]).toBe("aes-128-gcm");
    expect(proxyOut!["tls"]).toBeDefined();
    expect(proxyOut!["transport"]).toBeDefined();
  });

  it("converts minimal vless proxy", () => {
    const clash = { proxies: [minimalVlessProxy] };
    const result = parseConvert(clash);
    const proxyOut = result.outbounds!.find((o: { tag: string }) => o.tag === "vless-01") as
      | ProxyOutboundWithResolver
      | undefined;
    expect(proxyOut).toBeDefined();
    expect(proxyOut!.type).toBe("vless");
    expect(proxyOut!["server"]).toBe("198.51.100.11");
    expect(proxyOut!["server_port"]).toBe(443);
    expect(proxyOut!["uuid"]).toBe("12345678-1234-1234-1234-123456789abc");
  });

  it("converts full vless proxy with optional fields", () => {
    const clash = { proxies: [fullVlessProxy] };
    const result = parseConvert(clash);
    const proxyOut = result.outbounds!.find((o: { tag: string }) => o.tag === "vless-02") as
      | ProxyOutboundWithResolver
      | undefined;
    expect(proxyOut).toBeDefined();
    expect(proxyOut!.type).toBe("vless");
    expect(proxyOut!["server"]).toBe("203.0.113.110");
    expect(proxyOut!["server_port"]).toBe(8443);
    expect(proxyOut!["uuid"]).toBe("abcdefab-cdef-abcd-efab-cdefabcdefab");
    expect(proxyOut!["flow"]).toBe("xtls-rprx-vision");
    expect(proxyOut!["tls"]).toBeDefined();
    expect(proxyOut!["transport"]).toBeDefined();
  });

  it("merges minimalSingboxConfig as singboxInput", () => {
    const clash = { proxies: [minimalShadowsocksProxy] };
    const result = parseConvert(clash, minimalSingboxConfig);

    const tags = result.outbounds!.map((o: { tag: string }) => o.tag);
    expect(tags).toContain("ss-01");
    expect(tags).toContain("anytls-01");
    expect(tags).toContain("http-01");
    expect(tags).toContain("hysteria-01");
    expect(tags).toContain("hysteria2-01");
    expect(tags).toContain("socks5-01");
    expect(tags).toContain("ssh-01");
    expect(tags).toContain("trojan-01");
    expect(tags).toContain("tuic-01");
    expect(tags).toContain("vmess-01");
    expect(tags).toContain("vless-01");
  });
});
