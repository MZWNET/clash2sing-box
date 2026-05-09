import type { z } from "zod";
import type { SingboxOutbounds, SingboxOutboundURLTest } from "./types.ts";
import { deepmerge } from "deepmerge-ts";
import { doConvertAnyTls } from "./converters/anytls.ts";
import { doConvertHttp } from "./converters/http.ts";
import { doConvertHysteria2 } from "./converters/hysteria2.ts";
import { doConvertHysteria } from "./converters/hysteria.ts";
import { doConvertShadowsocks } from "./converters/shadowsocks.ts";
import { doConvertSocks5ToSocks } from "./converters/socks.ts";
import { doConvertSSH } from "./converters/ssh.ts";
import { doConvertTrojan } from "./converters/trojan.ts";
import { doConvertTUIC } from "./converters/tuic.ts";
import { doConvertVLESS } from "./converters/vless.ts";
import { doConvertVmess } from "./converters/vmess.ts";
import { Clash, ClashProxies, SingboxOutboundSelector } from "./types.ts";

// --- Helper Interfaces for Type Safety ---

export interface SingboxConfig {
  outbounds?: (
    | z.infer<typeof SingboxOutbounds>
    | z.infer<typeof SingboxOutboundSelector>
    | z.infer<typeof SingboxOutboundURLTest>
  )[];

  [key: string]: unknown;
}

export interface Options {
  outbound?: {
    domainresolver?: {
      tag?: string;
    };
    selector?: {
      default?: number;
      tag?: string[];
    };
  };
}

export function convert(clashInput: object, singboxInput: SingboxConfig, options: Options): string {
  const clash = Clash.safeParse(clashInput);
  const allOutbounds: (
    | z.infer<typeof SingboxOutbounds>
    | z.infer<typeof SingboxOutboundSelector>
    | z.infer<typeof SingboxOutboundURLTest>
  )[] = [];

  // 1. Process Clash proxies
  if (clash.success) {
    for (const rawProxy of clash.data.proxies) {
      const proxyResult = ClashProxies.safeParse(rawProxy);

      if (!proxyResult.success) {
        console.warn(`Skipping unsupported proxy "${rawProxy.name}" (type: ${rawProxy.type})`);
        continue;
      }

      const proxy = proxyResult.data;
      let outbound: z.infer<typeof SingboxOutbounds>;

      switch (proxy.type) {
        case "anytls":
          outbound = doConvertAnyTls(proxy);
          break;
        case "http":
          outbound = doConvertHttp(proxy);
          break;
        case "hysteria":
          outbound = doConvertHysteria(proxy);
          break;
        case "hysteria2":
          outbound = doConvertHysteria2(proxy);
          break;
        case "ss":
          outbound = doConvertShadowsocks(proxy);
          break;
        case "socks5":
          outbound = doConvertSocks5ToSocks(proxy);
          break;
        case "ssh":
          outbound = doConvertSSH(proxy);
          break;
        case "trojan":
          outbound = doConvertTrojan(proxy);
          break;
        case "tuic":
          outbound = doConvertTUIC(proxy);
          break;
        case "vmess":
          outbound = doConvertVmess(proxy);
          break;
        case "vless":
          outbound = doConvertVLESS(proxy);
          break;
      }

      if (proxy.udp === false) {
        outbound.network = "tcp";
      }

      if (proxy["ip-version"] !== undefined) {
        if (options.outbound?.domainresolver?.tag !== undefined) {
          outbound.domain_resolver = {
            server: options.outbound?.domainresolver?.tag,
          };
          switch (proxy["ip-version"]) {
            case "dual":
              break;
            case "ipv6-prefer":
              outbound.domain_resolver.strategy = "prefer_ipv6";
              break;
            case "ipv4-prefer":
              outbound.domain_resolver.strategy = "prefer_ipv4";
              break;
            case "ipv6":
              outbound.domain_resolver.strategy = "ipv6_only";
              break;
            case "ipv4":
              outbound.domain_resolver.strategy = "ipv4_only";
              break;
          }
        }
      }

      allOutbounds.push(outbound);
    }
  }

  // 2. Add outbounds from sing-box config
  if (singboxInput.outbounds) {
    allOutbounds.push(...singboxInput.outbounds);
  }

  // 3. Create selector(s) and URLTest
  const allOutboundTags = allOutbounds.map((o) => o.tag);

  const singboxOutboundURLTest: z.infer<typeof SingboxOutboundURLTest> = {
    type: "urltest",
    tag: "urltest-proxy",
    outbounds: allOutboundTags,
  };

  const singboxOutboundSelector: z.infer<typeof SingboxOutboundSelector> = {
    type: "selector",
    tag: "proxy",
    outbounds: [singboxOutboundURLTest.tag, ...allOutboundTags],
    default: singboxOutboundURLTest.tag,
  };

  const selectors: z.infer<typeof SingboxOutboundSelector>[] = [];

  if (options.outbound?.selector?.default !== undefined) {
    const outbound = allOutbounds.at(options.outbound.selector.default);
    if (outbound !== undefined) {
      singboxOutboundSelector.default = outbound.tag;
    } else {
      throw new Error("Invalid outbound ordinal number");
    }
  }

  if (options.outbound?.selector?.tag !== undefined) {
    for (const tag of options.outbound.selector.tag) {
      const selector = structuredClone(singboxOutboundSelector);
      selector.tag = tag;
      selectors.push(SingboxOutboundSelector.parse(selector));
    }
  } else {
    selectors.push(SingboxOutboundSelector.parse(singboxOutboundSelector));
  }

  // 4. Construct final config
  let finalConfig: SingboxConfig = {
    outbounds: [...selectors, singboxOutboundURLTest, ...allOutbounds],
  };

  // 5. Merge raw sing-box config (for dns, log, etc.)
  const { outbounds: _outbounds, ...restOfSingboxInput } = singboxInput;
  finalConfig = merge(finalConfig, restOfSingboxInput);

  return JSON.stringify(finalConfig, null, 2);
}

export function merge(...objects: object[]): Record<string, unknown> {
  // Filter out empty objects before merging
  const objectsToMerge = objects.filter((obj) => Object.keys(obj).length > 0);
  if (objectsToMerge.length === 0) {
    return {};
  }
  return deepmerge(...objectsToMerge) as Record<string, unknown>;
}
