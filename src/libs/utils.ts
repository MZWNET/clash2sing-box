import { deepmerge } from "deepmerge-ts";
import {
  Clash,
  ClashProxies,
  type SingboxOutbounds,
  SingboxOutboundSelector,
  type SingboxOutboundURLTest,
} from "./types.ts";
import { doConvertAnyTls } from "./converters/anytls.ts";
import { doConvertHttp } from "./converters/http.ts";
import { doConvertHysteria } from "./converters/hysteria.ts";
import { doConvertHysteria2 } from "./converters/hysteria2.ts";
import { doConvertShadowsocks } from "./converters/shadowsocks.ts";
import { doConvertSocks5ToSocks } from "./converters/socks.ts";
import { doConvertSSH } from "./converters/ssh.ts";
import { doConvertTrojan } from "./converters/trojan.ts";
import { doConvertTUIC } from "./converters/tuic.ts";
import { doConvertVmess } from "./converters/vmess.ts";
import { doConvertVLESS } from "./converters/vless.ts";

// --- Helper Interfaces for Type Safety ---

interface SingboxConfig {
  outbounds?:
    (SingboxOutbounds | SingboxOutboundSelector | SingboxOutboundURLTest)[];

  [key: string]: any;
}

export type Options = {
  outbound?: {
    domainresolver?: {
      tag?: string;
    };
    selector?: {
      default?: number;
      tag?: string[];
    };
  };
};

export function convert(
  clashInput: object,
  singboxInput: SingboxConfig,
  options: Options,
): string {
  const clash = Clash.safeParse(clashInput);
  const allOutbounds: (
    | SingboxOutbounds
    | SingboxOutboundSelector
    | SingboxOutboundURLTest
  )[] = [];

  // 1. Process Clash proxies
  if (clash.success) {
    for (const rawProxy of clash.data.proxies) {
      const proxyResult = ClashProxies.safeParse(rawProxy);

      if (!proxyResult.success) {
        console.warn(
          `Skipping unsupported proxy "${rawProxy.name}" (type: ${rawProxy.type})`,
        );
        continue;
      }

      const proxy = proxyResult.data;
      let outbound: SingboxOutbounds;

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

  const singboxOutboundURLTest: SingboxOutboundURLTest = {
    type: "urltest",
    tag: "urltest-proxy",
    outbounds: allOutboundTags,
  };

  const singboxOutboundSelector: SingboxOutboundSelector = {
    type: "selector",
    tag: "proxy",
    outbounds: [singboxOutboundURLTest.tag, ...allOutboundTags],
    default: singboxOutboundURLTest.tag,
  };

  const selectors: SingboxOutboundSelector[] = [];

  if (options.outbound?.selector?.default != undefined) {
    const outbound = allOutbounds.at(options.outbound.selector.default);
    if (outbound != undefined) {
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

export function merge(...objects: object[]): object {
  // Filter out empty objects before merging
  const objectsToMerge = objects.filter(
    (obj) => obj && Object.keys(obj).length > 0,
  );
  if (objectsToMerge.length === 0) {
    return {};
  }
  return deepmerge(...objectsToMerge) as object;
}
