import { deepmerge } from "deepmerge-ts";
import * as yaml from "yaml";
import {
  Clash,
  type SingboxOutbounds,
  SingboxOutboundSelector,
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

export type Options = {
  mergeable?: {
    value: object;
  };
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
  input: string,
  options: Options,
): string {
  const clash: Clash = Clash.parse(yaml.parse(input));

  const outbounds: (SingboxOutbounds | SingboxOutboundSelector)[] = [];

  const singboxOutboundSelector: SingboxOutboundSelector = {
    type: "selector",
    tag: "selector",
    outbounds: [],
  };

  for (const proxy of clash.proxies) {
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

    outbounds.push(outbound);
    singboxOutboundSelector.outbounds.push(outbound.tag);
  }

  if (options.outbound?.selector?.default != undefined) {
    const outbound = outbounds.at(options.outbound.selector.default);
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
      outbounds.push(SingboxOutboundSelector.parse(selector));
    }
  } else {
    outbounds.push(
      SingboxOutboundSelector.parse(singboxOutboundSelector),
    );
  }

  const result = { outbounds };

  if (options.mergeable !== undefined) {
    return JSON.stringify(
      merge(options.mergeable.value, result),
      null,
      2,
    );
  } else {
    return JSON.stringify(result, null, 2);
  }
}

export function merge(...objects: object[]): object {
  return deepmerge(...objects) as object;
}
