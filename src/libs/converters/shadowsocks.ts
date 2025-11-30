import { z } from "zod";
import { ClashProxyShadowsocks, SingboxOutboundShadowsocks } from "../types.ts";

export const convertShadowsocks = z.function({
  input: [ClashProxyShadowsocks],
  output: SingboxOutboundShadowsocks,
});
export const doConvertShadowsocks = convertShadowsocks.implement((proxy) => {
  const outbound: SingboxOutboundShadowsocks = {
    type: "shadowsocks",
    tag: proxy.name,
    server: proxy.server,
    server_port: proxy.port,
    method: proxy.cipher,
    password: proxy.password,
  };

  if (proxy.plugin !== undefined) {
    if (proxy.plugin === "obfs") {
      outbound.plugin = "obfs-local";
    } else {
      outbound.plugin = proxy.plugin;
    }
    outbound.plugin_opts = "";
    if (proxy["plugin-opts"] !== undefined) {
      outbound.plugin_opts += `mode=${proxy["plugin-opts"].mode}`;
      if (proxy["plugin-opts"].host !== undefined) {
        outbound.plugin_opts += `;host=${proxy["plugin-opts"].host}`;
      }
      if (proxy.plugin === "v2ray-plugin") {
        if (proxy["plugin-opts"].tls === true) {
          outbound.plugin_opts += `;tls`;
        }

        if (proxy["plugin-opts"].path !== undefined) {
          outbound.plugin_opts += `;path=${proxy["plugin-opts"].path}`;
        }
        if (proxy["plugin-opts"].mux !== undefined) {
          outbound.plugin_opts += `;mux=${proxy["plugin-opts"].mux}`;
        }
      }
    }
  }
  if (proxy["udp-over-tcp"] === true) {
    outbound.udp_over_tcp = { enabled: true };
    if (proxy["udp-over-tcp-version"] !== undefined) {
      outbound.udp_over_tcp.version = proxy["udp-over-tcp-version"];
    }
  }

  return outbound;
});
