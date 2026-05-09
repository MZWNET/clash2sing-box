import { z } from "zod";
import { ClashProxyHysteria, SingboxOutboundHysteria } from "../types.ts";
import { doConvertTLSTransport } from "./shared.ts";

const convertHysteria = z.function({
  input: [ClashProxyHysteria],
  output: SingboxOutboundHysteria,
});
export const doConvertHysteria = convertHysteria.implement((proxy) => {
  const outbound: z.infer<typeof SingboxOutboundHysteria> = {
    type: "hysteria",
    tag: proxy.name,
    server: proxy.server,
    server_port: proxy.port,
    up: proxy.up,
    down: proxy.down,
    tls: doConvertTLSTransport(proxy),
  };

  if (proxy.protocol !== "udp") {
    throw new Error("Unsupported protocol faketcp or wechat-video");
  }
  if (proxy.obfs !== undefined) {
    outbound.obfs = proxy.obfs;
  }
  if (proxy["auth-str"] !== undefined) {
    outbound.auth_str = proxy["auth-str"];
  }

  return outbound;
});
