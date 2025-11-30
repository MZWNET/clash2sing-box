import { z } from "zod";
import { ClashProxyHttp, SingboxOutboundHttp } from "../types.ts";
import { doConvertTLSTransport } from "./shared.ts";

export const convertHttp = z.function({
  input: [ClashProxyHttp],
  output: SingboxOutboundHttp,
});
export const doConvertHttp = convertHttp.implement((proxy) => {
  const outbound: SingboxOutboundHttp = {
    type: "http",
    tag: proxy.name,
    server: proxy.server,
    server_port: proxy.port,
  };

  if (proxy.username !== undefined) {
    outbound.username = proxy.username;
    if (proxy.password !== undefined) {
      outbound.password = proxy.password;
    }
  }
  if (proxy.tls !== undefined) {
    outbound.tls = doConvertTLSTransport(proxy);
  }

  return outbound;
});
