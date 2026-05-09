import { z } from "zod";
import { ClashProxyVmess, SingboxOutboundVmess } from "../types.ts";
import { doConvertTLSTransport, doConvertVmessOrVLESSTransport } from "./shared.ts";

const convertVmess = z.function({
  input: [ClashProxyVmess],
  output: SingboxOutboundVmess,
});
export const doConvertVmess = convertVmess.implement((proxy) => {
  const outbound: z.infer<typeof SingboxOutboundVmess> = {
    type: "vmess",
    tag: proxy.name,
    server: proxy.server,
    server_port: proxy.port,
    uuid: proxy.uuid,
    security: proxy.cipher,
    alter_id: proxy.alterId,
  };

  const transport = doConvertVmessOrVLESSTransport(proxy);
  if (transport) {
    outbound.transport = transport;
  }

  if (proxy.tls !== undefined) {
    outbound.tls = doConvertTLSTransport(proxy);
  }

  return outbound;
});
