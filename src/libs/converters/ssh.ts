import { z } from "zod";
import { ClashProxySSH, SingboxOutboundSSH } from "../types.ts";

export const convertSSH = z.function({
  input: [ClashProxySSH],
  output: SingboxOutboundSSH,
});

export const doConvertSSH = convertSSH.implement((proxy) => {
  const outbound: SingboxOutboundSSH = {
    type: "ssh",
    tag: proxy.name,
    server: proxy.server,
    server_port: proxy.port,
    user: proxy.username,
  };

  if (proxy.password !== undefined) {
    outbound.password = proxy.password;
  }
  if (proxy["private-key"] !== undefined) {
    outbound.private_key = proxy["private-key"];
  }
  if (proxy["private-key-passphrase"] !== undefined) {
    outbound.private_key_passphrase = proxy["private-key-passphrase"];
  }
  if (proxy["host-key"] !== undefined) {
    outbound.host_key = proxy["host-key"];
  }
  if (proxy["host-key-algorithms"] !== undefined) {
    outbound.host_key_algorithms = proxy["host-key-algorithms"];
  }
  if (proxy["interface-name"] !== undefined) {
    outbound.bind_interface = proxy["interface-name"];
  }
  if (proxy["routing-mark"] !== undefined) {
    outbound.routing_mark = proxy["routing-mark"];
  }
  if (proxy.tfo !== undefined) {
    outbound.tcp_fast_open = proxy.tfo;
  }
  if (proxy.mptcp !== undefined) {
    outbound.tcp_multi_path = proxy.mptcp;
  }
  if (proxy["dialer-proxy"] !== undefined) {
    outbound.detour = proxy["dialer-proxy"];
  }

  return outbound;
});
