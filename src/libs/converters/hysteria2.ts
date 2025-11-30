import { z } from "zod";
import { ClashProxyHysteria2, SingboxOutboundHysteria2 } from "../types.ts";

export const convertHysteria2 = z.function({
  input: [ClashProxyHysteria2],
  output: SingboxOutboundHysteria2,
});

function removeUndefined<T extends object>(obj: T): T {
  for (const key in obj) {
    if (obj[key] === undefined) {
      delete obj[key];
    }
  }
  return obj;
}

function convertToNumber(speed?: string): number | undefined {
  if (!speed) {
    return undefined;
  }
  const match = speed.match(/^(\d+)/);
  return match ? parseInt(match[1], 10) : undefined;
}

function convertPorts(ports?: string): string[] | undefined {
  if (!ports) {
    return undefined;
  }
  const replacedSlashes = ports.replace(/\//g, ",");
  return replacedSlashes.split(",").map((p) =>
    p.includes("-") ? p.replace("-", ":") : p
  );
}

export const doConvertHysteria2 = convertHysteria2.implement((proxy) => {
  const up_mbps = convertToNumber(proxy.up);
  const down_mbps = convertToNumber(proxy.down);
  const server_ports = convertPorts(proxy.ports);

  const tls: any = {
    enabled: true,
    server_name: proxy.sni || proxy.servername,
    insecure: proxy["skip-cert-verify"] || false,
    alpn: proxy.alpn,
  };

  if (proxy.certificate) {
    tls.certificate = [proxy.certificate];
  }

  if (proxy.fingerprint) {
    tls.utls = {
      enabled: true,
      fingerprint: proxy.fingerprint,
    };
  }
  if (proxy["client-fingerprint"]) {
    tls.utls = {
      enabled: true,
      fingerprint: proxy["client-fingerprint"],
    };
  }

  if (proxy["reality-opts"]) {
    tls.reality = {
      enabled: true,
      public_key: proxy["reality-opts"]["public-key"],
      short_id: proxy["reality-opts"]["short-id"],
    };
  }

  if (proxy["ech-opts"]?.enable) {
    tls.ech = {
      enabled: true,
      config: proxy["ech-opts"]?.config,
    };
  }

  const obfs = (proxy.obfs && proxy["obfs-password"])
    ? {
      type: proxy.obfs,
      password: proxy["obfs-password"],
    }
    : undefined;

  return removeUndefined({
    type: "hysteria2",
    tag: proxy.name,
    server: proxy.server,
    server_port: proxy.port,
    server_ports: server_ports,
    up_mbps,
    down_mbps,
    password: proxy.password,
    obfs: obfs,
    tls: removeUndefined(tls),
    tcp_fast_open: proxy.tfo,
    tcp_multi_path: proxy.mptcp,
    bind_interface: proxy["interface-name"],
    routing_mark: proxy["routing-mark"],
  });
});
