import { z } from "zod";
import {
  ClashProxyBaseTLS,
  ClashProxyBaseVmessOrVLESS,
  SingboxOutboundCommonTlsTransport,
  SingboxOutboundCommonVmessOrVLESSTransport,
} from "../types.ts";

export const convertTLSTransport = z.function({
  input: [ClashProxyBaseTLS],
  output: z.optional(SingboxOutboundCommonTlsTransport),
});
export const doConvertTLSTransport = convertTLSTransport.implement(
  (proxy) => {
    const tls: SingboxOutboundCommonTlsTransport = { enabled: true };
    if (proxy.alpn !== undefined) {
      tls.alpn = proxy.alpn;
    }
    if (proxy.servername !== undefined) {
      tls.server_name = proxy.servername;
    }
    if (proxy.sni !== undefined) {
      tls.server_name = proxy.sni;
    }
    if (proxy["skip-cert-verify"] === true) {
      tls.insecure = true;
    }
    if (proxy["x-clash2singbox-certificate"] !== undefined) {
      tls.certificate = proxy["x-clash2singbox-certificate"];
    }
    if (proxy["x-clash2singbox-certificate-public-key-sha256"] !== undefined) {
      tls.certificate_public_key_sha256 =
        proxy["x-clash2singbox-certificate-public-key-sha256"];
    }

    return tls;
  },
);

export const convertVmessOrVLESSTransport = z.function({
  input: [ClashProxyBaseVmessOrVLESS],
  output: z.optional(SingboxOutboundCommonVmessOrVLESSTransport),
});
export const doConvertVmessOrVLESSTransport = convertVmessOrVLESSTransport
  .implement(
    (proxy) => {
      if (proxy["http-opts"] !== undefined) {
        const transport: SingboxOutboundCommonVmessOrVLESSTransport = {
          "type": "http",
        };
        if (proxy["http-opts"].path !== undefined) {
          transport.path = proxy["http-opts"].path[0];
        }
        if (proxy["http-opts"].method !== undefined) {
          transport.method = proxy["http-opts"].method;
        }
        if (proxy["http-opts"].headers !== undefined) {
          transport.headers = {};
          for (
            const [key, value] of Object.entries(proxy["http-opts"].headers)
          ) {
            transport.headers[key] = value[0];
          }
        }
        return transport;
      } else if (proxy["h2-opts"] !== undefined) {
        const transport: SingboxOutboundCommonVmessOrVLESSTransport = {
          "type": "http",
        };
        if (proxy["h2-opts"].host !== undefined) {
          transport.host = proxy["h2-opts"].host;
        }
        if (proxy["h2-opts"].path !== undefined) {
          transport.path = proxy["h2-opts"].path;
        }
        return transport;
      } else if (
        proxy["ws-opts"] !== undefined &&
        proxy["ws-opts"]["v2ray-http-upgrade"] === true
      ) {
        const transport: SingboxOutboundCommonVmessOrVLESSTransport = {
          "type": "httpupgrade",
        };
        if (proxy["ws-opts"].path !== undefined) {
          transport.path = proxy["ws-opts"].path;
        }
        if (proxy["ws-opts"].headers !== undefined) {
          transport.headers = proxy["ws-opts"].headers;
        }
        return transport;
      } else if (proxy["ws-opts"] !== undefined) {
        const transport: SingboxOutboundCommonVmessOrVLESSTransport = {
          "type": "ws",
        };

        if (proxy["ws-opts"].path !== undefined) {
          transport.path = proxy["ws-opts"].path;
        }
        if (proxy["ws-opts"].headers !== undefined) {
          transport.headers = proxy["ws-opts"].headers;
        }
        if (proxy["ws-opts"]["max-early-data"] !== undefined) {
          transport.max_early_data = proxy["ws-opts"]["max-early-data"];
        }
        if (proxy["ws-opts"]["early-data-header-name"] !== undefined) {
          transport.early_data_header_name =
            proxy["ws-opts"]["early-data-header-name"];
        }
        return transport;
      } else if (proxy["grpc-opts"] !== undefined) {
        const transport: SingboxOutboundCommonVmessOrVLESSTransport = {
          "type": "grpc",
        };
        if (proxy["grpc-opts"]["grpc-service-name"] !== undefined) {
          transport.service_name = proxy["grpc-opts"]["grpc-service-name"];
        }
        return transport;
      }

      return undefined;
    },
  );
