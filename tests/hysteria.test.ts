import { doConvertHysteria } from "../src/libs/converters/hysteria.ts";

describe("doConvertHysteria", () => {
  it("converts basic fields with protocol udp", () => {
    const proxy = {
      name: "test-hy",
      server: "1.2.3.4",
      port: 443,
      type: "hysteria" as const,
      protocol: "udp" as const,
      up: "100 Mbps",
      down: "200 Mbps",
    };

    const result = doConvertHysteria(proxy);

    expect(result.type).toBe("hysteria");
    expect(result.tag).toBe("test-hy");
    expect(result.server).toBe("1.2.3.4");
    expect(result.server_port).toBe(443);
    expect(result.up).toBe("100 Mbps");
    expect(result.down).toBe("200 Mbps");
    expect(result.tls).toEqual({ enabled: true });
  });

  it("throws error for protocol faketcp", () => {
    const proxy = {
      name: "test",
      server: "1.2.3.4",
      port: 443,
      type: "hysteria" as const,
      protocol: "faketcp" as const,
      up: "100",
      down: "200",
    };

    expect(() => doConvertHysteria(proxy)).toThrow("Unsupported protocol faketcp or wechat-video");
  });

  it("throws error for protocol wechat-video", () => {
    const proxy = {
      name: "test",
      server: "1.2.3.4",
      port: 443,
      type: "hysteria" as const,
      protocol: "wechat-video" as const,
      up: "100",
      down: "200",
    };

    expect(() => doConvertHysteria(proxy)).toThrow("Unsupported protocol faketcp or wechat-video");
  });

  it("converts optional obfs field", () => {
    const proxy = {
      name: "test",
      server: "1.2.3.4",
      port: 443,
      type: "hysteria" as const,
      protocol: "udp" as const,
      up: "100",
      down: "200",
      obfs: "obfs-password",
    };

    const result = doConvertHysteria(proxy);

    expect(result.obfs).toBe("obfs-password");
  });

  it("converts optional auth-str to auth_str", () => {
    const proxy = {
      name: "test",
      server: "1.2.3.4",
      port: 443,
      type: "hysteria" as const,
      protocol: "udp" as const,
      up: "100",
      down: "200",
      "auth-str": "my-auth-token",
    };

    const result = doConvertHysteria(proxy);

    expect(result.auth_str).toBe("my-auth-token");
  });

  it("omits obfs and auth_str when not provided", () => {
    const proxy = {
      name: "test",
      server: "1.2.3.4",
      port: 443,
      type: "hysteria" as const,
      protocol: "udp" as const,
      up: "100",
      down: "200",
    };

    const result = doConvertHysteria(proxy);

    expect(result.obfs).toBeUndefined();
    expect(result.auth_str).toBeUndefined();
  });
});
