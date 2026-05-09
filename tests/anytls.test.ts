import { doConvertAnyTls } from "../src/libs/converters/anytls.ts";

describe("doConvertAnyTls", () => {
  it("converts basic required fields", () => {
    const proxy = {
      name: "test-anytls",
      server: "1.2.3.4",
      port: 443,
      type: "anytls" as const,
      password: "my-secret",
    };

    const result = doConvertAnyTls(proxy);

    expect(result.type).toBe("anytls");
    expect(result.tag).toBe("test-anytls");
    expect(result.server).toBe("1.2.3.4");
    expect(result.server_port).toBe(443);
    expect(result.password).toBe("my-secret");
    expect(result.tls).toEqual({ enabled: true });
  });

  it("converts TLS via doConvertTLSTransport with sni and skip-cert-verify", () => {
    const proxy = {
      name: "test",
      server: "1.2.3.4",
      port: 443,
      type: "anytls" as const,
      password: "pass",
      sni: "example.com",
      "skip-cert-verify": true,
      alpn: ["h2", "http/1.1"],
    };

    const result = doConvertAnyTls(proxy);

    expect(result.tls).toEqual({
      enabled: true,
      server_name: "example.com",
      insecure: true,
      alpn: ["h2", "http/1.1"],
    });
  });

  it("converts idle-session-check-interval with s suffix", () => {
    const proxy = {
      name: "test",
      server: "1.2.3.4",
      port: 443,
      type: "anytls" as const,
      password: "pass",
      "idle-session-check-interval": 30,
    };

    const result = doConvertAnyTls(proxy);

    expect(result.idle_session_check_interval).toBe("30s");
  });

  it("converts idle-session-timeout with s suffix", () => {
    const proxy = {
      name: "test",
      server: "1.2.3.4",
      port: 443,
      type: "anytls" as const,
      password: "pass",
      "idle-session-timeout": 120,
    };

    const result = doConvertAnyTls(proxy);

    expect(result.idle_session_timeout).toBe("120s");
  });

  it("converts min-idle-session without suffix", () => {
    const proxy = {
      name: "test",
      server: "1.2.3.4",
      port: 443,
      type: "anytls" as const,
      password: "pass",
      "min-idle-session": 5,
    };

    const result = doConvertAnyTls(proxy);

    expect(result.min_idle_session).toBe(5);
  });
});
