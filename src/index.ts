export interface Env {}

// Tool 1: DNS Record Inspector (via Cloudflare 1.1.1.1 DNS over HTTPS)
async function handleDnsRecords(args: { domain: string; type?: string }) {
  const recordType = args.type || "A";
  const url = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(args.domain)}&type=${encodeURIComponent(recordType)}`;

  const res = await fetch(url, {
    headers: { Accept: "application/dns-json" }
  });

  if (!res.ok) {
    return { status: "error", message: `DNS lookup failed with status ${res.status}` };
  }

  const data: any = await res.json();
  return {
    domain: args.domain,
    type: recordType,
    status: data.Status === 0 ? "NOERROR" : `Status ${data.Status}`,
    answers: (data.Answer || []).map((ans: any) => ({
      name: ans.name,
      type: ans.type,
      ttl: ans.TTL,
      data: ans.data
    }))
  };
}

// Tool 2: HTTP Security Headers & TLS Inspection
async function handleSecurityHeaders(args: { domain: string }) {
  const target = args.domain.startsWith("http") ? args.domain : `https://${args.domain}`;

  try {
    const res = await fetch(target, { method: "HEAD", redirect: "follow" });
    const headers = Object.fromEntries(res.headers.entries());

    const securityHeaders = {
      "strict-transport-security": headers["strict-transport-security"] || "Missing",
      "content-security-policy": headers["content-security-policy"] || "Missing",
      "x-frame-options": headers["x-frame-options"] || "Missing",
      "x-content-type-options": headers["x-content-type-options"] || "Missing",
      "referrer-policy": headers["referrer-policy"] || "Missing",
      "permissions-policy": headers["permissions-policy"] || "Missing"
    };

    return {
      domain: args.domain,
      status: res.status,
      security_headers: securityHeaders,
      raw_headers: headers
    };
  } catch (err: any) {
    return { status: "error", message: `Failed to fetch target: ${err.message}` };
  }
}

// Tool 3: SPF / DMARC Email Hygiene Inspector
async function handleEmailHygiene(args: { domain: string }) {
  const txtUrl = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(args.domain)}&type=TXT`;
  const dmarcUrl = `https://cloudflare-dns.com/dns-query?name=_dmarc.${encodeURIComponent(args.domain)}&type=TXT`;

  const [txtRes, dmarcRes] = await Promise.all([
    fetch(txtUrl, { headers: { Accept: "application/dns-json" } }),
    fetch(dmarcUrl, { headers: { Accept: "application/dns-json" } })
  ]);

  const txtData: any = await txtRes.json();
  const dmarcData: any = await dmarcRes.json();

  const spfRecord = (txtData.Answer || []).find((a: any) => a.data && a.data.includes("v=spf1"))?.data || "No SPF record found";
  const dmarcRecord = (dmarcData.Answer || []).find((a: any) => a.data && a.data.includes("v=DMARC1"))?.data || "No DMARC record found";

  return {
    domain: args.domain,
    spf: spfRecord,
    dmarc: dmarcRecord,
    has_spf: spfRecord !== "No SPF record found",
    has_dmarc: dmarcRecord !== "No DMARC record found"
  };
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    // CORS Preflight
    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type, Authorization, x-api-key"
        }
      });
    }

    // Healthcheck
    if (url.pathname === "/health") {
      return new Response(JSON.stringify({ status: "healthy", timestamp: new Date().toISOString() }), {
        status: 200,
        headers: { "Content-Type": "application/json" }
      });
    }

    // Server-Card Discovery Route
    if (url.pathname === "/.well-known/mcp/server-card.json") {
      return new Response(
        JSON.stringify({
          serverInfo: { name: "io.github.geekmarine/mcp-domain-auditor", version: "1.0.0" },
          authentication: { required: false },
          tools: [
            {
              name: "dns_lookup",
              description: "Look up DNS records (A, AAAA, MX, TXT, NS) via Cloudflare DoH.",
              inputSchema: {
                type: "object",
                properties: {
                  domain: { type: "string", description: "Target domain name" },
                  type: { type: "string", description: "Record type (A, AAAA, MX, TXT, NS)", default: "A" }
                },
                required: ["domain"]
              }
            },
            {
              name: "security_headers",
              description: "Audit HTTP response security headers (HSTS, CSP, X-Frame-Options).",
              inputSchema: {
                type: "object",
                properties: {
                  domain: { type: "string", description: "Target domain name or full URL" }
                },
                required: ["domain"]
              }
            },
            {
              name: "email_hygiene",
              description: "Check SPF and DMARC records for spoofing and phishing defenses.",
              inputSchema: {
                type: "object",
                properties: {
                  domain: { type: "string", description: "Target domain to inspect" }
                },
                required: ["domain"]
              }
            }
          ]
        }),
        {
          status: 200,
          headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
        }
      );
    }

    // JSON-RPC MCP Streamable HTTP Route
    if (url.pathname === "/mcp" || url.pathname === "/") {
      if (request.method === "POST") {
        let body: any;
        try {
          body = await request.json();
        } catch {
          return new Response(JSON.stringify({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse error" } }), {
            status: 400,
            headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
          });
        }

        const id = body.id;

        // Protocol Initialization Handshake
        if (body.method === "initialize") {
          return new Response(
            JSON.stringify({
              jsonrpc: "2.0",
              id,
              result: {
                protocolVersion: "2024-11-05",
                capabilities: { tools: {} },
                serverInfo: { name: "io.github.geekmarine/mcp-domain-auditor", version: "1.0.0" }
              }
            }),
            { status: 200, headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" } }
          );
        }

        // Tools Listing
        if (body.method === "tools/list") {
          return new Response(
            JSON.stringify({
              jsonrpc: "2.0",
              id,
              result: {
                tools: [
                  {
                    name: "dns_lookup",
                    description: "Look up DNS records (A, AAAA, MX, TXT, NS) via Cloudflare DoH.",
                    inputSchema: {
                      type: "object",
                      properties: {
                        domain: { type: "string" },
                        type: { type: "string", default: "A" }
                      },
                      required: ["domain"]
                    }
                  },
                  {
                    name: "security_headers",
                    description: "Audit HTTP response security headers (HSTS, CSP, X-Frame-Options).",
                    inputSchema: {
                      type: "object",
                      properties: {
                        domain: { type: "string" }
                      },
                      required: ["domain"]
                    }
                  },
                  {
                    name: "email_hygiene",
                    description: "Check SPF and DMARC records for spoofing and phishing defenses.",
                    inputSchema: {
                      type: "object",
                      properties: {
                        domain: { type: "string" }
                      },
                      required: ["domain"]
                    }
                  }
                ]
              }
            }),
            { status: 200, headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" } }
          );
        }

        // Tools Execution
        if (body.method === "tools/call") {
          const toolName = body.params?.name;
          const args = body.params?.arguments || {};
          let resultData: any;

          if (toolName === "dns_lookup") {
            resultData = await handleDnsRecords(args);
          } else if (toolName === "security_headers") {
            resultData = await handleSecurityHeaders(args);
          } else if (toolName === "email_hygiene") {
            resultData = await handleEmailHygiene(args);
          } else {
            return new Response(
              JSON.stringify({
                jsonrpc: "2.0",
                id,
                error: { code: -32601, message: `Tool ${toolName} not found` }
              }),
              { status: 404, headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" } }
            );
          }

          return new Response(
            JSON.stringify({
              jsonrpc: "2.0",
              id,
              result: {
                content: [{ type: "text", text: JSON.stringify(resultData, null, 2) }]
              }
            }),
            { status: 200, headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" } }
          );
        }

        return new Response(
          JSON.stringify({ jsonrpc: "2.0", id, error: { code: -32601, message: "Method not found" } }),
          { status: 404, headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" } }
        );
      }
    }

    return new Response("Not Found", { status: 404 });
  }
};
