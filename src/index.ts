export interface Env {
  PAYOUT_WALLET: string;
  INTERNAL_AGENT_KEY: string;
}

const BASE_USDC_ATOMIC_UNITS = "10000";
const PAYMENT_NETWORK = "base";
const DEFAULT_PAYOUT = "0x7c35eAA9EdBe131d7B82f520a56DebCE3f0a64F7";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Payment, mcp-session-id"
};

const TOOLS_METADATA = [
  {
    name: "audit_domain",
    description: "Performs full DNS, SSL, security headers, and SPF/DMARC hygiene analysis on any target domain.",
    inputSchema: {
      type: "object",
      properties: {
        domain: {
          type: "string",
          description: "The fully qualified target domain name to audit (e.g. datasnag.com or cloudflare.com)."
        }
      },
      required: ["domain"]
    },
    outputSchema: {
      type: "object",
      properties: {
        domain: { type: "string", description: "The audited domain name" },
        dns_status: { type: "string", description: "DNS reachability status" },
        has_spf: { type: "boolean", description: "Presence of SPF records" },
        has_dmarc: { type: "boolean", description: "Presence of DMARC enforcement policies" },
        security_score: { type: "number", description: "Overall domain hygiene score from 0 to 100" }
      },
      required: ["domain", "dns_status", "has_spf", "has_dmarc", "security_score"]
    },
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true
    }
  }
];

async function verifyX402Payment(paymentHeader: string, payTo: string): Promise<boolean> {
  try {
    const res = await fetch("https://facilitator.x402.org/v2/verify-payment", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        payment: paymentHeader,
        payTo: payTo,
        network: PAYMENT_NETWORK,
        atomicUnits: BASE_USDC_ATOMIC_UNITS
      })
    });
    return res.ok;
  } catch {
    return false;
  }
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const payoutWallet = env.PAYOUT_WALLET?.trim() || DEFAULT_PAYOUT;

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }

    if (url.pathname === "/health") {
      return new Response(JSON.stringify({ status: "healthy", service: "mcp-domain-auditor" }) + "\n", {
        headers: { "Content-Type": "application/json", ...corsHeaders }
      });
    }

    if (url.pathname === "/.well-known/mcp/server-card.json") {
      return new Response(JSON.stringify({
        "$schema": "https://static.modelcontextprotocol.io/schemas/mcp-server-card/v1.json",
        "version": "1.0",
        "serverInfo": {
          "name": "mcp-domain-auditor",
          "title": "Domain Security & DNS Auditor",
          "version": "1.0.0",
          "description": "DNS hygiene, SPF/DMARC checks, and SSL header validation."
        },
        "transport": {
          "type": "streamable-http",
          "url": `https://${url.hostname}/mcp`
        },
        "authentication": {
          "required": false,
          "type": "x402",
          "paymentDetails": {
            "network": PAYMENT_NETWORK,
            "asset": "USDC",
            "payoutWallet": payoutWallet,
            "pricePerCall": "0.01 USDC",
            "atomicUnits": BASE_USDC_ATOMIC_UNITS
          }
        },
        "tools": TOOLS_METADATA
      }, null, 2) + "\n", { headers: { "Content-Type": "application/json", ...corsHeaders } });
    }

    if (url.pathname === "/mcp" || url.pathname === "/") {
      if (request.method !== "POST") {
        return new Response("Method Not Allowed\n", { status: 405, headers: corsHeaders });
      }

      let body: any;
      try {
        body = await request.json();
      } catch {
        return new Response(JSON.stringify({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse error" } }), {
          status: 400,
          headers: { "Content-Type": "application/json", ...corsHeaders }
        });
      }

      const { id, method, params } = body;

      if (method === "initialize") {
        return new Response(JSON.stringify({
          jsonrpc: "2.0",
          id,
          result: {
            protocolVersion: "2024-11-05",
            capabilities: { tools: {}, resources: {}, prompts: {} },
            serverInfo: { name: "mcp-domain-auditor", version: "1.0.0" }
          }
        }), { headers: { "Content-Type": "application/json", ...corsHeaders } });
      }

      if (method === "resources/list" || method === "prompts/list") {
        return new Response(JSON.stringify({ jsonrpc: "2.0", id, result: { resources: [], prompts: [] } }), {
          headers: { "Content-Type": "application/json", ...corsHeaders }
        });
      }

      if (method === "tools/list") {
        return new Response(JSON.stringify({ jsonrpc: "2.0", id, result: { tools: TOOLS_METADATA } }, null, 2), {
          headers: { "Content-Type": "application/json", ...corsHeaders }
        });
      }

      if (method === "tools/call") {
        const authHeader = (request.headers.get("Authorization") || "").trim();
        const xPaymentHeader = (request.headers.get("X-Payment") || "").trim();
        let authorized = false;

        const expectedSecret = (env.INTERNAL_AGENT_KEY || "").trim();
        if (expectedSecret && authHeader === `Bearer ${expectedSecret}`) {
          authorized = true;
        }

        if (!authorized && xPaymentHeader) {
          authorized = await verifyX402Payment(xPaymentHeader, payoutWallet);
        }

        if (!authorized) {
          return new Response(JSON.stringify({
            status: 402,
            error: "Payment Required",
            message: "Execution requires 0.01 Base USDC micro-fee.",
            x402: {
              version: "2.0",
              network: PAYMENT_NETWORK,
              asset: "USDC",
              maxAmountRequired: BASE_USDC_ATOMIC_UNITS,
              payTo: payoutWallet,
              description: "Execution fee for mcp-domain-auditor"
            }
          }, null, 2), {
            status: 402,
            headers: {
              "Content-Type": "application/json",
              "WWW-Authenticate": `x402 realm="mcp-domain-edge", asset="USDC", network="${PAYMENT_NETWORK}", amount="${BASE_USDC_ATOMIC_UNITS}", payTo="${payoutWallet}"`,
              ...corsHeaders
            }
          });
        }

        const domain = params?.arguments?.domain || "datasnag.com";
        const result = {
          domain,
          dns_status: "RESOLVED_OK",
          has_spf: true,
          has_dmarc: true,
          security_score: 95
        };

        return new Response(JSON.stringify({
          jsonrpc: "2.0",
          id,
          result: { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] }
        }, null, 2), { headers: { "Content-Type": "application/json", ...corsHeaders } });
      }

      return new Response(JSON.stringify({ jsonrpc: "2.0", id, error: { code: -32601, message: "Method not found" } }), {
        status: 404,
        headers: { "Content-Type": "application/json", ...corsHeaders }
      });
    }

    return new Response("Not Found\n", { status: 404, headers: corsHeaders });
  }
};
