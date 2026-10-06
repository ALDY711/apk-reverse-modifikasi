/**
 * Cloudflare Worker Edge Reverse Proxy Script
 * Modeled after Step CF-Worker in C:\streming-anime\backend\src\helpers\getHTML.ts
 *
 * HOW THIS WORKS:
 * When this script is deployed as a free Cloudflare Worker, requests to the target site
 * originate from Cloudflare's own IP addresses and ASNs (Cloudflare Edge).
 * Many websites behind Cloudflare trust incoming requests from internal Cloudflare Edge nodes
 * or do not trigger bot challenges against fellow Cloudflare IPs.
 *
 * DEPLOYMENT:
 * 1. Log in to dash.cloudflare.com -> Workers & Pages -> Create Worker.
 * 2. Paste this code and click Deploy.
 * 3. Set the URL in your app environment: CF_WORKER_URL="https://your-worker.workers.dev"
 */

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const targetUrl = url.searchParams.get("url");

    // Health check or root route
    if (!targetUrl) {
      return new Response(
        JSON.stringify({
          status: "ready",
          service: "CF-Worker Edge Proxy",
          usage: `${url.origin}/?url=https://example.com`,
          timestamp: new Date().toISOString()
        }),
        {
          headers: {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*"
          }
        }
      );
    }

    try {
      // Validate target URL
      const parsedTarget = new URL(targetUrl);

      // Clone original headers while sanitizing problematic proxy headers
      const forwardedHeaders = new Headers(request.headers);
      forwardedHeaders.delete("host");
      forwardedHeaders.delete("cf-connecting-ip");
      forwardedHeaders.delete("cf-ray");
      forwardedHeaders.delete("cf-visitor");
      forwardedHeaders.delete("x-forwarded-for");
      forwardedHeaders.delete("x-real-ip");

      // Default desktop User-Agent if not provided
      if (!forwardedHeaders.get("user-agent")) {
        forwardedHeaders.set(
          "user-agent",
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36"
        );
      }

      // Preserve host header for target
      forwardedHeaders.set("Host", parsedTarget.host);
      forwardedHeaders.set("Referer", parsedTarget.origin);

      const fetchOptions = {
        method: request.method,
        headers: forwardedHeaders,
        redirect: "follow"
      };

      if (request.method !== "GET" && request.method !== "HEAD") {
        fetchOptions.body = await request.arrayBuffer();
      }

      const response = await fetch(targetUrl, fetchOptions);

      // Modify response headers to enable CORS
      const responseHeaders = new Headers(response.headers);
      responseHeaders.set("Access-Control-Allow-Origin", "*");
      responseHeaders.set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
      responseHeaders.set("Access-Control-Allow-Headers", "*");
      responseHeaders.set("X-Proxied-By", "CF-Worker-Bypass-Layer0");

      return new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers: responseHeaders
      });
    } catch (err) {
      return new Response(
        JSON.stringify({
          error: "Proxy upstream request failed",
          message: err.message,
          targetUrl
        }),
        {
          status: 502,
          headers: {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*"
          }
        }
      );
    }
  }
};
