"use strict";

const fs = require("node:fs");
const http = require("node:http");
const path = require("node:path");

const PORT = Number(process.env.PORT || 5000);
const indexHtml = fs.readFileSync(path.join(__dirname, "index.html"));
const kohazeImage = fs.readFileSync(
  path.join(__dirname, "attached_assets", "c969e9e9637091499c0f7787eefbd090_1793332994576.png"),
);
const contentSecurityPolicy =
  "default-src 'none'; img-src 'self'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

function respond(request, response, status, contentType, body, headers = {}) {
  response.writeHead(status, {
    "Cache-Control": "no-store",
    "Content-Security-Policy": contentSecurityPolicy,
    "Content-Type": contentType,
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-Robots-Tag": "noindex, nofollow, noarchive, nosnippet",
    ...headers,
  });
  response.end(request.method === "HEAD" ? undefined : body);
}

const server = http.createServer((request, response) => {
  const requestUrl = new URL(request.url || "/", "http://site.local");
  const pathname = requestUrl.pathname;

  if (request.method !== "GET" && request.method !== "HEAD") {
    respond(request, response, 405, "text/plain; charset=utf-8", "Method not allowed", {
      Allow: "GET, HEAD",
    });
    return;
  }

  if (pathname === "/" || pathname === "/index.html") {
    respond(request, response, 200, "text/html; charset=utf-8", indexHtml);
    return;
  }

  if (pathname === "/favicon.ico" || pathname === "/apple-touch-icon.png") {
    respond(request, response, 204, "image/x-icon", "");
    return;
  }

  if (pathname === "/kohaze.png") {
    respond(request, response, 200, "image/png", kohazeImage, {
      "Content-Length": String(kohazeImage.length),
    });
    return;
  }

  if (pathname === "/robots.txt") {
    respond(request, response, 200, "text/plain; charset=utf-8", "User-agent: *\nDisallow: /\n");
    return;
  }

  respond(request, response, 404, "text/plain; charset=utf-8", "Not found");
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`Kohaze page listening on port ${PORT}`);
});
