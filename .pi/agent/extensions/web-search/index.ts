/**
 * Web search & fetch tools, ported from opencode's websearch/webfetch
 * (see opencode-web-search-port-spec.md).
 *
 * Env:
 *   PI_WEBSEARCH_PROVIDER  "exa" | "parallel" (default "exa")
 *   EXA_API_KEY            appended to Exa MCP URL
 *   PARALLEL_API_KEY       Bearer token for Parallel MCP
 */
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { StringEnum } from "@earendil-works/pi-ai";
import { Type } from "typebox";
import TurndownService from "turndown";

const UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36";

// --- MCP client (hand-rolled JSON-RPC over HTTP, JSON or SSE response) ---
async function mcpCall(url: string, tool: string, args: unknown, headers: Record<string, string>, timeoutMs: number) {
	const res = await fetch(url, {
		method: "POST",
		headers: { "content-type": "application/json", accept: "application/json, text/event-stream", ...headers },
		body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: tool, arguments: args } }),
		signal: AbortSignal.timeout(timeoutMs),
	});
	if (!res.ok) throw new Error(`MCP request failed: HTTP ${res.status}`);
	const body = await res.text();
	// SSE: keep only data: lines, take the first valid JSON payload
	const candidates = res.headers.get("content-type")?.includes("text/event-stream") || body.startsWith("data:")
		? body.split("\n").filter((l) => l.startsWith("data:")).map((l) => l.slice(5).trim())
		: [body];
	for (const c of candidates) {
		try {
			const json = JSON.parse(c);
			const text = json?.result?.content?.filter((p: any) => p.type === "text").map((p: any) => p.text).join("\n");
			if (text) return text as string;
		} catch { /* skip malformed chunk */ }
	}
	return undefined;
}

// --- HTML helpers ---
function stripBoiler(html: string) {
	return html.replace(/<(script|style|noscript|iframe|svg)[\s\S]*?<\/\1>/gi, "");
}
function htmlToText(html: string) {
	return stripBoiler(html)
		.replace(/<[^>]+>/g, " ")
		.replace(/&nbsp;/g, " ").replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&#39;/g, "'")
		.replace(/[ \t]+/g, " ").replace(/\n\s*\n+/g, "\n\n").trim();
}

const isImage = (mime: string) => mime.startsWith("image/") && !["image/svg+xml", "image/vnd.fastbidsheet"].includes(mime);

export default function (pi: ExtensionAPI) {
	const turndown = new TurndownService({ headingStyle: "atx", codeBlockStyle: "fenced" });
	turndown.remove(["script", "style"]);

	// ---------- websearch ----------
	pi.registerTool({
		name: "websearch",
		label: "Web Search",
		description: `Search the web for real-time information. The current year is ${new Date().getFullYear()}; use it in queries about recent events. Returns relevant results with page content.`,
		promptSnippet: "Search the web in real time",
		parameters: Type.Object({
			query: Type.String({ description: "Search query" }),
			numResults: Type.Optional(Type.Number({ description: "Number of results (default 8)" })),
			livecrawl: Type.Optional(StringEnum(["fallback", "preferred"] as const)),
			type: Type.Optional(StringEnum(["auto", "fast", "deep"] as const)),
			contextMaxCharacters: Type.Optional(Type.Number({ description: "Max characters of page content (default 10000)" })),
		}),
		async execute(_id, params) {
			const provider = (process.env.PI_WEBSEARCH_PROVIDER ?? "exa").toLowerCase();
			const args = {
				query: params.query,
				numResults: params.numResults ?? 8,
				livecrawl: params.livecrawl ?? "fallback",
				type: params.type ?? "auto",
				contextMaxCharacters: params.contextMaxCharacters ?? 10000,
			};
			let text: string | undefined;
			if (provider === "parallel") {
				const key = process.env.PARALLEL_API_KEY;
				text = await mcpCall("https://search.parallel.ai/mcp", "web_search", args,
					key ? { authorization: `Bearer ${key}` } : {}, 25_000);
			} else {
				const key = process.env.EXA_API_KEY;
				const url = "https://mcp.exa.ai/mcp" + (key ? `?exaApiKey=${encodeURIComponent(key)}` : "");
				text = await mcpCall(url, "web_search_exa", args, {}, 25_000);
			}
			return { content: [{ type: "text", text: text ?? "No search results found. Please try a different query." }] };
		},
	});

	// ---------- webfetch ----------
	pi.registerTool({
		name: "webfetch",
		label: "Web Fetch",
		description: "Fetch a URL and return its content as markdown, text, or raw html. Images are returned as image attachments.",
		promptSnippet: "Fetch a single URL and convert it to markdown/text/html",
		parameters: Type.Object({
			url: Type.String({ description: "URL to fetch (must start with http:// or https://)" }),
			format: Type.Optional(StringEnum(["text", "markdown", "html"] as const)),
			timeout: Type.Optional(Type.Number({ description: "Timeout in seconds (default 30, max 120)" })),
		}),
		async execute(_id, params, signal) {
			const { url, format = "markdown" } = params;
			if (!/^https?:\/\//.test(url)) throw new Error("URL must start with http:// or https://");
			const timeout = Math.min(params.timeout ?? 30, 120) * 1000;
			const accept =
				format === "markdown" ? "text/markdown, text/html, */*" :
				format === "text" ? "text/plain, text/html, */*" :
				"text/html, */*";
			const doFetch = (ua: string) => fetch(url, {
				headers: { "user-agent": ua, accept },
				redirect: "follow",
				signal: AbortSignal.any([AbortSignal.timeout(timeout), ...(signal ? [signal] : [])]),
			});
			let res = await doFetch(UA);
			// Cloudflare challenge: retry once with an honest UA
			if (res.status === 403 && res.headers.get("cf-mitigated") === "challenge") {
				res = await doFetch("pi");
			}
			if (!res.ok) {
				// Include a snippet of the error body so the model can self-correct (bad params, missing key, etc.)
				const detail = (await res.text().catch(() => "")).replace(/\s+/g, " ").slice(0, 500).trim();
				throw new Error(`Request failed: HTTP ${res.status}${detail ? ` — ${detail}` : ""}`);
			}
			const mime = (res.headers.get("content-type") ?? "").split(";")[0].trim().toLowerCase();
			const buf = Buffer.from(await res.arrayBuffer());
			if (buf.length > 5 * 1024 * 1024) throw new Error("Response too large (exceeds 5MB limit)");

			if (isImage(mime)) {
				return {
					content: [
						{ type: "text", text: `Image fetched (${mime}, ${buf.length} bytes)` },
						{ type: "image", mimeType: mime, data: buf.toString("base64") },
					],
				};
			}
			const html = buf.toString("utf8");
			const isHtml = mime.includes("html") || (!mime && looksLikeHtml(html));
			let out: string;
			if (format === "html" || !isHtml) out = html;
			else if (format === "markdown") out = turndown.turndown(html);
			else out = htmlToText(html);
			return { content: [{ type: "text", text: out }] };
		},
	});
}

function looksLikeHtml(s: string) {
	return /<(html|head|body|div|p|a)[\s>]/i.test(s.slice(0, 2000));
}
