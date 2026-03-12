// ── Entry Point v4 (Fortaleza) ────────────────────────────────────────────────
import express, { type Request, type Response } from "express";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import crypto from "crypto";
import { loadConfig } from "./config.js";
import { createMcpServer, requestContext, createServices } from "./server.js";
import { authMiddleware } from "./middleware/auth.js";
import { rateLimitMiddleware } from "./middleware/rateLimiter.js";
import { SERVER_VERSION } from "./constants.js";

// FIX M-9: Capturar errores no manejados antes de que maten el proceso sin log
process.on("unhandledRejection", (reason) => {
    process.stderr.write(`🔴 UnhandledRejection: ${String(reason)}\n`);
    process.exit(1);
});
process.on("uncaughtException", (err) => {
    process.stderr.write(`🔴 UncaughtException: ${String(err)}\n`);
    process.exit(1);
});

const config = loadConfig();
const services = createServices(config);

let stdioServer: McpServer | null = null;

if (config.transport === "stdio") {
    stdioServer = createMcpServer(services);
    const transport = new StdioServerTransport();
    try {
        await stdioServer.connect(transport);
    } catch (e) {
        process.stderr.write(`❌ Error iniciando transporte stdio: ${e}\n`);
        process.exit(1);
    }
} else {
    const app = express();

    // FIX Bug-4: Solo confiar en el primer proxy (Cloud Run load balancer)
    app.set("trust proxy", 1);

    // ── CORS ────────────────────────────────────────────────────────────────
    app.use((req: Request, res: Response, next) => {
        const origin = req.headers["origin"] ?? "";
        const allowed = config.allowedOrigins.length > 0
            ? config.allowedOrigins
            : ["http://localhost:3000", "http://localhost:8080"];

        if (allowed.includes(origin) || (allowed.includes("*") && process.env.NODE_ENV !== "production")) {
            res.setHeader("Access-Control-Allow-Origin", origin);
            res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
            res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
        }
        if (req.method === "OPTIONS") { res.sendStatus(204); return; }
        next();
    });

    // ── Security Headers ────────────────────────────────────────────────────
    app.use((req: Request, res: Response, next) => {
        // FIX A-1: Sanitizar X-Request-Id — nunca reflejar valor crudo del cliente
        const rawId = req.headers["x-request-id"];
        const requestId = typeof rawId === "string" && /^[a-zA-Z0-9_\-]{1,64}$/.test(rawId)
            ? rawId
            : crypto.randomUUID();

        res.setHeader("X-Request-Id", requestId);
        res.setHeader("X-Content-Type-Options", "nosniff");
        res.setHeader("X-Frame-Options", "DENY");
        res.setHeader("X-XSS-Protection", "0");
        res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
        res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload");
        res.setHeader("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'");
        res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
        res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
        res.setHeader("Pragma", "no-cache");
        res.setHeader("Expires", "0");
        next();
    });

    app.use(express.json({ limit: "1mb" }));

    // ── Health / Readiness ──────────────────────────────────────────────────
    app.get("/health", (_req, res) => res.json({ status: "ok", timestamp: new Date().toISOString() }));
    app.get("/ready", (_req, res) => res.json({ ready: true }));

    // ── Security Jitter ────────────────────────────────────────────────────
    const securityJitter = () => new Promise(r => setTimeout(r, 50 + Math.random() * 200));

    // ── MCP Endpoint (protegido) ────────────────────────────────────────────
    app.post("/mcp",
        rateLimitMiddleware,
        authMiddleware(config),
        async (req: Request, res: Response) => {
            const clientId = (req as Request & { clientId: string }).clientId;
            const sessionServer = createMcpServer(services);
            const transport = new StreamableHTTPServerTransport({
                sessionIdGenerator: () => crypto.randomUUID(),
                enableJsonResponse: true,
            });

            res.on("close", async () => {
                await transport.close();
                await sessionServer.close();
            });

            try {
                await requestContext.run({ clientId }, async () => {
                    await sessionServer.connect(transport);
                    await transport.handleRequest(req, res, req.body);
                });
            } catch (e) {
                await securityJitter();
                if (!res.headersSent) {
                    res.status(500).json({
                        error: "Internal Security Error",
                        ticketId: crypto.randomBytes(4).toString("hex"),
                    });
                }
            }
        },
    );

    // ── 404 catch-all ───────────────────────────────────────────────────────
    app.use((_req: Request, res: Response) => {
        res.status(404).json({ error: "Not Found" });
    });

    // ── Start ───────────────────────────────────────────────────────────────
    const httpServer = app.listen(config.port, () => {
        process.stderr.write(`✅ GCP Secrets MCP Server v${SERVER_VERSION} — puerto ${config.port}\n`);
    });

    // ── Graceful Shutdown ───────────────────────────────────────────────────
    const shutdown = (signal: string) => {
        process.stderr.write(`⚠️  ${signal} recibido — iniciando apagado limpio...\n`);
        httpServer.close(async () => {
            process.stderr.write("📡 Conexiones HTTP cerradas.\n");
            if (stdioServer) {
                await stdioServer.close();
                process.stderr.write("🔌 MCP Server (stdio) cerrado.\n");
            }
            // FIX A-6: destruir servicios limpiamente
            services.svc.destroy();
            process.stderr.write("🔌 Shutdown completado.\n");
            process.exit(0);
        });
        setTimeout(() => {
            process.stderr.write("⛔ Timeout de apagado — forzando salida.\n");
            process.exit(1);
        }, 8_000).unref();
    };

    process.on("SIGTERM", () => shutdown("SIGTERM"));
    process.on("SIGINT",  () => shutdown("SIGINT"));
}
