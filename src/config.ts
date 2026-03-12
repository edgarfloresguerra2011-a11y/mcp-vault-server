// ── Configuración v4 (Fortaleza) ──────────────────────────────────────────────
import { DEFAULT_PORT } from "./constants.js";
import type { ServerConfig } from "./types.js";

function requireEnv(key: string): string {
    const val = process.env[key];
    if (!val?.trim()) {
        process.stderr.write(`❌ Variable de entorno requerida no encontrada: ${key}\n`);
        process.exit(1);
    }
    return val.trim();
}

function loadAuthTokens(): Set<string> {
    const raw = requireEnv("MCP_AUTH_TOKENS");
    const tokens = raw.split(",").map(t => t.trim()).filter(Boolean);
    if (tokens.length === 0) {
        process.stderr.write("❌ MCP_AUTH_TOKENS está vacío.\n");
        process.exit(1);
    }
    return new Set(tokens);
}

export function loadConfig(): ServerConfig {
    const projectId = requireEnv("GCP_PROJECT_ID");
    const authTokens = loadAuthTokens();
    const pubSubTopic = process.env["PUBSUB_ROTATION_TOPIC"] ?? null;

    const allowedOrigins = (process.env["ALLOWED_ORIGINS"] ?? "")
        .split(",").map(o => o.trim()).filter(Boolean);

    // FIX A-5: Validar PORT explícitamente — parseInt("abc") = NaN, listen(NaN) = puerto 0
    const rawPort = parseInt(process.env["PORT"] ?? String(DEFAULT_PORT), 10);
    if (isNaN(rawPort) || rawPort < 1 || rawPort > 65535) {
        process.stderr.write(`❌ PORT inválido: "${process.env["PORT"]}". Debe ser 1-65535.\n`);
        process.exit(1);
    }
    const port = rawPort;

    const transport = (process.env["TRANSPORT"] ?? "http") as "http" | "stdio";
    if (transport !== "http" && transport !== "stdio") {
        process.stderr.write(`❌ TRANSPORT inválido: "${transport}". Debe ser "http" o "stdio".\n`);
        process.exit(1);
    }

    process.stderr.write(`✅ Config v4 cargada: proyecto=${projectId}, transport=${transport}, port=${port}, pubsub=${!!pubSubTopic}\n`);
    return { projectId, port, transport, authTokens, allowedOrigins, pubSubTopic };
}
