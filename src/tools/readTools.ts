// ── Tools de lectura v4 (Fortaleza) ───────────────────────────────────────────
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { SecretManagerService } from "../services/SecretManagerService.js";
import {
    GetSecretSchema, GetMetadataSchema, ListSecretsSchema,
    ListVersionsSchema, PermissionCheckSchema,
} from "../schemas/secrets.js";
import { CHARACTER_LIMIT, SERVER_VERSION } from "../constants.js";

const trunc = (t: string) =>
    t.length <= CHARACTER_LIMIT ? t : t.slice(0, CHARACTER_LIMIT) + "\n\n[truncado]";

const ok = (data: unknown) => ({
    content: [{ type: "text" as const, text: trunc(JSON.stringify(data, null, 2)) }],
});
const err = (msg: string) => ({
    isError: true as const,
    content: [{ type: "text" as const, text: msg }],
});

export function registerReadTools(
    server: McpServer,
    svc: SecretManagerService,
    clientId: () => string,
): void {

    server.registerTool("vault_check_permission", {
        title: "Verificar permisos MCP",
        description: "Verifica si un secreto tiene el label mcp-accessible=true antes de operar.",
        inputSchema: PermissionCheckSchema,
        annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    }, async (p) => {
        try { return ok(await svc.checkPermission(p.secretId, clientId())); }
        catch (e) { return err(e instanceof Error ? e.message : String(e)); }
    });

    server.registerTool("vault_get_secret", {
        title: "Obtener valor del secreto",
        description: `Obtiene el valor de un secreto. Requiere 'reason' de al menos 10 caracteres.\n⚠️ Devuelve el valor REAL. Trátalo como información sensible.`,
        inputSchema: GetSecretSchema,
        annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    }, async (p) => {
        try {
            return ok({
                secretId: p.secretId,
                version: p.version,
                value: await svc.getSecretValue(p.secretId, p.version, clientId(), p.reason),
            });
        }
        catch (e) { return err(e instanceof Error ? e.message : String(e)); }
    });

    server.registerTool("vault_get_metadata", {
        title: "Obtener metadata del secreto",
        description: "Obtiene información del secreto SIN revelar su valor. Seguro para LLMs.",
        inputSchema: GetMetadataSchema,
        annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    }, async (p) => {
        try { return ok(await svc.getSecretMetadata(p.secretId, clientId())); }
        catch (e) { return err(e instanceof Error ? e.message : String(e)); }
    });

    server.registerTool("vault_list_secrets", {
        title: "Listar secretos accesibles",
        description: "Lista los secretos con label mcp-accessible=true. Paginación incluida.",
        inputSchema: ListSecretsSchema,
        annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    }, async (p) => {
        try { return ok(await svc.listSecrets(clientId(), p.pageSize, p.pageToken)); }
        catch (e) { return err(e instanceof Error ? e.message : String(e)); }
    });

    server.registerTool("vault_list_versions", {
        title: "Historial de versiones",
        description: "Lista versiones de un secreto con su estado y fecha.",
        inputSchema: ListVersionsSchema,
        annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    }, async (p) => {
        try { return ok(await svc.listVersions(p.secretId, clientId())); }
        catch (e) { return err(e instanceof Error ? e.message : String(e)); }
    });

    // FIX M-6: server_status sin datos internos sensibles (sin uptime, sin cache sizes)
    // El uptime y estado del CB puede usarse para planificar ataques (timing de key rotation, HALF_OPEN)
    server.registerTool("vault_server_status", {
        title: "Estado del servidor",
        description: "Devuelve el estado operacional del servidor.",
        inputSchema: {},
        annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    }, async () => {
        return ok({
            version: SERVER_VERSION,
            status: "operational",
            circuitBreaker: svc.circuitBreakerStats.state, // Solo el estado, no contadores internos
            timestamp: new Date().toISOString(),
        });
    });
}
