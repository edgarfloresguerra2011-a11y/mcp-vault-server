// ── Tools de escritura v3 (Remediado) ─────────────────────────────────────────
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { SecretManagerService } from "../services/SecretManagerService.js";
import { CreateSecretSchema, AddVersionSchema, DisableVersionSchema } from "../schemas/secrets.js";

const ok = (data: unknown) => ({
    content: [{ type: "text" as const, text: JSON.stringify(data, null, 2) }],
});
const err = (msg: string) => ({
    isError: true as const,
    content: [{ type: "text" as const, text: msg }],
});

export function registerWriteTools(
    server: McpServer,
    svc: SecretManagerService,
    clientId: () => string,
): void {

    // ── vault_create_secret ─────────────────────────────────────────────────
    server.registerTool("vault_create_secret", {
        title: "Crear secreto",
        description: `Crea un nuevo secreto en Secret Manager con el label mcp-accessible=true.
Se puede agregar labels adicionales para organización.`,
        inputSchema: CreateSecretSchema,
        annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
    }, async (p) => {
        try { return ok(await svc.createSecret(p.secretId, p.labels, clientId())); }
        catch (e) { return err(e instanceof Error ? e.message : String(e)); }
    });

    // ── vault_add_version ───────────────────────────────────────────────────
    server.registerTool("vault_add_version", {
        title: "Rotar secreto (nueva versión)",
        description: `Agrega una nueva versión al secreto. La anterior permanece habilitada.
Notifica por Pub/Sub a suscriptores para recarga de configuración.

⚠️ El 'value' contiene el secreto real. Trátalo como información sensible.`,
        inputSchema: AddVersionSchema,
        annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
    }, async (p) => {
        try { return ok({ secretId: p.secretId, newVersion: await svc.addSecretVersion(p.secretId, p.value, clientId()) }); }
        catch (e) { return err(e instanceof Error ? e.message : String(e)); }
    });

    // ── vault_disable_version ───────────────────────────────────────────────
    server.registerTool("vault_disable_version", {
        title: "Desactivar versión",
        description: `Desactiva una versión específica del secreto. La versión no se elimina,
pero ya no puede ser accedida. Útil para invalidar versiones comprometidas.`,
        inputSchema: DisableVersionSchema,
        annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: true },
    }, async (p) => {
        try { return ok(await svc.disableVersion(p.secretId, p.version, clientId())); }
        catch (e) { return err(e instanceof Error ? e.message : String(e)); }
    });
}
