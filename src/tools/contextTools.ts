// ── Tools de contexto v3 (Remediado) ──────────────────────────────────────────
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { SecretManagerService } from "../services/SecretManagerService.js";
import { SynthesizeEnvSchema } from "../schemas/secrets.js";

const ok = (data: unknown) => ({
  content: [{ type: "text" as const, text: JSON.stringify(data, null, 2) }],
});
const err = (msg: string) => ({
  isError: true as const,
  content: [{ type: "text" as const, text: msg }],
});

export function registerContextTools(
  server: McpServer,
  svc: SecretManagerService,
  clientId: () => string,
): void {

  server.registerTool("vault_synthesize_env", {
    title: "Generar archivo .env",
    description: "Genera un archivo .env completo con multiples secretos resueltos desde la boveda.",
    inputSchema: SynthesizeEnvSchema,
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: false, openWorldHint: true },
  }, async (p) => {
    try { return ok(await svc.synthesizeEnv(p.secretIds, clientId(), p.reason)); }
    catch (e) { return err(e instanceof Error ? e.message : String(e)); }
  });
}
