// ── SecretManagerService v4 (Fortaleza) ──────────────────────────────────────
import { SecretManagerServiceClient } from "@google-cloud/secret-manager";
import { CacheService } from "./CacheService.js";
import { AuditService } from "./AuditService.js";
import { CircuitBreaker } from "./CircuitBreaker.js";
import { PubSubService } from "./PubSubService.js";
import type {
    SecretMetadata, SecretVersionInfo, ListSecretsResult,
    PermissionCheckResult, EnvSynthesisResult,
} from "../types.js";
import {
    DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE,
    REQUIRED_LABEL_KEY, REQUIRED_LABEL_VALUE,
    SECRET_VALUE_MAX_AGE_MS,
} from "../constants.js";

const RETRY_ATTEMPTS = 3;
const RETRY_BASE_MS = 200;

// FIX A-3: Solo reintentar errores transitorios de GCP — nunca PERMISSION_DENIED o NOT_FOUND
const RETRYABLE_CODES = new Set([
    "UNAVAILABLE", "DEADLINE_EXCEEDED", "RESOURCE_EXHAUSTED", "ABORTED", "INTERNAL",
]);

function isRetryable(e: unknown): boolean {
    if (e instanceof Error) {
        const msg = e.message.toUpperCase();
        return [...RETRYABLE_CODES].some(code => msg.includes(code));
    }
    return false;
}

async function withRetry<T>(fn: () => Promise<T>, cb: CircuitBreaker, op: string): Promise<T> {
    return cb.execute(async () => {
        let lastErr: unknown;
        for (let i = 0; i < RETRY_ATTEMPTS; i++) {
            try { return await fn(); } catch (e) {
                lastErr = e;
                // FIX A-3: no reintentar errores permanentes
                if (!isRetryable(e)) throw e;
                if (i < RETRY_ATTEMPTS - 1) {
                    await new Promise(r => setTimeout(r, RETRY_BASE_MS * Math.pow(2, i)));
                }
            }
        }
        throw lastErr;
    }, op);
}

function shortName(n: string | null | undefined): string {
    return n?.split("/").pop() ?? "";
}

// FIX C-3: Sanitizar mensajes de error de GCP — nunca exponer paths internos
function sanitizeGcpError(e: unknown): string {
    if (!(e instanceof Error)) return "Error desconocido";
    const msg = e.message;
    // Extraer solo el código de error gRPC, no el path completo del recurso
    const codeMatch = msg.match(/\b(NOT_FOUND|PERMISSION_DENIED|ALREADY_EXISTS|INVALID_ARGUMENT|UNAVAILABLE|INTERNAL|UNAUTHENTICATED|RESOURCE_EXHAUSTED)\b/);
    if (codeMatch) return `GCP_ERROR: ${codeMatch[1]}`;
    return "Error al acceder al secreto";
}

export class SecretManagerService {
    private client = new SecretManagerServiceClient();
    private cache: CacheService;
    private cbs = new Map<string, CircuitBreaker>();

    constructor(
        readonly projectId: string,
        private audit: AuditService,
        private pubsub: PubSubService,
    ) {
        this.cache = new CacheService(audit);
    }

    // FIX A-6: cleanup al destruir el servicio
    destroy(): void {
        this.cache.destroy();
    }

    private _getCB(op: string): CircuitBreaker {
        let cb = this.cbs.get(op);
        if (!cb) { cb = new CircuitBreaker(this.audit, op); this.cbs.set(op, cb); }
        return cb;
    }

    get circuitBreakerStats() { return this._getCB("access").stats; }
    get cacheStats() { return this.cache.stats; }

    // ── Lectura ────────────────────────────────────────────────────────────────

    async checkPermission(secretId: string, clientId: string): Promise<PermissionCheckResult> {
        try {
            const meta = await this.getSecretMetadata(secretId, clientId);
            this.audit.log({ action: "permission_check", secretId, clientId, success: true });
            return {
                secretId, allowed: meta.mcpAccessible,
                reason: meta.mcpAccessible ? "Habilitado por label" : "Falta label mcp-accessible=true",
                hasLabel: meta.mcpAccessible, hasVersion: meta.versions > 0, serverRole: "accessor",
            };
        } catch (e) {
            this.audit.logError("permission_check", secretId, clientId, "CHECK_FAILED");
            throw e;
        }
    }

    async getSecretValue(secretId: string, version: string, clientId: string, reason: string): Promise<string> {
        // Canary Tripwire
        if (secretId.toLowerCase().includes("canary") || secretId === "mcp-admin-trap") {
            this.audit.log({ action: "security_breach", secretId, clientId, success: false, reason: "CANARY_TRAP_TRIGGERED" });
            throw new Error("Access denied");
        }

        await this._assertAccessible(secretId, clientId);

        if (version.includes("/") || version.includes(".")) {
            throw new Error("Formato de version ilegal");
        }

        const key = `val:${secretId}:${version}`;

        // FIX C-2: TOCTOU — si el valor está en cache, verificar que NO haya expirado
        // en más del 80% de su TTL (re-verificar labels en GCP si está próximo a expirar)
        const ageMs = this.cache.getStringAge(key);
        if (ageMs !== null && ageMs > SECRET_VALUE_MAX_AGE_MS * 0.2) {
            const cached = this.cache.getString(key);
            if (cached) {
                this.audit.log({ action: "get_secret", secretId, clientId, success: true, reason });
                return cached;
            }
        } else if (ageMs !== null) {
            // Próximo a expirar: invalidar y re-fetch para re-verificar labels frescos
            this.cache.delete(key);
        }

        const name = `projects/${this.projectId}/secrets/${secretId}/versions/${version}`;
        const [res] = await withRetry(() => this.client.accessSecretVersion({ name }), this._getCB("access"), "access");

        // Double-Check Lock: Re-verificar labels justo antes de devolver (anti-TOCTOU)
        const [latestMeta] = await this.client.getSecret({ name: `projects/${this.projectId}/secrets/${secretId}` });
        const labels = (latestMeta.labels ?? {}) as Record<string, string>;
        if (labels[REQUIRED_LABEL_KEY] !== REQUIRED_LABEL_VALUE) {
            this.audit.log({ action: "security_breach", secretId, clientId, success: false, reason: "JUST_IN_TIME_ACCESS_REVOKED" });
            throw new Error("Access Revoked: Labels changed during request");
        }

        const payloadBuffer = res.payload?.data as Buffer;
        const payload = payloadBuffer?.toString("utf8") ?? "";
        this.cache.setString(key, payload);
        this.audit.log({ action: "get_secret", secretId, clientId, success: true, reason });
        return payload;
    }

    async getSecretMetadata(secretId: string, clientId: string): Promise<SecretMetadata> {
        const key = `meta:${secretId}`;
        const cached = this.cache.getObject<SecretMetadata>(key);
        if (cached) return cached;

        const name = `projects/${this.projectId}/secrets/${secretId}`;
        const [secret] = await withRetry(() => this.client.getSecret({ name }), this._getCB("metadata"), "getSecret");

        // FIX M-4: pageSize=1 para solo verificar existencia de versiones habilitadas
        const [vers] = await withRetry(
            () => this.client.listSecretVersions({ parent: name, filter: "state:ENABLED", pageSize: 10 }),
            this._getCB("listVers"), "listVers",
        );

        const labels = (secret.labels ?? {}) as Record<string, string>;
        const meta: SecretMetadata = {
            secretId,
            fullName: secret.name ?? "",
            createTime: secret.createTime?.seconds
                ? new Date(Number(secret.createTime.seconds) * 1000).toISOString() : "",
            labels,
            state: "ACTIVE",
            versions: Array.isArray(vers) ? vers.length : 0,
            mcpAccessible: labels[REQUIRED_LABEL_KEY] === REQUIRED_LABEL_VALUE,
        };
        this.cache.setObject(key, meta);
        this.audit.log({ action: "get_metadata", secretId, clientId, success: true });
        return meta;
    }

    async listSecrets(clientId: string, pageSize = DEFAULT_PAGE_SIZE, pageToken = ""): Promise<ListSecretsResult> {
        const safePageSize = Math.min(Math.max(1, pageSize), MAX_PAGE_SIZE);
        const [secrets, , response] = await withRetry(() => this.client.listSecrets({
            parent: `projects/${this.projectId}`, pageSize: safePageSize, pageToken,
            filter: `labels.${REQUIRED_LABEL_KEY}=${REQUIRED_LABEL_VALUE}`,
        }), this._getCB("list"), "list");

        const result: ListSecretsResult = {
            secrets: secrets.map(s => ({
                secretId: shortName(s.name),
                fullName: s.name ?? "",
                createTime: "",
                labels: (s.labels ?? {}) as Record<string, string>,
                state: "ACTIVE",
                versions: 0,
                mcpAccessible: true,
            })),
            totalCount: secrets.length,
            pageSize: safePageSize,
            hasMore: !!(response as any)?.nextPageToken,
            nextPage: (response as any)?.nextPageToken ?? null,
        };
        this.audit.log({ action: "list_secrets", secretId: null, clientId, success: true });
        return result;
    }

    async listVersions(secretId: string, clientId: string): Promise<SecretVersionInfo[]> {
        await this._assertAccessible(secretId, clientId);
        const parent = `projects/${this.projectId}/secrets/${secretId}`;

        // FIX M-4: pageSize limitado — nunca paginar miles de versiones
        const [versions] = await withRetry(
            () => this.client.listSecretVersions({ parent, pageSize: 50 }),
            this._getCB("listVersions"), "listVersions",
        );

        const result: SecretVersionInfo[] = (Array.isArray(versions) ? versions : []).map(v => ({
            version: shortName(v.name),
            state: (v.state as SecretVersionInfo["state"]) ?? "ENABLED",
            createTime: v.createTime?.seconds
                ? new Date(Number(v.createTime.seconds) * 1000).toISOString() : "",
        }));
        this.audit.log({ action: "list_versions", secretId, clientId, success: true });
        return result;
    }

    // ── Escritura ──────────────────────────────────────────────────────────────

    async createSecret(
        secretId: string,
        labels: Record<string, string>,
        clientId: string,
    ): Promise<{ secretId: string; fullName: string; labels: Record<string, string> }> {
        const finalLabels = { ...labels, [REQUIRED_LABEL_KEY]: REQUIRED_LABEL_VALUE };

        const [secret] = await withRetry(() => this.client.createSecret({
            parent: `projects/${this.projectId}`,
            secretId,
            secret: { replication: { automatic: {} }, labels: finalLabels },
        }), this._getCB("create"), "createSecret");

        this.audit.log({ action: "create_secret", secretId, clientId, success: true });
        return { secretId, fullName: secret.name ?? "", labels: finalLabels };
    }

    async addSecretVersion(secretId: string, value: string, clientId: string): Promise<string> {
        await this._assertAccessible(secretId, clientId);

        if (Buffer.byteLength(value, "utf8") > 5 * 1024 * 1024) {
            throw new Error("Secret value exceeds security size limit (5MB)");
        }

        const [v] = await withRetry(() => this.client.addSecretVersion({
            parent: `projects/${this.projectId}/secrets/${secretId}`,
            payload: { data: Buffer.from(value, "utf8") },
        }), this._getCB("addVersion"), "addVers");

        const ver = shortName(v.name);
        this.cache.invalidatePrefix(`val:${secretId}`);
        this.cache.delete(`meta:${secretId}`);
        this.audit.log({ action: "add_version", secretId, clientId, success: true });

        void this.pubsub.notifyRotation({
            secretId, newVersion: ver, projectId: this.projectId,
            rotatedAt: new Date().toISOString(), rotatedBy: clientId,
        });
        return ver;
    }

    async disableVersion(secretId: string, version: string, clientId: string): Promise<{ secretId: string; version: string; newState: string }> {
        await this._assertAccessible(secretId, clientId);

        if (version.includes("/") || version.includes(".")) {
            throw new Error("Formato de version ilegal");
        }

        const name = `projects/${this.projectId}/secrets/${secretId}/versions/${version}`;
        const [result] = await withRetry(
            () => this.client.disableSecretVersion({ name }),
            this._getCB("disable"), "disableVersion",
        );

        this.cache.invalidatePrefix(`val:${secretId}`);
        this.cache.delete(`meta:${secretId}`);
        this.audit.log({ action: "disable_version", secretId, clientId, success: true });

        return { secretId, version, newState: (result.state as string) ?? "DISABLED" };
    }

    // ── Contexto ───────────────────────────────────────────────────────────────

    async synthesizeEnv(secretIds: string[], clientId: string, reason: string): Promise<EnvSynthesisResult> {
        const lines = [`# MCP Vault Synthesized — ${new Date().toISOString()}`];
        const missingIds: string[] = [];
        const seenKeys = new Map<string, string>();

        const results = await Promise.allSettled(
            secretIds.map(id => this.getSecretValue(id, "latest", clientId, reason))
        );

        results.forEach((result, index) => {
            const id = secretIds[index]!;
            if (result.status === "fulfilled") {
                const val = result.value;
                const envKey = id.toUpperCase().replace(/[^A-Z0-9_]/g, "_");

                if (seenKeys.has(envKey)) {
                    missingIds.push(id);
                    lines.push(`# ERROR: ${id} — Colisión de nombre con "${seenKeys.get(envKey)}"`);
                } else {
                    seenKeys.set(envKey, id);
                    lines.push(`${envKey}=${val}`);
                }
            } else {
                missingIds.push(id);
                // FIX C-3: Sanitizar error — nunca exponer paths internos de GCP
                const safeMsg = sanitizeGcpError(result.reason);
                lines.push(`# ERROR: ${id} — ${safeMsg}`);
            }
        });

        this.audit.log({ action: "synthesize_env", secretId: null, clientId, success: missingIds.length === 0, reason });
        return {
            secretIds,
            envContent: lines.join("\n"),
            missingIds,
            generatedAt: new Date().toISOString(),
        };
    }

    // ── Interno ────────────────────────────────────────────────────────────────

    private async _assertAccessible(secretId: string, clientId: string): Promise<void> {
        const meta = await this.getSecretMetadata(secretId, clientId);
        if (!meta.mcpAccessible) {
            this.audit.logError("permission_check", secretId, clientId, "LABEL_DENIED");
            throw new Error(`Acceso denegado: secreto no tiene label requerido`);
        }
    }
}
