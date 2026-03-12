// ── Interfaces centrales v3 ────────────────────────────────────────────────────

export interface SecretMetadata {
    secretId: string;
    fullName: string;
    createTime: string;
    labels: Record<string, string>;
    state: string;
    versions: number;
    mcpAccessible: boolean;
}

export interface SecretVersionInfo {
    version: string;
    state: "ENABLED" | "DISABLED" | "DESTROYED";
    createTime: string;
}

export interface ListSecretsResult {
    secrets: SecretMetadata[];
    totalCount: number;
    pageSize: number;
    hasMore: boolean;
    nextPage: string | null;
}

export interface AuditEvent {
    timestamp: string;
    action: "get_secret" | "list_secrets" | "get_metadata" | "list_versions"
    | "create_secret" | "add_version" | "disable_version" | "delete_version"
    | "permission_check" | "notify_rotation" | "synthesize_env" | "security_breach";
    secretId: string | null;
    clientId: string;
    projectId: string;
    success: boolean;
    errorCode?: string;
    reason?: string;
    ticketId?: string;
}

export interface CacheEntry<T> {
    value: T;
    expiresAt: number;
    iv?: Buffer;
    tag?: Buffer;
}

export interface RateLimitEntry {
    count: number;
    windowStart: number;
}

export interface ServerConfig {
    projectId: string;
    port: number;
    transport: "http" | "stdio";
    authTokens: Set<string>;
    allowedOrigins: string[];
    pubSubTopic: string | null;
}

export type CircuitState = "CLOSED" | "OPEN" | "HALF_OPEN";

export interface CircuitBreakerStats {
    state: CircuitState;
    failures: number;
    successes: number;
    lastFailureAt: string | null;
    openSince: string | null;
}

export interface PermissionCheckResult {
    secretId: string;
    allowed: boolean;
    reason: string;
    hasLabel: boolean;
    hasVersion: boolean;
    serverRole: string;
}

export interface EnvSynthesisResult {
    secretIds: string[];
    envContent: string;
    missingIds: string[];
    generatedAt: string;
}
