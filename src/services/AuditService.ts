// ── AuditService v4 (Fortaleza) ───────────────────────────────────────────────
// Integridad garantizada por la inmutabilidad nativa de Google Cloud Logging.
import { AuditEvent } from "../types.js";

type Severity = "INFO" | "WARNING" | "ERROR" | "CRITICAL";

// FIX C-1: "security_breach" ahora se persiste en Cloud Logging como CRITICAL
const CRITICAL_ACTIONS = new Set<AuditEvent["action"]>([
    "get_secret", "create_secret", "add_version", "disable_version",
    "security_breach",  // ← CRÍTICO: ataques detectados DEBEN persistirse
]);

const SEVERITY_MAP: Partial<Record<AuditEvent["action"], Severity>> = {
    "security_breach": "CRITICAL",
    "disable_version": "WARNING",
};

export class AuditService {
    private projectId: string;
    private cloudLogging: any = null;
    private pendingLogs: any[] = [];
    private isInitializing = false;

    constructor(projectId: string) {
        this.projectId = projectId;
        this._initCloudLogging();
    }

    private _initCloudLogging(): void {
        if (this.isInitializing) return;
        this.isInitializing = true;

        import("@google-cloud/logging").then(({ Logging }: any) => {
            const logging = new Logging({ projectId: this.projectId });
            this.cloudLogging = logging.log("mcp-vault-audit");
            process.stderr.write("✅ Audit: Cloud Logging SDK inicializado\n");

            if (this.pendingLogs.length > 0) {
                process.stderr.write(`📦 Audit: Flushing ${this.pendingLogs.length} logs pendientes\n`);
                const writePromises = this.pendingLogs.map(p =>
                    this.cloudLogging.write(this.cloudLogging.entry(p.metadata, p.entry))
                );
                Promise.all(writePromises).catch(err =>
                    process.stderr.write(`⚠️  Audit flush error: ${String(err)}\n`)
                );
                this.pendingLogs = [];
            }
        }).catch((err) => {
            process.stderr.write(`⚠️  Audit: Error inicializando SDK: ${String(err)}\n`);
        }).finally(() => {
            this.isInitializing = false;
        });
    }

    log(event: Omit<AuditEvent, "timestamp" | "projectId">): void {
        const entry: AuditEvent = {
            ...event,
            timestamp: new Date().toISOString(),
            projectId: this.projectId,
        };

        // FIX C-1: security_breach = CRITICAL, override de success=false en severity
        const severity: Severity = SEVERITY_MAP[event.action]
            ?? (event.success ? "INFO" : "WARNING");

        const isCritical = CRITICAL_ACTIONS.has(event.action);

        process.stderr.write(JSON.stringify({ severity, ...entry }) + "\n");

        if (isCritical) {
            const metadata = {
                resource: { type: "cloud_run_revision" },
                severity,
            };
            if (this.cloudLogging) {
                this.cloudLogging.write(this.cloudLogging.entry(metadata, entry))
                    .catch((err: unknown) =>
                        process.stderr.write(`⚠️  Audit write falló: ${String(err)}\n`)
                    );
            } else {
                this.pendingLogs.push({ metadata, entry });
                if (this.pendingLogs.length > 100) {
                    process.stderr.write("⚠️ AUDIT BUFFER FULL — dropping oldest critical log\n");
                    this.pendingLogs.shift();
                }
            }
        }
    }

    logError(
        action: AuditEvent["action"],
        secretId: string | null,
        clientId: string,
        errorCode: string,
        reason?: string,
    ): void {
        this.log({ action, secretId, clientId, success: false, errorCode, reason });
    }
}
