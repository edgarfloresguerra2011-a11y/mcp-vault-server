// ── CircuitBreaker v4 (Fortaleza) ─────────────────────────────────────────────
import { CB_FAILURE_THRESHOLD, CB_SUCCESS_THRESHOLD, CB_OPEN_TIMEOUT_MS } from "../constants.js";
import type { CircuitState, CircuitBreakerStats } from "../types.js";
import type { AuditService } from "./AuditService.js";

export class CircuitBreaker {
    private state: CircuitState = "CLOSED";
    private failures = 0;
    private successes = 0;
    private openAt: number | null = null;

    constructor(private audit?: AuditService, private opName = "unknown") {}

    async execute<T>(fn: () => Promise<T>, opName: string): Promise<T> {
        if (this.state === "OPEN") {
            const elapsed = Date.now() - (this.openAt ?? 0);
            if (elapsed > CB_OPEN_TIMEOUT_MS) {
                this._transition("HALF_OPEN");
            } else {
                const wait = Math.ceil((CB_OPEN_TIMEOUT_MS - elapsed) / 1000);
                throw new Error(`Circuit breaker ABIERTO para "${opName}". Reintente en ${wait}s.`);
            }
        }
        try {
            const res = await fn();
            this._onSuccess();
            return res;
        } catch (err) {
            this._onFailure(opName);
            throw err;
        }
    }

    private _onSuccess(): void {
        if (this.state === "HALF_OPEN") {
            this.successes++;
            if (this.successes >= CB_SUCCESS_THRESHOLD) this._transition("CLOSED");
        } else if (this.state === "CLOSED") {
            this.failures = 0;
        }
    }

    private _onFailure(op: string): void {
        this.failures++;
        if (this.state === "HALF_OPEN" || this.failures >= CB_FAILURE_THRESHOLD) {
            this._transition("OPEN");
            // FIX M-3: log explícito cuando el breaker se abre — nunca silencioso
            process.stderr.write(`🔴 CircuitBreaker ABIERTO: op="${op}" failures=${this.failures}\n`);
            this.audit?.log({
                action: "security_breach",
                secretId: null,
                clientId: "system",
                success: false,
                reason: `CIRCUIT_BREAKER_OPEN: ${op} (${this.failures} failures)`,
            });
        }
    }

    private _transition(next: CircuitState): void {
        const prev = this.state;
        this.state = next;
        if (next === "OPEN")     { this.openAt = Date.now(); this.successes = 0; }
        if (next === "CLOSED")   { this.failures = 0; this.successes = 0; this.openAt = null; }
        if (next === "HALF_OPEN") { this.successes = 0; }

        // FIX M-3: log todas las transiciones
        process.stderr.write(`⚡ CircuitBreaker [${this.opName}]: ${prev} → ${next}\n`);
    }

    get stats(): CircuitBreakerStats {
        return {
            state: this.state, failures: this.failures, successes: this.successes,
            lastFailureAt: this.openAt ? new Date(this.openAt).toISOString() : null,
            openSince: this.state === "OPEN" && this.openAt ? new Date(this.openAt).toISOString() : null,
        };
    }
}
