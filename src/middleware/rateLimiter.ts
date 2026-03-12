// ── Rate Limiter v3 (Remediado) ───────────────────────────────────────────────
// Fix I-09: Purga periódica del store para evitar memory leaks
import type { Request, Response, NextFunction } from "express";
import { RATE_LIMIT_MAX, RATE_LIMIT_WINDOW_MS } from "../constants.js";

interface RateLimitRecord {
    count: number;
    windowStart: number;
}

const store = new Map<string, RateLimitRecord>();

// Purgar entradas expiradas cada 60 segundos para evitar crecimiento indefinido
const PURGE_INTERVAL_MS = 60_000;
setInterval(() => {
    const now = Date.now();
    for (const [key, entry] of store) {
        if (now - entry.windowStart > RATE_LIMIT_WINDOW_MS) {
            store.delete(key);
        }
    }
}, PURGE_INTERVAL_MS).unref(); // .unref() para no bloquear el shutdown

export function rateLimitMiddleware(req: Request, res: Response, next: NextFunction): void {
    // Fix Bug 5: El rate limit corre antes que auth, por lo que siempre debe usar IP.
    const id = req.ip ?? req.socket.remoteAddress ?? "anon";
    const now = Date.now();
    const entry = store.get(id);

    if (!entry || now - entry.windowStart > RATE_LIMIT_WINDOW_MS) {
        store.set(id, { count: 1, windowStart: now });
        next();
        return;
    }

    if (entry.count >= RATE_LIMIT_MAX) {
        const retryAfter = Math.ceil((RATE_LIMIT_WINDOW_MS - (now - entry.windowStart)) / 1000);
        res.setHeader("Retry-After", String(retryAfter));
        res.status(429).json({
            error: "Too Many Requests",
            message: `Límite de ${RATE_LIMIT_MAX} peticiones por minuto excedido`,
            retryAfterSeconds: retryAfter,
        });
        return;
    }

    entry.count++;
    next();
}
