// ── Auth Middleware v4 (Fortaleza) ────────────────────────────────────────────
import { createHash, timingSafeEqual } from "crypto";
import type { Request, Response, NextFunction } from "express";
import type { ServerConfig } from "../types.js";

export function tokenId(token: string): string {
    return createHash("sha256").update(token).digest("hex").slice(0, 8);
}

function safeCompare(token: string, secretToken: string): boolean {
    const tBuf = createHash("sha256").update(token).digest();
    const sBuf = createHash("sha256").update(secretToken).digest();
    return timingSafeEqual(tBuf, sBuf);
}

// FIX M-1: jitter aplicado a TODOS los errores de auth, no solo al 403
// Evita distinguir entre "no envié token" y "token incorrecto" por tiempo de respuesta
const authJitter = () => new Promise<void>(r =>
    setTimeout(r, 200 + Math.random() * 500)
);

export function authMiddleware(config: ServerConfig) {
    return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
        const authHeader = req.headers["authorization"];

        if (!authHeader?.startsWith("Bearer ")) {
            await authJitter(); // FIX M-1: jitter también en 401
            res.status(401).json({ error: "Unauthorized", message: "Bearer token requerido" });
            return;
        }

        // FIX M-2: slice en vez de split — captura todo lo que sigue al "Bearer "
        const token = authHeader.slice("Bearer ".length);

        if (!token) {
            await authJitter();
            res.status(401).json({ error: "Unauthorized", message: "Bearer token requerido" });
            return;
        }

        let isValid = false;
        for (const t of config.authTokens) {
            if (safeCompare(token, t)) { isValid = true; break; }
        }

        if (!isValid) {
            await authJitter();
            res.status(403).json({ error: "Forbidden", message: "Token inválido" });
            return;
        }

        (req as any).clientId = tokenId(token);
        next();
    };
}
