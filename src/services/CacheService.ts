// ── CacheService v4 (Fortaleza) ───────────────────────────────────────────────
import { createCipheriv, createDecipheriv, randomBytes, createHmac, timingSafeEqual } from "crypto";
import { CACHE_TTL_MS, CACHE_MAX_ENTRIES } from "../constants.js";
import type { CacheEntry } from "../types.js";
import { AuditService } from "./AuditService.js";

const ALGO = "aes-256-gcm";
let RUNTIME_KEY = randomBytes(32);
let HMAC_KEY = randomBytes(32);

function encryptValue(plain: string): { iv: Buffer; tag: Buffer; data: Buffer; mac: Buffer } {
    const iv = randomBytes(16);
    const cipher = createCipheriv(ALGO, RUNTIME_KEY, iv);
    const data = Buffer.concat([cipher.update(plain, "utf8"), cipher.final()]);
    const tag = cipher.getAuthTag();
    const mac = createHmac("sha256", HMAC_KEY).update(Buffer.concat([iv, data, tag])).digest();
    return { iv, tag, data, mac };
}

function decryptValue(enc: { iv: Buffer; tag: Buffer; data: Buffer }): Buffer {
    const decipher = createDecipheriv(ALGO, RUNTIME_KEY, enc.iv);
    decipher.setAuthTag(enc.tag);
    return Buffer.concat([decipher.update(enc.data), decipher.final()]);
}

function verifyMac(entry: { iv: Buffer; tag: Buffer; data: Buffer; mac: Buffer }): boolean {
    const computed = createHmac("sha256", HMAC_KEY)
        .update(Buffer.concat([entry.iv, entry.data, entry.tag]))
        .digest();
    return timingSafeEqual(computed, entry.mac);
}

export class CacheService {
    // FIX A-6: WeakRef para evitar memory leak — el GC puede liberar instancias destruidas
    private static instances = new Set<CacheService>();

    private stringStore = new Map<string, CacheEntry<{ iv: Buffer; tag: Buffer; data: Buffer; mac: Buffer }>>();
    private objectStore = new Map<string, CacheEntry<{ iv: Buffer; tag: Buffer; data: Buffer; mac: Buffer }>>();
    private destroyed = false;

    constructor(private audit?: AuditService) {
        CacheService.instances.add(this);
        CacheService._ensureRotationStarted();
    }

    private static _rotationStarted = false;
    private static _ensureRotationStarted(): void {
        if (this._rotationStarted) return;
        this._rotationStarted = true;

        setInterval(() => {
            RUNTIME_KEY = randomBytes(32);
            HMAC_KEY = randomBytes(32);
            // FIX: limpiar todas las instancias al rotar — entradas viejas son indescifrable
            for (const instance of CacheService.instances) {
                instance.clear();
            }
            process.stderr.write("🔐 Keys rotated + cache cleared\n");
        }, 4 * 60 * 60 * 1000).unref();
    }

    // FIX A-6: destroy() para remover del Set estático — evita memory leak
    public destroy(): void {
        this.clear();
        CacheService.instances.delete(this);
        this.destroyed = true;
    }

    public clear(): void {
        this.stringStore.clear();
        this.objectStore.clear();
    }

    setString(key: string, value: string, ttlMs = CACHE_TTL_MS): void {
        if (this.destroyed) return;
        this._evictIfNeeded(this.stringStore);
        const enc = encryptValue(value);
        this.stringStore.set(key, { value: enc, expiresAt: Date.now() + ttlMs, iv: enc.iv, tag: enc.tag });
    }

    getString(key: string): string | null {
        if (this.destroyed) return null;
        const entry = this.stringStore.get(key);
        if (!entry) return null;
        if (Date.now() > entry.expiresAt) { this.stringStore.delete(key); return null; }

        this.stringStore.delete(key);
        this.stringStore.set(key, entry);

        // FIX C-1/Bug-1: HMAC check completo antes de descifrar
        if (!verifyMac(entry.value)) {
            this.audit?.log({ action: "security_breach", secretId: key, clientId: "system", success: false, reason: "CACHE_TAMPERING_DETECTED_STRING" });
            throw new Error("Cache integrity violation detected");
        }

        const dec = decryptValue(entry.value);
        const result = dec.toString("utf8");
        dec.fill(0);
        return result;
    }

    // FIX C-2: permite preguntar cuándo expira la metadata para forzar re-check de labels
    getStringAge(key: string): number | null {
        const entry = this.stringStore.get(key);
        if (!entry) return null;
        return entry.expiresAt - Date.now();
    }

    setObject<T>(key: string, value: T, ttlMs = CACHE_TTL_MS): void {
        if (this.destroyed) return;
        this._evictIfNeeded(this.objectStore);
        const enc = encryptValue(JSON.stringify(value));
        this.objectStore.set(key, { value: enc, expiresAt: Date.now() + ttlMs, iv: enc.iv, tag: enc.tag });
    }

    getObject<T>(key: string): T | null {
        if (this.destroyed) return null;
        const entry = this.objectStore.get(key);
        if (!entry) return null;
        if (Date.now() > entry.expiresAt) { this.objectStore.delete(key); return null; }

        this.objectStore.delete(key);
        this.objectStore.set(key, entry);

        if (!verifyMac(entry.value)) {
            this.audit?.log({ action: "security_breach", secretId: key, clientId: "system", success: false, reason: "CACHE_TAMPERING_DETECTED_OBJECT" });
            throw new Error("Security violation: cache integrity check failed");
        }

        const dec = decryptValue(entry.value);
        const result = JSON.parse(dec.toString("utf8")) as T;
        dec.fill(0);
        return result;
    }

    invalidatePrefix(prefix: string): void {
        for (const k of this.stringStore.keys()) if (k.startsWith(prefix)) this.stringStore.delete(k);
        for (const k of this.objectStore.keys()) if (k.startsWith(prefix)) this.objectStore.delete(k);
    }

    delete(key: string): void { this.stringStore.delete(key); this.objectStore.delete(key); }

    get stats() { return { strings: this.stringStore.size, objects: this.objectStore.size }; }

    private _evictIfNeeded(store: Map<string, unknown>): void {
        if (store.size >= CACHE_MAX_ENTRIES) {
            const toRemove = Math.ceil(CACHE_MAX_ENTRIES * 0.1);
            const keys = store.keys();
            for (let i = 0; i < toRemove; i++) {
                const k = keys.next().value;
                if (k !== undefined) store.delete(k); else break;
            }
        }
    }
}
