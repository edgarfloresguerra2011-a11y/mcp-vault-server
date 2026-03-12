// ── Constantes globales v4 ─────────────────────────────────────────────────────

export const CHARACTER_LIMIT = 8_000;
export const MAX_PAGE_SIZE = 50;
export const DEFAULT_PAGE_SIZE = 20;

export const CACHE_TTL_MS = 5 * 60 * 1_000;          // 5 minutos
// FIX C-2: TTL máximo para valores de secretos antes de re-verificar labels en GCP
// Si quedan menos de este tiempo (20% del TTL), se hace re-fetch completo
export const SECRET_VALUE_MAX_AGE_MS = CACHE_TTL_MS;

export const CACHE_MAX_ENTRIES = 200;

// FIX A-2: Rate limit conservador para compensar que el store es por instancia
// Con max 10 instancias Cloud Run: 20 * 10 = 200 req/min como peor caso (aceptable)
export const RATE_LIMIT_MAX = 20;
export const RATE_LIMIT_WINDOW_MS = 60 * 1_000;

export const DEFAULT_PORT = 8080;
export const SERVER_NAME = "gcp-secrets-mcp-server";
export const SERVER_VERSION = "4.0.0";

export const REQUIRED_LABEL_KEY = "mcp-accessible";
export const REQUIRED_LABEL_VALUE = "true";

export const CB_FAILURE_THRESHOLD = 5;
export const CB_SUCCESS_THRESHOLD = 3;
export const CB_OPEN_TIMEOUT_MS = 30 * 1_000;
