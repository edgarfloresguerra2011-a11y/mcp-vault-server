# GCP Secrets MCP Server v3 — Nivel Fortaleza

Este servidor MCP ha sido diseñado con estándares de seguridad de nivel bancario (Zero Trust) para gestionar secretos de Google Cloud.

## 🛡️ Características de Seguridad
- **Arquitectura Distroless**: El contenedor no tiene shell ni herramientas de red, reduciendo la superficie de ataque casi a cero.
- **Caché Cifrada**: Los secretos se cifran en memoria usando AES-256-GCM con una llave generada al arranque.
- **Circuit Breaker**: Protección automática contra fallos en cascada de la API de Google Cloud.
- **Auditoría Dual**: Logs estructurados en `stderr` y copias críticas en Google Cloud Logging.
- **IAM Condicional**: Solo el Service Account puede leer secretos marcados con el label `mcp-accessible=true`.
- **Rotación Proactiva**: Notificaciones inmediatas vía Pub/Sub al rotar versiones.

## 🚀 Cómo empezar

### 1. Requisitos de Infraestructura
Asegúrate de tener un secreto llamado `mcp-auth-tokens` en Secret Manager con al menos un token (ej: `mi-token-seguro`).

### 2. Configuración Local
```bash
export GCP_PROJECT_ID="tu-proyecto"
export MCP_AUTH_TOKENS="tu-token-seguro"
npm install
npm run dev
```

### 3. Uso con MCP (10 Tools)
El servidor expone herramientas como `vault_get_secret`, `vault_synthesize_env` y `vault_server_status`.

## 📦 Despliegue
Usa el script proporcionado:
```bash
./infra/deploy.sh [PROJECT_ID] [REGION]
```
