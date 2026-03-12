#!/usr/bin/env bash
# ── deploy.sh v4 (Fortaleza) ──────────────────────────────────────────────────
set -euo pipefail

PROJECT_ID="${1:-$(gcloud config get-value project)}"
REGION="${2:-us-central1}"
IMAGE_TAG="$(git rev-parse --short HEAD 2>/dev/null || echo 'latest')"
IMAGE="$REGION-docker.pkg.dev/$PROJECT_ID/mcp-vault/gcp-secrets-mcp-server:$IMAGE_TAG"
LATEST="$REGION-docker.pkg.dev/$PROJECT_ID/mcp-vault/gcp-secrets-mcp-server:latest"

echo "🔧 Proyecto: $PROJECT_ID | Región: $REGION | Tag: $IMAGE_TAG"

echo "📦 Compilando TypeScript..."
npm run build

echo "🐳 Build distroless..."
gcloud auth configure-docker "$REGION-docker.pkg.dev" --quiet
docker build --platform linux/amd64 -t "$IMAGE" -t "$LATEST" .
docker push "$IMAGE"
docker push "$LATEST"

echo "🚀 Deploy Cloud Run..."
gcloud run deploy mcp-vault-server \
  --image          "$IMAGE" \
  --region         "$REGION" \
  --platform       managed \
  --no-allow-unauthenticated \
  --service-account "mcp-vault-sa@$PROJECT_ID.iam.gserviceaccount.com" \
  --set-env-vars   "GCP_PROJECT_ID=$PROJECT_ID,NODE_ENV=production,TRANSPORT=http,ALLOWED_ORIGINS=${ALLOWED_ORIGINS:-}" \
  --set-secrets    "MCP_AUTH_TOKENS=mcp-auth-tokens:latest" \
  --update-env-vars "PUBSUB_ROTATION_TOPIC=secret-rotation-events" \
  --min-instances  0 \
  --max-instances  10 \
  --memory         512Mi \
  --cpu            1 \
  --timeout        60 \
  --port           8080 \
  --quiet

URL=$(gcloud run services describe mcp-vault-server --region "$REGION" --format "value(status.url)")
echo ""
echo "✅ Deploy v4 exitoso!"
echo "   🌐 $URL"
echo "   🏥 $URL/health"
echo "   🔌 $URL/mcp  (requiere Bearer token)"
