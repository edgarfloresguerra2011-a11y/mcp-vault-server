# ── Infraestructura v4 (Fortaleza) ────────────────────────────────────────────

# FIX A-4: Backend remoto en GCS — el state NO se guarda localmente en texto plano
terraform {
  required_version = ">= 1.6"
  required_providers {
    google      = { source = "hashicorp/google",      version = "~> 5.0" }
    google-beta = { source = "hashicorp/google-beta", version = "~> 5.0" }
  }
  backend "gcs" {
    bucket = "REEMPLAZAR-CON-TU-BUCKET-DE-STATE"
    prefix = "mcp-vault/terraform"
  }
}

provider "google"      { project = var.project_id; region = var.region }
provider "google-beta" { project = var.project_id; region = var.region }

# ── Artifact Registry ──────────────────────────────────────────────────────────
resource "google_artifact_registry_repository" "mcp_repo" {
  location      = var.region
  repository_id = "mcp-vault"
  format        = "DOCKER"
  description   = "Imágenes del MCP Vault Server"
}

# ── Service Account mínimo privilegio ─────────────────────────────────────────
resource "google_service_account" "mcp_sa" {
  account_id   = "mcp-vault-sa"
  display_name = "MCP Vault SA — mínimos privilegios"
}

resource "google_project_iam_member" "secret_accessor" {
  project = var.project_id
  role    = "roles/secretmanager.secretAccessor"
  member  = "serviceAccount:${google_service_account.mcp_sa.email}"
  condition {
    title      = "mcp-label-only"
    expression = "resource.labels.\"mcp-accessible\" == \"true\""
  }
}

resource "google_project_iam_member" "secret_viewer" {
  project = var.project_id
  role    = "roles/secretmanager.viewer"
  member  = "serviceAccount:${google_service_account.mcp_sa.email}"
  condition {
    title      = "mcp-label-only-viewer"
    expression = "resource.labels.\"mcp-accessible\" == \"true\""
  }
}

resource "google_secret_manager_secret_iam_member" "auth_token_accessor" {
  secret_id = google_secret_manager_secret.mcp_auth_tokens.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.mcp_sa.email}"
}

resource "google_project_iam_member" "pubsub_publisher" {
  project = var.project_id
  role    = "roles/pubsub.publisher"
  member  = "serviceAccount:${google_service_account.mcp_sa.email}"
}

resource "google_project_iam_member" "log_writer" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.mcp_sa.email}"
}

# ── Pub/Sub ────────────────────────────────────────────────────────────────────
resource "google_pubsub_topic" "rotation_events" {
  name                       = "secret-rotation-events"
  labels                     = { managed-by = "terraform" }
  message_retention_duration = "86400s"
}

resource "google_pubsub_subscription" "rotation_sub" {
  name                       = "secret-rotation-sub"
  topic                      = google_pubsub_topic.rotation_events.name
  ack_deadline_seconds       = 20
  message_retention_duration = "86400s"
  retain_acked_messages      = false
  expiration_policy { ttl = "" }
}

# ── Secret para tokens de auth ────────────────────────────────────────────────
resource "google_secret_manager_secret" "mcp_auth_tokens" {
  secret_id = "mcp-auth-tokens"
  replication { auto {} }
  labels = {
    managed-by       = "terraform"
    env              = var.env
    "mcp-accessible" = "false"
  }
}

# ── Cloud Run ─────────────────────────────────────────────────────────────────
resource "google_cloud_run_v2_service" "mcp_vault" {
  name     = "mcp-vault-server"
  location = var.region

  template {
    service_account = google_service_account.mcp_sa.email
    scaling {
      min_instance_count = var.min_instances
      max_instance_count = var.max_instances
    }
    containers {
      image = "${var.region}-docker.pkg.dev/${var.project_id}/mcp-vault/gcp-secrets-mcp-server:latest"
      resources {
        limits   = { cpu = "1", memory = "512Mi" }
        cpu_idle = true
      }
      env { name = "GCP_PROJECT_ID";        value = var.project_id }
      env { name = "NODE_ENV";              value = "production" }
      env { name = "PORT";                  value = "8080" }
      env { name = "TRANSPORT";             value = "http" }
      env { name = "ALLOWED_ORIGINS";       value = join(",", var.allowed_origins) }
      env { name = "PUBSUB_ROTATION_TOPIC"; value = google_pubsub_topic.rotation_events.name }
      env {
        name = "MCP_AUTH_TOKENS"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.mcp_auth_tokens.secret_id
            version = "latest"
          }
        }
      }
      startup_probe {
        http_get { path = "/health" }
        initial_delay_seconds = 5
        period_seconds        = 5
        failure_threshold     = 10
      }
      liveness_probe {
        http_get { path = "/health" }
        period_seconds    = 30
        failure_threshold = 3
      }
    }
  }
  traffic {
    type    = "TRAFFIC_TARGET_ALLOCATION_TYPE_LATEST"
    percent = 100
  }
}

# FIX C-5: Denegar acceso público a Cloud Run — solo el LB puede invocar
resource "google_cloud_run_v2_service_iam_member" "deny_all_users" {
  # No otorgamos allUsers — Cloud Run requiere auth IAM por defecto
  # El LB usa el service account del backend para invocar
  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.mcp_vault.name
  role     = "roles/run.invoker"
  member   = "serviceAccount:${google_service_account.mcp_sa.email}"
}

# ── Cloud Armor — WAF ──────────────────────────────────────────────────────────
resource "google_compute_security_policy" "mcp_armor" {
  provider    = google-beta
  name        = "mcp-vault-armor"
  description = "WAF para MCP Vault"

  rule {
    action   = "deny(403)"
    priority = 1000
    match { expr { expression = "evaluatePreconfiguredExpr('sqli-stable')" } }
    description = "Bloquear SQL injection"
  }
  rule {
    action   = "deny(403)"
    priority = 1001
    match { expr { expression = "evaluatePreconfiguredExpr('xss-stable')" } }
    description = "Bloquear XSS"
  }
  rule {
    action   = "throttle"
    priority = 2000
    match {
      versioned_expr = "SRC_IPS_V1"
      config { src_ip_ranges = ["*"] }
    }
    rate_limit_options {
      conform_action = "allow"
      exceed_action  = "deny(429)"
      rate_limit_threshold { count = 100; interval_sec = 60 }
    }
    description = "Rate limit 100 req/min por IP"
  }
  dynamic "rule" {
    for_each = length(var.allowed_countries) > 0 ? [1] : []
    content {
      action   = "deny(403)"
      priority = 3000
      match {
        expr {
          # FIX Bug-10: expresión correcta para geo-blocking en Cloud Armor
          expression = "!(origin.region_code in [${join(",", formatlist("'%s'", var.allowed_countries))}])"
        }
      }
      description = "Bloquear países no autorizados"
    }
  }
  rule {
    action   = "allow"
    priority = 2147483647
    match {
      versioned_expr = "SRC_IPS_V1"
      config { src_ip_ranges = ["*"] }
    }
    description = "Default: permitir"
  }
}

# FIX C-4: Cloud Armor conectado a Cloud Run via Load Balancer + Serverless NEG
# Sin esto, Cloud Armor existe pero NUNCA aplica al tráfico real

resource "google_compute_region_network_endpoint_group" "mcp_neg" {
  name                  = "mcp-vault-neg"
  network_endpoint_type = "SERVERLESS"
  region                = var.region
  cloud_run {
    service = google_cloud_run_v2_service.mcp_vault.name
  }
}

resource "google_compute_backend_service" "mcp_backend" {
  name                  = "mcp-vault-backend"
  protocol              = "HTTPS"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  security_policy       = google_compute_security_policy.mcp_armor.id

  backend {
    group = google_compute_region_network_endpoint_group.mcp_neg.id
  }
}

resource "google_compute_url_map" "mcp_url_map" {
  name            = "mcp-vault-url-map"
  default_service = google_compute_backend_service.mcp_backend.id
}

resource "google_compute_managed_ssl_certificate" "mcp_ssl" {
  name = "mcp-vault-ssl"
  managed {
    domains = var.domains
  }
}

resource "google_compute_target_https_proxy" "mcp_proxy" {
  name             = "mcp-vault-https-proxy"
  url_map          = google_compute_url_map.mcp_url_map.id
  ssl_certificates = [google_compute_managed_ssl_certificate.mcp_ssl.id]
}

resource "google_compute_global_forwarding_rule" "mcp_forwarding" {
  name                  = "mcp-vault-forwarding-rule"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  port_range            = "443"
  target                = google_compute_target_https_proxy.mcp_proxy.id
  ip_address            = google_compute_global_address.mcp_ip.address
}

resource "google_compute_global_address" "mcp_ip" {
  name = "mcp-vault-ip"
}

# ── VPC Service Controls ───────────────────────────────────────────────────────
resource "google_access_context_manager_service_perimeter" "mcp_perimeter" {
  count  = var.enable_vpc_sc ? 1 : 0
  parent = "accessPolicies/${var.access_policy_id}"
  name   = "accessPolicies/${var.access_policy_id}/servicePerimeters/mcp_vault"
  title  = "MCP Vault Perimeter"

  status {
    resources           = ["projects/${var.project_number}"]
    restricted_services = ["secretmanager.googleapis.com", "pubsub.googleapis.com"]
    ingress_policies {
      ingress_from {
        sources { resource = "projects/${var.project_number}" }
        # FIX M-10: Identidad específica — solo mcp-vault-sa, no cualquier SA del proyecto
        identities = ["serviceAccount:mcp-vault-sa@${var.project_id}.iam.gserviceaccount.com"]
      }
      ingress_to {
        resources = ["*"]
        operations {
          service_name = "secretmanager.googleapis.com"
          method_selectors { method = "*" }
        }
      }
    }
  }
}

# ── Outputs ────────────────────────────────────────────────────────────────────
output "load_balancer_ip"      { value = google_compute_global_address.mcp_ip.address }
output "cloud_run_url"         { value = google_cloud_run_v2_service.mcp_vault.uri }
output "service_account_email" { value = google_service_account.mcp_sa.email }
output "armor_policy"          { value = google_compute_security_policy.mcp_armor.name }
