variable "project_id"     { type = string; description = "ID del proyecto GCP" }
variable "project_number" { type = string; description = "Número del proyecto GCP (para VPC SC)" }
variable "region"         { type = string; default = "us-central1" }
variable "env"            { type = string; default = "prod" }
variable "min_instances"  { type = number; default = 0 }
variable "max_instances"  { type = number; default = 10 }

variable "domains" {
  type        = list(string)
  description = "Dominios para el certificado SSL administrado. Ej: [\"mcp.tudominio.com\"]"
}

variable "allowed_origins" {
  type        = list(string)
  default     = []
  description = "Orígenes CORS permitidos"
}

variable "allowed_countries" {
  type        = list(string)
  default     = []
  description = "Países permitidos para geo-blocking (vacío = sin restricción). Ej: [\"MX\",\"US\"]"
}

variable "enable_vpc_sc" {
  type        = bool
  default     = false
  description = "Activar VPC Service Controls"
}

variable "access_policy_id" {
  type        = string
  default     = ""
  description = "ID de la Access Policy de GCP (requerido si enable_vpc_sc=true)"
}
