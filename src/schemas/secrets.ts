// ── Schemas v4 (Fortaleza) ────────────────────────────────────────────────────
import { z } from "zod";
import { MAX_PAGE_SIZE, DEFAULT_PAGE_SIZE } from "../constants.js";

const SecretIdSchema = z
    .string().min(1).max(255)
    .regex(/^[a-zA-Z0-9_-]+$/, "Solo letras, números, - y _")
    .describe("Nombre del secreto, ej: openai-api-key");

const VersionSchema = z.string()
    .regex(/^(latest|[0-9]+)$/, "Versión inválida (solo 'latest' o números)")
    .optional().default("latest")
    .describe('Versión del secreto. "latest" o número como "3"');

const DisableVersionNumberSchema = z.string()
    .regex(/^[0-9]+$/, "Debe ser un número de versión")
    .describe('Número de versión, ej: "2"');

const ReasonSchema = z
    .string().min(10, "El motivo debe tener al menos 10 caracteres")
    .max(500).describe("Motivo de acceso, ej: 'Procesar pago de factura #1234'");

const TicketIdSchema = z.string().optional()
    .describe("ID de ticket/tarea opcional, ej: JIRA-456");

// FIX M-5: Labels con validación estricta según límites reales de GCP
// GCP: max 64 labels, keys ≤ 63 chars (lowercase), values ≤ 63 chars
const GcpLabelKeySchema = z.string()
    .min(1).max(63)
    .regex(/^[a-z][a-z0-9_-]*$/, "Label key: solo minúsculas, números, _ y - (empieza con letra)");

const GcpLabelValueSchema = z.string()
    .max(63)
    .regex(/^[a-z0-9_-]*$/, "Label value: solo minúsculas, números, _ y -");

const LabelsSchema = z.record(GcpLabelKeySchema, GcpLabelValueSchema)
    .max(64, "Máximo 64 labels permitidos por GCP")
    .optional()
    .default({});

export const GetSecretSchema = z.object({
    secretId: SecretIdSchema,
    version: VersionSchema,
    reason: ReasonSchema,
    ticketId: TicketIdSchema,
}).strict();

export const GetMetadataSchema = z.object({ secretId: SecretIdSchema }).strict();
export const ListVersionsSchema = z.object({ secretId: SecretIdSchema }).strict();
export const PermissionCheckSchema = z.object({ secretId: SecretIdSchema }).strict();

export const ListSecretsSchema = z.object({
    pageSize: z.number().int().min(1).max(MAX_PAGE_SIZE).default(DEFAULT_PAGE_SIZE),
    pageToken: z.string().optional().default(""),
}).strict();

export const CreateSecretSchema = z.object({
    secretId: SecretIdSchema,
    labels: LabelsSchema,
}).strict();

export const AddVersionSchema = z.object({
    secretId: SecretIdSchema,
    value: z.string().min(1),
}).strict();

export const DisableVersionSchema = z.object({
    secretId: SecretIdSchema,
    version: DisableVersionNumberSchema,
}).strict();

export const SynthesizeEnvSchema = z.object({
    secretIds: z.array(SecretIdSchema).min(1).max(50)
        .describe("Lista de secretos a incluir en el .env"),
    reason: ReasonSchema,
}).strict();

export type GetSecretInput = z.infer<typeof GetSecretSchema>;
export type GetMetadataInput = z.infer<typeof GetMetadataSchema>;
export type ListSecretsInput = z.infer<typeof ListSecretsSchema>;
export type ListVersionsInput = z.infer<typeof ListVersionsSchema>;
export type CreateSecretInput = z.infer<typeof CreateSecretSchema>;
export type AddVersionInput = z.infer<typeof AddVersionSchema>;
export type DisableVersionInput = z.infer<typeof DisableVersionSchema>;
export type SynthesizeEnvInput = z.infer<typeof SynthesizeEnvSchema>;
export type PermissionCheckInput = z.infer<typeof PermissionCheckSchema>;
