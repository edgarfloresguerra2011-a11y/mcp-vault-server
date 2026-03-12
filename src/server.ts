import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { AsyncLocalStorage } from "async_hooks";
import { SecretManagerService } from "./services/SecretManagerService.js";
import { AuditService } from "./services/AuditService.js";
import { PubSubService } from "./services/PubSubService.js";
import { registerReadTools } from "./tools/readTools.js";
import { registerWriteTools } from "./tools/writeTools.js";
import { registerContextTools } from "./tools/contextTools.js";
import { SERVER_NAME, SERVER_VERSION } from "./constants.js";
import type { ServerConfig } from "./types.js";

export const requestContext = new AsyncLocalStorage<{ clientId: string }>();

export interface McpVaultServices {
    audit: AuditService;
    pubsub: PubSubService;
    svc: SecretManagerService;
}

export function createServices(config: ServerConfig): McpVaultServices {
    const audit = new AuditService(config.projectId);
    const pubsub = new PubSubService(config.pubSubTopic, config.projectId, audit);
    const svc = new SecretManagerService(config.projectId, audit, pubsub);
    return { audit, pubsub, svc };
}

export function createMcpServer(services: McpVaultServices): McpServer {
    const server = new McpServer({ name: SERVER_NAME, version: SERVER_VERSION });
    const clientId = () => requestContext.getStore()?.clientId ?? "unknown";

    registerReadTools(server, services.svc, clientId);
    registerWriteTools(server, services.svc, clientId);
    registerContextTools(server, services.svc, clientId);

    return server;
}
