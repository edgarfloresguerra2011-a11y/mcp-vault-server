import type { AuditService } from "./AuditService.js";

interface RotationEvent {
    secretId: string;
    newVersion: string;
    projectId: string;
    rotatedAt: string;
    rotatedBy: string;
}

export class PubSubService {
    private publisher: any = null;
    constructor(topic: string | null, private projectId: string, private audit: AuditService) {
        if (topic) this._init(topic);
    }

    private _init(topicName: string): void {
        // @ts-ignore — dynamic import, types optional
        import("@google-cloud/pubsub").then(({ PubSub }: any) => {
            this.publisher = new PubSub({ projectId: this.projectId }).topic(topicName);
            process.stderr.write(`✅ Pub/Sub: listo (${topicName})\n`);
        }).catch(() => process.stderr.write("⚠️  Pub/Sub: SDK no disponible\n"));
    }

    async notifyRotation(event: RotationEvent): Promise<void> {
        if (!this.publisher) return;
        try {
            await this.publisher.publishMessage({ data: Buffer.from(JSON.stringify(event)) });
            this.audit.log({ action: "notify_rotation", secretId: event.secretId, clientId: event.rotatedBy, success: true });
        } catch (err) {
            const errMsg = String(err);
            process.stderr.write(`⚠️  Pub/Sub falla: ${errMsg}\n`);
            this.audit.logError("notify_rotation", event.secretId, event.rotatedBy, "PUBSUB_ERROR", errMsg);
        }
    }
}
