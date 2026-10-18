/**
 * Minimal, typed client for Cursor's Cloud Agents API v1 (https://cursor.com/docs/cloud-agent/api/endpoints).
 * An agent is a durable session on a repo; each prompt (the first one and every follow-up) is a run.
 * Responses are validated with zod; unknown fields are kept so API additions don't break us.
 */
import { z } from 'zod';

const BASE = 'https://api.cursor.com/v1';

const agentSchema = z
  .object({
    id: z.string(),
    name: z.string().optional(),
    status: z.string(),
    url: z.string().optional(),
    latestRunId: z.string().optional(),
    createdAt: z.string().optional(),
  })
  .passthrough();
const runSchema = z
  .object({
    id: z.string(),
    agentId: z.string(),
    status: z.string(),
    durationMs: z.number().optional(),
    result: z.string().optional(),
    git: z
      .object({ branches: z.array(z.object({ repoUrl: z.string().optional(), branch: z.string().optional(), prUrl: z.string().optional() }).passthrough()) })
      .partial()
      .optional(),
  })
  .passthrough();
export type CursorAgent = z.infer<typeof agentSchema>;
export type CursorRun = z.infer<typeof runSchema>;

/** Run states after which nothing changes. */
export const TERMINAL_RUN = new Set(['FINISHED', 'ERROR', 'CANCELLED', 'EXPIRED']);

export interface LaunchOptions {
  prompt: string;
  repoUrl: string;
  ref?: string;
  model?: string;
  name?: string;
  autoCreatePR?: boolean;
  mode?: 'agent' | 'plan';
}

export class CursorError extends Error {
  constructor(
    readonly status: number,
    body: string,
  ) {
    super(`Cursor ${status}: ${body.slice(0, 300)}`);
  }
}

export class CursorClient {
  constructor(private readonly apiKey: string) {}

  private async call<T>(schema: z.ZodType<T>, method: string, path: string, body?: unknown, retries = 3): Promise<T> {
    for (let attempt = 0; ; attempt++) {
      const res = await fetch(BASE + path, {
        method,
        headers: { Authorization: `Bearer ${this.apiKey}`, ...(body ? { 'Content-Type': 'application/json' } : {}) },
        body: body ? JSON.stringify(body) : undefined,
      });
      if (res.ok) return schema.parse(await res.json());
      const retryable = res.status === 429 || res.status >= 500;
      if (!retryable || attempt >= retries) throw new CursorError(res.status, await res.text());
      await new Promise((r) => setTimeout(r, 1000 * 2 ** attempt + Math.random() * 500));
    }
  }

  launch(o: LaunchOptions) {
    return this.call(z.object({ agent: agentSchema, run: runSchema }), 'POST', '/agents', {
      prompt: { text: o.prompt },
      repos: [{ url: o.repoUrl, ...(o.ref ? { startingRef: o.ref } : {}) }],
      ...(o.model ? { model: { id: o.model } } : {}),
      ...(o.name ? { name: o.name.slice(0, 100) } : {}),
      autoCreatePR: o.autoCreatePR ?? true,
      mode: o.mode ?? 'agent',
    });
  }

  async followUp(agentId: string, prompt: string) {
    return (await this.call(z.object({ run: runSchema }), 'POST', `/agents/${agentId}/runs`, { prompt: { text: prompt } })).run;
  }

  agent(agentId: string) {
    return this.call(agentSchema, 'GET', `/agents/${agentId}`);
  }

  run(agentId: string, runId: string) {
    return this.call(runSchema, 'GET', `/agents/${agentId}/runs/${runId}`);
  }

  list(limit = 20) {
    return this.call(z.object({ items: z.array(agentSchema), nextCursor: z.string().optional() }), 'GET', `/agents?limit=${limit}`);
  }

  cancel(agentId: string, runId: string) {
    return this.call(z.object({ id: z.string() }), 'POST', `/agents/${agentId}/runs/${runId}/cancel`);
  }

  /** Polls a run until it reaches a terminal state. */
  async wait(agentId: string, runId: string, opts: { intervalMs?: number; onStatus?: (s: string) => void } = {}) {
    let last = '';
    for (;;) {
      const r = await this.run(agentId, runId);
      if (r.status !== last) opts.onStatus?.((last = r.status));
      if (TERMINAL_RUN.has(r.status)) return r;
      await new Promise((res) => setTimeout(res, opts.intervalMs ?? 15_000));
    }
  }
}
