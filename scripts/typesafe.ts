/**
 * Minimal, typed client for TypeSafe's System One API (https://docs.typesafe.ai/api).
 * Responses are validated with zod, and Choice answers are typed to the option keys you pass in.
 */
import { z } from 'zod';

const ENDPOINT = 'https://api.typesafe.ai/v1/systemone';

export interface ChoiceQuestion<K extends string> {
  type: 'choice';
  instructions: string | Record<string, unknown>;
  criteria: Record<K, string | Record<string, unknown> | null>;
}
export interface NoulQuestion {
  type: 'noul';
  instructions: string | Record<string, unknown>;
}
type Question = ChoiceQuestion<string> | NoulQuestion;

export type Answer<Q> = Q extends ChoiceQuestion<infer K>
  ? { type: 'choice'; choice: K; confidence: number; probabilities: Record<K, number> }
  : Q extends NoulQuestion
    ? { type: 'noul'; noul: number }
    : never;

const choiceAnswer = z.object({ type: z.literal('choice'), choice: z.string(), confidence: z.number(), probabilities: z.record(z.number()) });
const noulAnswer = z.object({ type: z.literal('noul'), noul: z.number() });
const responseSchema = z.object({
  model: z.string(),
  answers: z.record(z.union([choiceAnswer, noulAnswer])),
  usage: z.object({ input_tokens: z.number(), output_tokens: z.number() }).optional(),
});

export class TypeSafeError extends Error {
  constructor(
    readonly status: number,
    body: string,
  ) {
    super(`TypeSafe ${status}: ${body.slice(0, 300)}`);
  }
}

export async function systemOne<Qs extends Record<string, Question>>(opts: {
  apiKey: string;
  model?: string;
  state: unknown;
  questions: Qs;
  retries?: number;
}): Promise<{ model: string; answers: { [K in keyof Qs]: Answer<Qs[K]> }; usage?: { input_tokens: number; output_tokens: number } }> {
  const { apiKey, model = 'jev-latest', state, questions, retries = 5 } = opts;
  for (let attempt = 0; ; attempt++) {
    const res = await fetch(ENDPOINT, {
      method: 'POST',
      headers: { Authorization: `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ model, state, questions }),
    });
    if (res.ok) {
      const parsed = responseSchema.parse(await res.json());
      for (const [id, q] of Object.entries(questions)) {
        const a = parsed.answers[id];
        if (!a || a.type !== q.type) throw new Error(`TypeSafe: missing or mistyped answer for "${id}"`);
        if (a.type === 'choice' && !(a.choice in (q as ChoiceQuestion<string>).criteria)) {
          throw new Error(`TypeSafe: "${id}" returned unknown option "${a.choice}"`);
        }
      }
      return parsed as never;
    }
    const retryable = res.status === 429 || res.status === 529 || res.status >= 500;
    if (!retryable || attempt >= retries) throw new TypeSafeError(res.status, await res.text());
    await new Promise((r) => setTimeout(r, 1000 * 2 ** attempt + Math.random() * 500));
  }
}
