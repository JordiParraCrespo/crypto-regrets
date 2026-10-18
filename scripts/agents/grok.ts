/**
 * Runs xAI's Grok Build agent (https://docs.x.ai/build/overview) headless in the current checkout.
 * Grok Build has no hosted "start a session" API (Grok Bot is a separate product), so the cloud side is
 * whatever machine runs this: your laptop, a devbox, or the GitHub Actions runner in .github/workflows/agents.yml.
 *
 * Install: curl -fsSL https://x.ai/cli/install.sh | bash   Auth: `grok login` or XAI_API_KEY.
 */
import { spawn } from 'node:child_process';

export interface GrokRunOptions {
  prompt: string;
  model?: string;
  /** Named session, so the run can be resumed later with --resume. */
  sessionId?: string;
  resume?: string;
  maxTurns?: number;
  /** Auto-approve every tool call. Only for throwaway environments such as CI runners. */
  alwaysApprove?: boolean;
  /** Extra rules appended to the system prompt. */
  rules?: string;
  cwd?: string;
}

export function grokArgs(o: GrokRunOptions): string[] {
  return [
    '--no-auto-update',
    '--output-format',
    'plain',
    ...(o.model ? ['--model', o.model] : []),
    ...(o.sessionId ? ['--session-id', o.sessionId] : []),
    ...(o.resume ? ['--resume', o.resume] : []),
    ...(o.maxTurns ? ['--max-turns', String(o.maxTurns)] : []),
    ...(o.alwaysApprove ? ['--always-approve'] : []),
    ...(o.rules ? ['--rules', o.rules] : []),
    '-p',
    o.prompt,
  ];
}

/** Streams Grok's output to stdout and resolves with the exit code. */
export function runGrok(o: GrokRunOptions): Promise<number> {
  return new Promise((resolve, reject) => {
    const child = spawn('grok', grokArgs(o), { cwd: o.cwd, stdio: ['ignore', 'inherit', 'inherit'] });
    child.on('error', (e: NodeJS.ErrnoException) =>
      reject(e.code === 'ENOENT' ? new Error('grok CLI not found. Install it: curl -fsSL https://x.ai/cli/install.sh | bash') : e),
    );
    child.on('exit', (code) => resolve(code ?? 1));
  });
}
