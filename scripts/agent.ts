/**
 * Start and manage coding-agent sessions on Cursor (cloud) and Grok Build (headless, on this machine or CI).
 *
 *   npm run agent -- tasks                                       # list named automations
 *   CURSOR_API_KEY=... npm run agent -- cursor launch refresh-data [--wait] [--ref main] [--model composer-2] [--plan]
 *   CURSOR_API_KEY=... npm run agent -- cursor launch "free-form prompt"
 *   CURSOR_API_KEY=... npm run agent -- cursor list | status <agentId> | follow-up <agentId> "prompt" | cancel <agentId>
 *   npm run agent -- grok run refresh-data [--model grok-build] [--session-id <uuid>] [--yolo]
 *   npm run agent -- grok resume <sessionId> "prompt"
 *
 * In CI, grok runs with --yolo and --rules telling it to leave commits to the workflow (.github/workflows/agents.yml).
 *
 * The first argument after `launch`/`run` is a task id from scripts/agents/tasks.ts, or any other text as the prompt.
 */
import { execFileSync } from 'node:child_process';
import { CursorClient, type CursorRun } from './agents/cursor';
import { runGrok } from './agents/grok';
import { TASKS, isTaskId } from './agents/tasks';

const argv = process.argv.slice(2);
const flag = (name: string) => argv.includes(name);
const opt = (name: string) => {
  const i = argv.indexOf(name);
  return i >= 0 ? argv[i + 1] : undefined;
};
const VALUE_FLAGS = new Set(['--ref', '--model', '--repo', '--session-id', '--max-turns', '--limit', '--rules']);
const positional = argv.filter((a, i) => !a.startsWith('--') && !VALUE_FLAGS.has(argv[i - 1] ?? ''));
const [platform, command, ...rest] = positional;

function resolvePrompt(input: string | undefined): { prompt: string; name?: string } {
  if (!input) throw new Error('Pass a task id (npm run agent -- tasks) or a prompt');
  return isTaskId(input) ? { prompt: TASKS[input].prompt, name: TASKS[input].title } : { prompt: input };
}

/** https://github.com/owner/repo for the current checkout, unless --repo or CURSOR_REPO says otherwise. */
function repoUrl(): string {
  const explicit = opt('--repo') ?? process.env.CURSOR_REPO;
  if (explicit) return explicit;
  const remote = execFileSync('git', ['remote', 'get-url', 'origin'], { encoding: 'utf8' }).trim();
  const m = remote.match(/github\.com[:/]([^/]+\/[^/]+?)(?:\.git)?$/);
  if (!m) throw new Error(`Cannot derive a GitHub URL from remote "${remote}"; pass --repo https://github.com/owner/repo`);
  return `https://github.com/${m[1]}`;
}

function printRun(r: CursorRun) {
  console.log(`run ${r.id}: ${r.status}${r.durationMs ? ` (${Math.round(r.durationMs / 1000)}s)` : ''}`);
  if (r.result) console.log(r.result);
  for (const b of r.git?.branches ?? []) console.log(`branch ${b.branch ?? '?'}${b.prUrl ? ` → ${b.prUrl}` : ''}`);
}

async function cursor() {
  const apiKey = process.env.CURSOR_API_KEY;
  if (!apiKey) throw new Error('Set CURSOR_API_KEY (Cursor Dashboard → API Keys)');
  const client = new CursorClient(apiKey);
  const latestRun = async (agentId: string) => {
    const a = await client.agent(agentId);
    if (!a.latestRunId) throw new Error(`Agent ${agentId} has no runs`);
    return { agent: a, runId: a.latestRunId };
  };

  switch (command) {
    case 'launch': {
      const { prompt, name } = resolvePrompt(rest.join(' ') || undefined);
      const { agent, run } = await client.launch({
        prompt,
        name,
        repoUrl: repoUrl(),
        ref: opt('--ref'),
        model: opt('--model'),
        mode: flag('--plan') ? 'plan' : 'agent',
        autoCreatePR: !flag('--no-pr'),
      });
      console.log(`agent ${agent.id} (${run.status})${agent.url ? `\n${agent.url}` : ''}`);
      if (process.env.GITHUB_OUTPUT) {
        const { appendFileSync } = await import('node:fs');
        appendFileSync(process.env.GITHUB_OUTPUT, `agent_id=${agent.id}\nagent_url=${agent.url ?? ''}\n`);
      }
      if (flag('--wait')) printRun(await client.wait(agent.id, run.id, { onStatus: (s) => console.log(`… ${s}`) }));
      return;
    }
    case 'list': {
      for (const a of (await client.list(Number(opt('--limit') ?? 20))).items) {
        console.log(`${a.id}  ${a.status.padEnd(8)}  ${a.createdAt?.slice(0, 16) ?? ''}  ${a.name ?? ''}`);
      }
      return;
    }
    case 'status': {
      const { agent, runId } = await latestRun(rest[0]!);
      console.log(`agent ${agent.id}: ${agent.status}${agent.url ? `  ${agent.url}` : ''}`);
      printRun(flag('--wait') ? await client.wait(agent.id, runId, { onStatus: (s) => console.log(`… ${s}`) }) : await client.run(agent.id, runId));
      return;
    }
    case 'follow-up': {
      const [agentId, ...words] = rest;
      const { prompt } = resolvePrompt(words.join(' ') || undefined);
      const run = await client.followUp(agentId!, prompt);
      console.log(`run ${run.id} (${run.status})`);
      if (flag('--wait')) printRun(await client.wait(agentId!, run.id, { onStatus: (s) => console.log(`… ${s}`) }));
      return;
    }
    case 'cancel': {
      const { agent, runId } = await latestRun(rest[0]!);
      await client.cancel(agent.id, runId);
      console.log(`cancelled run ${runId}`);
      return;
    }
    default:
      throw new Error('cursor commands: launch, list, status, follow-up, cancel');
  }
}

async function grok() {
  const common = { model: opt('--model'), maxTurns: opt('--max-turns') ? Number(opt('--max-turns')) : undefined, alwaysApprove: flag('--yolo'), rules: opt('--rules') };
  switch (command) {
    case 'run': {
      const { prompt } = resolvePrompt(rest.join(' ') || undefined);
      process.exitCode = await runGrok({ ...common, prompt, sessionId: opt('--session-id') });
      return;
    }
    case 'resume': {
      const [sessionId, ...words] = rest;
      const { prompt } = resolvePrompt(words.join(' ') || undefined);
      process.exitCode = await runGrok({ ...common, prompt, resume: sessionId });
      return;
    }
    default:
      throw new Error('grok commands: run, resume');
  }
}

if (platform === 'tasks') {
  for (const [id, t] of Object.entries(TASKS)) console.log(`${id.padEnd(22)} ${t.title}`);
} else if (platform === 'cursor') {
  await cursor();
} else if (platform === 'grok') {
  await grok();
} else {
  throw new Error('usage: npm run agent -- <tasks|cursor|grok> ...  (see scripts/agent.ts)');
}
