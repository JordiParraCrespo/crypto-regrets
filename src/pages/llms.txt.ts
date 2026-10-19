import type { APIRoute } from 'astro';
import { href } from '../lib/paths';
import { incidents, fmtUsd, sum } from '../lib/data';
import { CLASS_IDS } from '../lib/classes';

/** A Markdown map of the site for LLM agents and tool builders (llmstxt.org). */
export const GET: APIRoute = ({ site }) => {
  const url = (p: string) => new URL(href(p), site).toString();
  const body = `# Crypto Regrets

> A classified index of ${incidents.length.toLocaleString('en')} crypto security incidents (${fmtUsd(sum(incidents))} lost, 2010 to today), each traced to a failure pattern and, where the evidence allows, one of ${CLASS_IDS.length} vulnerability classes with vulnerable and fixed code.

## Data
- [All incidents (JSON)](${url('/api/incidents.json')}): every incident with pattern, class, sources, tx hashes and PoC links
- [All incidents (CSV)](${url('/data/incidents.csv')}): the main fields, one row per incident
- [Vulnerability classes (JSON)](${url('/api/vulnerability-classes.json')}): class definitions, CWE/SWC ids, fixes and labelled incidents
- [Taxonomy (JSON)](${url('/api/taxonomy.json')}): layers, patterns and classes
- [Client and SDK advisories (JSON)](${url('/api/advisories.json')})
- [Cosmos scanner rules (JSON)](${url('/api/cosmos-scanner-rules.json')})

## Pages
- [Incident index](${url('/hacks')}): searchable list of every incident
- [Vulnerability classes](${url('/classes')}): what keeps going wrong and how to fix it
- [Secure-coding checklist](${url('/developers')})
- [Trends](${url('/trends')}): losses per year, chain and vulnerability
- [Method and sources](${url('/sources')}): how the data is merged and classified
`;
  return new Response(body, { headers: { 'Content-Type': 'text/markdown; charset=utf-8' } });
};
