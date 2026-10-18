import type { CategoryId } from '../src/lib/taxonomy';

/** Keyword classifier for free-text root-cause titles (DeFiHackLabs, REKT). Order matters. */
const KEYWORD_RULES: [RegExp, CategoryId][] = [
  [/reentr|re-entr|erc777|callback re-?enter/i, 'reentrancy'],
  [/oracle|price manipulation|spot price|twap|price feed|manipulat\w* (the )?(price|reserve|rate|nav)|reserve manipulation|self-trade|nav inflation|getprice|pricing/i, 'oracle-manipulation'],
  [/signature|ecrecover|replay|permit\b|weak (private )?key|profanity|vanity/i, 'signature-crypto'],
  [/private key|key (leak|compromis)|hot wallet|multisig (compromis|signer)|stolen key|compromised (wallet|key|account)/i, 'key-compromise'],
  [/phishing|social engineering|malware|impersonat|lazarus/i, 'social-engineering'],
  [/\bdns\b|frontend|front-end|supply chain|\bnpm\b|\bcdn\b/i, 'frontend-infra'],
  [/bridge|cross-chain|crosschain|merkle|proof/i, 'bridge-crosschain'],
  [/governance|proposal|voting/i, 'governance'],
  [/\brug|backdoor|exit scam|insider/i, 'rugpull'],
  [/arbitrary (external )?call|arbitrary.*calldata|approv|transferfrom|allowance|unverified (user )?input.*call|multicall/i, 'arbitrary-call'],
  [/access control|unprotected|permissionless|lack of (permission|auth)|missing (auth|modifier|access|caller|owner|permission)|caller check|onlyowner|initiali[sz]|uninitiali|ungated|no (access|auth)|anyone can|authori[sz]ation bypass|unauthori[sz]ed|unguarded|unrestricted|public (mint|burn|function)/i, 'access-control'],
  [/overflow|underflow|rounding|precision|share (price|accounting|calculation)|inflation|donat|divceil|division|arithmetic|decimal|infinite mint|fee-on-transfer|deflationary|skim|\bsync\b|truncat|accounting|erc-?404|balance (check|update)/i, 'accounting-math'],
  [/input validation|unchecked|insufficient validation|fake (token|pool|market|contract)|lack of validation|missing (check|validation)|not (check|validat)|unverified|arbitrary (token|pool|address)|user-supplied/i, 'input-validation'],
  [/logic|flaw|incorrect|calculation|reward|business|liquidat|withdraw|deposit|claim|swap|mint|burn|stak|duplicate|double|presale|arbitrage|funding|fee|bypass|misclassif|update|redemption|redeem|borrow|lock/i, 'logic-error'],
];

export function classifyText(text: string): CategoryId {
  for (const [re, cat] of KEYWORD_RULES) if (re.test(text)) return cat;
  return 'unknown';
}
