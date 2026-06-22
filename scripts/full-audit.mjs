#!/usr/bin/env node
//
// Deep, whole-repo security audit (one Opus pass, or chunked for big repos).
//
// Usage:
//   CLAUDE_API_KEY=sk-ant-... node scripts/full-audit.mjs
//   AUDIT_DRY_RUN=1 node scripts/full-audit.mjs     # coverage + cost only, no API call
//
// Env:
//   CLAUDE_API_KEY / ANTHROPIC_API_KEY  (required unless dry-run)
//   AUDIT_MODEL   (default claude-opus-4-8)
//
// Output (written to CWD):
//   audit-coverage.json  — exactly which files were/weren't sent, with token counts
//   audit-report.md      — findings (secrets redacted)
//   audit-findings.json  — machine-readable findings
//
// Exit: 1 if any CRITICAL/HIGH finding (so it can gate a private-repo release PR),
//       2 on operational error, 0 otherwise.
//
// IMPORTANT: never run this in PUBLIC-repo CI — its output would be public. Run
// it locally for public repos, or in private-repo CI only (see audit.yml).
//
import { readFileSync, readdirSync, lstatSync, existsSync, writeFileSync } from 'node:fs';
import { join, extname, relative, basename } from 'node:path';

const root = process.cwd();
const MODEL = process.env.AUDIT_MODEL || 'claude-opus-4-8';
const DRY = !!process.env.AUDIT_DRY_RUN;
const KEY = process.env.CLAUDE_API_KEY || process.env.ANTHROPIC_API_KEY || '';

// ---- Central, non-PR-controllable inventory ---------------------------------
// Deliberately includes the supply-chain surface (workflows, manifests,
// Dockerfiles, scripts), not just app source. A repo cannot narrow this.
const INCLUDE_EXT = new Set([
	'.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs', '.json',
	'.yml', '.yaml', '.sh', '.bash', '.env.example', '.sql', '.prisma',
]);
const INCLUDE_NAME = new Set(['Dockerfile', 'Procfile', '.npmrc', 'CODEOWNERS']);
const SKIP_DIR = new Set([
	'node_modules', '.git', 'build', 'dist', '.next', 'coverage', 'out',
	'.ci-security', 'vendor', '.cache', '.turbo', '.vercel',
]);
const SKIP_FILE = (name) =>
	/(^|\.)lock(\.json|file)?$|-lock\.(json|yaml)$|^package-lock\.json$|^yarn\.lock$|^pnpm-lock\.yaml$|\.min\.(js|css)$|\.map$/.test(name);
const MAX_FILE_BYTES = 200_000; // skip giant/generated files (recorded as omitted)
const CHUNK_TOKEN_BUDGET = 180_000; // chunk if the repo exceeds this (approx tokens)
const approxTokens = (s) => Math.ceil(s.length / 3.5);

function walk(dir, acc) {
	for (const name of readdirSync(dir)) {
		if (SKIP_DIR.has(name)) continue;
		const p = join(dir, name);
		let st;
		try { st = lstatSync(p); } catch { continue; }
		if (st.isSymbolicLink()) continue;
		if (st.isDirectory()) walk(p, acc);
		else if (st.isFile()) acc.push({ p, size: st.size, name });
	}
	return acc;
}

const wanted = (f) =>
	!SKIP_FILE(f.name) &&
	(INCLUDE_EXT.has(extname(f.name)) || INCLUDE_NAME.has(f.name) || f.name.startsWith('Dockerfile'));

const all = walk(root, []);
const included = [], omitted = [];
for (const f of all) {
	if (!wanted(f)) continue;
	if (f.size > MAX_FILE_BYTES) { omitted.push({ file: relative(root, f.p), reason: `>${MAX_FILE_BYTES}B` }); continue; }
	const text = readFileSync(f.p, 'utf8');
	included.push({ file: relative(root, f.p), tokens: approxTokens(text), text });
}

// ---- Chunk (never silently truncate) ----------------------------------------
const chunks = [[]];
let acc = 0;
for (const f of included) {
	if (acc + f.tokens > CHUNK_TOKEN_BUDGET && chunks[chunks.length - 1].length) {
		chunks.push([]); acc = 0;
	}
	chunks[chunks.length - 1].push(f); acc += f.tokens;
}
const totalTokens = included.reduce((n, f) => n + f.tokens, 0);

const coverage = {
	root: basename(root),
	files_included: included.length,
	files_omitted: omitted.length,
	approx_input_tokens: totalTokens,
	chunks: chunks.length,
	included: included.map((f) => ({ file: f.file, tokens: f.tokens })),
	omitted,
};
writeFileSync('audit-coverage.json', JSON.stringify(coverage, null, 2));

const estCost = (totalTokens / 1e6) * 5 + (chunks.length * 12000 / 1e6) * 25; // rough
console.log(`Coverage: ${included.length} files, ~${totalTokens} input tokens, ${chunks.length} chunk(s), ${omitted.length} omitted.`);
console.log(`Estimated Opus cost: ~$${estCost.toFixed(2)} (rough).`);

if (DRY) {
	console.log('Dry run — wrote audit-coverage.json, skipped the API call.');
	process.exit(0);
}
if (!KEY) { console.error('No CLAUDE_API_KEY/ANTHROPIC_API_KEY set.'); process.exit(2); }

// ---- Audit prompt + structured output schema --------------------------------
const SYSTEM =
	'You are a security auditor reviewing a code repository. Find real, exploitable security issues: ' +
	'injection, auth/permission bypass, secret exposure, SSRF, unsafe deserialization, supply-chain/CI risks ' +
	'(workflows, dependencies), and trust-boundary errors. Prefer precision over volume. ' +
	'Do NOT quote full secrets/keys in your output — refer to them by file and a short redacted prefix.';

const SCHEMA = {
	type: 'object',
	additionalProperties: false,
	required: ['summary', 'findings'],
	properties: {
		summary: { type: 'string' },
		findings: {
			type: 'array',
			items: {
				type: 'object',
				additionalProperties: false,
				required: ['severity', 'title', 'file', 'issue', 'impact', 'fix'],
				properties: {
					severity: { type: 'string', enum: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] },
					title: { type: 'string' },
					file: { type: 'string' },
					issue: { type: 'string' },
					impact: { type: 'string' },
					fix: { type: 'string' },
				},
			},
		},
	},
};

async function auditChunk(chunk, idx, n) {
	const body = chunk.map((f) => `### ${f.file}\n\`\`\`\n${f.text}\n\`\`\``).join('\n\n');
	const user =
		(n > 1 ? `This is chunk ${idx + 1}/${n} of the repository. Audit only what is shown.\n\n` : '') +
		`Repository files:\n\n${body}`;
	const res = await fetch('https://api.anthropic.com/v1/messages', {
		method: 'POST',
		headers: { 'content-type': 'application/json', 'x-api-key': KEY, 'anthropic-version': '2023-06-01' },
		body: JSON.stringify({
			model: MODEL,
			max_tokens: 16000,
			thinking: { type: 'adaptive' },
			output_config: { effort: 'high', format: { type: 'json_schema', schema: SCHEMA } },
			system: SYSTEM,
			messages: [{ role: 'user', content: user }],
		}),
	});
	if (!res.ok) throw new Error(`API ${res.status}: ${(await res.text()).slice(0, 400)}`);
	const data = await res.json();
	if (data.stop_reason === 'refusal') throw new Error('Model refused the audit request.');
	const textBlock = (data.content || []).find((b) => b.type === 'text');
	if (!textBlock) throw new Error('No text block in response.');
	return JSON.parse(textBlock.text);
}

let summary = [], findings = [];
try {
	for (let i = 0; i < chunks.length; i++) {
		const r = await auditChunk(chunks[i], i, chunks.length);
		if (r.summary) summary.push(r.summary);
		if (Array.isArray(r.findings)) findings.push(...r.findings);
	}
} catch (e) {
	console.error('Audit failed:', e.message);
	process.exit(2);
}

// ---- Redact anything secret-shaped before writing the report ----------------
const redact = (s) =>
	s
		.replace(/sk-ant-[A-Za-z0-9_-]{12,}/g, 'sk-ant-[REDACTED]')
		.replace(/AKIA[0-9A-Z]{16}/g, 'AKIA[REDACTED]')
		.replace(/gh[posru]_[A-Za-z0-9]{20,}/g, 'gh_[REDACTED]')
		.replace(/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, '[REDACTED PRIVATE KEY]');

const order = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
findings.sort((a, b) => (order[a.severity] ?? 9) - (order[b.severity] ?? 9));
const counts = findings.reduce((m, f) => ((m[f.severity] = (m[f.severity] || 0) + 1), m), {});

let md = `# Security audit — ${coverage.root}\n\n`;
md += `Scanned ${coverage.files_included} files (~${coverage.approx_input_tokens} tokens, ${coverage.chunks} chunk(s)). `;
md += `Omitted: ${coverage.files_omitted}. Model: ${MODEL}.\n\n`;
md += `**Findings:** ` + (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((s) => `${counts[s] || 0} ${s}`).join(', ')) + `\n\n`;
md += summary.map((s) => s.trim()).join('\n\n') + '\n\n';
for (const f of findings) {
	md += `## [${f.severity}] ${f.title}\n- **File:** ${f.file}\n- **Issue:** ${f.issue}\n- **Impact:** ${f.impact}\n- **Fix:** ${f.fix}\n\n`;
}
if (coverage.files_omitted) {
	md += `## Coverage gaps\nThese files were not audited (size/binary): ` +
		coverage.omitted.map((o) => `\`${o.file}\``).join(', ') + `.\n`;
}

writeFileSync('audit-report.md', redact(md));
writeFileSync('audit-findings.json', JSON.stringify({ counts, findings }, null, 2));

const blocking = (counts.CRITICAL || 0) + (counts.HIGH || 0);
console.log(`Audit complete: ${['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((s) => `${counts[s] || 0} ${s}`).join(', ')}.`);
console.log('Wrote audit-report.md, audit-findings.json, audit-coverage.json.');
process.exit(blocking ? 1 : 0);
