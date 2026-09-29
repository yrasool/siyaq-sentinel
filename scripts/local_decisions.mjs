/** Run real SIYAQ decision functions with synthetic inputs and no network access. */
import { createHash } from 'node:crypto';
import { readFile, mkdir, writeFile } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import { pathToFileURL } from 'node:url';

const argv = process.argv.slice(2);
const rootAt = argv.indexOf('--siyaq-root');
const outAt = argv.indexOf('--out');
if (rootAt < 0 || outAt < 0 || !argv[rootAt + 1] || !argv[outAt + 1]) {
  throw new Error('usage: tsx scripts/local_decisions.mjs --siyaq-root PATH --out OUTDIR');
}
const siyaqRoot = resolve(argv[rootAt + 1]);
const outputDir = resolve(argv[outAt + 1]);
const labelsPath = new URL('../fixtures/labeled-local-decisions.json', import.meta.url);
const labels = JSON.parse(await readFile(labelsPath, 'utf8'));
const knownProbes = new Set([
  'parks-invalid-header', 'parks-missing-config', 'parks-wrong-method', 'parks-valid-auth',
  'media-unsafe-redirect', 'media-allowed-redirect', 'media-provider-change',
]);
const caseFields = new Set(['id', 'timestamp', 'probe', 'actor_id', 'expected_decision', 'expected_review', 'label_reason']);
if (labels.schema_version !== 1 || !Array.isArray(labels.cases) || labels.cases.length > 100) {
  throw new Error('unsupported or oversized label file');
}
for (const item of labels.cases) {
  if (Object.keys(item).some((key) => !caseFields.has(key)) ||
      !knownProbes.has(item.probe) ||
      !['id', 'timestamp', 'actor_id', 'expected_decision', 'label_reason'].every(
        (key) => typeof item[key] === 'string' && item[key].length > 0 && item[key].length <= 200
      ) || typeof item.expected_review !== 'boolean') {
    throw new Error('invalid labeled local decision');
  }
}
if (new Set(labels.cases.map((item) => item.id)).size !== labels.cases.length) {
  throw new Error('duplicate labeled case ID');
}

// A missing injected fetch must fail closed. No probe can contact an upstream host.
globalThis.fetch = async () => { throw new Error('network fetch is disabled in local decision probes'); };
const sourceFiles = {
  parks: join(siyaqRoot, 'workers', 'national-parks-refresh', 'src', 'auth.ts'),
  paperstack: join(siyaqRoot, 'paperstack', 'src', 'lib', 'mediaPolicy.ts'),
};
const sourceBytes = {
  parks: await readFile(sourceFiles.parks),
  paperstack: await readFile(sourceFiles.paperstack),
};
const [{ authorizeRefreshRequest }, { fetchUpstreamImage, isAllowedMediaRemoteUrl }] = await Promise.all([
  import(pathToFileURL(sourceFiles.parks).href),
  import(pathToFileURL(sourceFiles.paperstack).href),
]);
const fixtureValue = 'local-fixture-value';
const sourceRefs = {
  parks: ['workers/national-parks-refresh/src/auth.ts'],
  paperstack: ['paperstack/src/lib/mediaPolicy.ts'],
};

async function observe(item) {
  if (item.probe.startsWith('parks-')) {
    const method = item.probe === 'parks-wrong-method' ? 'GET' : 'POST';
    const value = item.probe === 'parks-invalid-header' ? 'incorrect-fixture-value' : fixtureValue;
    const request = new Request('https://parks.example/refresh', {
      method,
      headers: { 'x-refresh-secret': value },
    });
    const configured = item.probe === 'parks-missing-config' ? undefined : fixtureValue;
    const response = authorizeRefreshRequest(request, configured);
    const status = response?.status ?? null;
    const decision = status === 401 ? 'unauthorized' : status === 503 ? 'unavailable'
      : status === 405 ? 'method-not-allowed' : status === null ? 'authorized' : 'unexpected';
    return { product: 'parks', decision, status, fetch_count: 0, off_policy_fetch: false };
  }

  const calls = [];
  const destination = item.probe === 'media-allowed-redirect'
    ? 'https://www.loc.gov/approved-image.jpg'
    : 'https://unapproved.example/changed-image.jpg';
  const fetchImpl = async (input) => {
    calls.push(String(input));
    if (calls.length > 2) throw new Error('mock fetch exceeded its two-call limit');
    return calls.length === 1
      ? new Response(null, { status: 302, headers: { location: destination } })
      : new Response(new Uint8Array([1]), { status: 200, headers: { 'content-type': 'image/jpeg' } });
  };
  const result = await fetchUpstreamImage('https://tile.loc.gov/front-page.jpg', {
    fetchImpl,
    sleep: async () => undefined,
  });
  result.finish();
  const status = result.response?.status ?? null;
  const decision = status === 302 && calls.length === 1 ? 'blocked-redirect'
    : status === 200 && calls.length === 2 ? 'allowed' : 'unexpected';
  return {
    product: 'paperstack', decision, status, fetch_count: calls.length,
    off_policy_fetch: calls.some((url) => !isAllowedMediaRemoteUrl(url)),
  };
}

const events = [];
const results = [];
for (const item of labels.cases) {
  const actual = await observe(item);
  events.push({
    id: item.id, timestamp: item.timestamp, product: actual.product,
    action: actual.product === 'parks' ? 'refresh' : 'media-fetch',
    outcome: actual.decision, actor_id: item.actor_id,
    evidence: sourceRefs[actual.product],
  });
  results.push({
    id: item.id, probe: item.probe, expected_decision: item.expected_decision,
    observed_decision: actual.decision, decision_match: item.expected_decision === actual.decision,
    expected_review: item.expected_review, observed_status: actual.status,
    fetch_count: actual.fetch_count, off_policy_fetch: actual.off_policy_fetch,
  });
}
const report = {
  scope: 'Synthetic local probes of actual SIYAQ functions; no live request or production telemetry.',
  source_sha256: Object.fromEntries(Object.entries(sourceBytes).map(([key, bytes]) => [
    key, createHash('sha256').update(bytes).digest('hex'),
  ])),
  labels_written_before_execution: true,
  results,
};
await mkdir(outputDir, { recursive: true });
await writeFile(join(outputDir, 'local-decisions.jsonl'), events.map((event) => JSON.stringify(event)).join('\n') + '\n');
await writeFile(join(outputDir, 'local-decision-probe.json'), JSON.stringify(report, null, 2) + '\n');
console.log(JSON.stringify({
  events: events.length,
  decisions_matched: results.filter((item) => item.decision_match).length,
  off_policy_fetches: results.filter((item) => item.off_policy_fetch).length,
}));
