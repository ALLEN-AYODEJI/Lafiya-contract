# Verifier SDK (`@lafiya/verifier`)

`packages/verifier-sdk/` is the high-level library a verifier app uses to
check a scanned Lafiya card. It wraps the generated
[TypeScript bindings](typescript-bindings.md) and runs every step in one
place, so consumers cannot get a step subtly wrong:

1. Parse the QR payload and check its network and contract IDs against
   **trust anchors**. A contract ID is never trusted just because the QR
   payload names it.
2. Recompute the LRC-1 record commitment from the disclosed fields and
   compare it with the card's record hash.
3. Read the attestation from `attestation-registry`.
4. Read the attester's **current** status from `attester-registry`
   (ADR-0006).
5. Apply revocation, supersession, and maximum-age rules.
6. Return a single UI-ready verdict with ordered reasons.

## Usage

```ts
import { LafiyaVerifier, loadTrustAnchors } from "@lafiya/verifier";

const trust = await loadTrustAnchors({
  domain: "lafiya.example",          // publishes /.well-known/stellar.toml
  network: "testnet",
  rpcUrl: "https://soroban-testnet.stellar.org",
});
const verifier = new LafiyaVerifier({ network: "testnet", trust });

const result = await verifier.verifyCard(qrPayload, { disclosedFields, maxAgeDays: 365 });
// { verdict, reasons[], attestation?, attester?, checkedAt, source }
```

`verifyCard` never throws: RPC and parsing failures become verdicts.

### Cancellation, timeouts, and retries

Every chain read accepts an `AbortSignal` and a per-call deadline:

```ts
const controller = new AbortController();
const result = await verifier.verifyCard(qrPayload, {
  signal: controller.signal, // e.g. aborted when the user leaves the screen
  timeoutMs: 5_000,          // per read attempt
});
if (result.verdict === "unavailable") console.log(result.transportError?.kind);
```

`BindingsChainReader` defaults to a 10 s per-attempt deadline and retries
**reads** (all of its calls are idempotent simulations) at most twice, with
full-jitter exponential backoff (`random() * min(maxDelayMs, baseDelayMs * 2^n)`,
200 ms base, 2 s cap). Configure both with
`new BindingsChainReader({ timeoutMs, retry: { retries, baseDelayMs, maxDelayMs } })`.
An abort cancels the in-flight attempt and any pending backoff; it is never
retried. `callWithPolicy` is exported for integrators' own calls: it only
retries when `idempotent: true` is passed, so ambiguous writes (where the
first attempt may have landed) are never retried.

Custom `ChainReader` implementations receive the same `{ signal, timeoutMs }`
as the last argument of each read and should honour it.

### Transport error taxonomy

Failed reads reject with a `TransportError` (exported, with
`isTransportError(err, kind?)` and `classifyError(err)`); narrow on `kind`:

| `kind` | Meaning | Retried (idempotent reads) |
|---|---|---|
| `network` | No usable answer: connection refused/reset, DNS, HTTP 5xx or 429. | Yes |
| `timeout` | No answer within `timeoutMs`. | Yes |
| `aborted` | The caller's `AbortSignal` fired. | No |
| `protocol` | The server answered with something unusable: malformed response, simulation/contract error, HTTP 4xx. | No |
| `not_found` | The RPC endpoint or contract does not exist (HTTP 404). A missing *attestation* is not an error; it is `null`. | No |
| `untrusted` | Refused before sending because the transport is not trusted (plain HTTP without `allowHttp`). | No |

`error.attempts` is the number of attempts made. In `verifyCard` any of these
becomes the `unavailable` verdict, with the error on `result.transportError`.
The SDK's lint (`pnpm lint`, `@typescript-eslint/no-floating-promises` and
`no-misused-promises`) keeps failure paths free of unhandled rejections, and
the fake-timer tests in `test/transport.test.ts` assert none occur.

### Trust anchors

`loadTrustAnchors` accepts either explicit configuration
(`{ config: { testnet: { networkPassphrase, rpcUrl, attestationRegistry, attesterRegistry } } }`)
or SEP-1 discovery, where the home domain's `stellar.toml` publishes
`NETWORK_PASSPHRASE`, `LAFIYA_ATTESTATION_REGISTRY`, and
`LAFIYA_ATTESTER_REGISTRY`. Invalid anchors raise `TrustError`.

### Offline mode

Pass `chain: new OfflineChainReader(bundle)` to verify from a previously
downloaded bundle of attestations and attester states instead of RPC.
Results then report `source: "offline"`.

## Verdicts

The verdict set is finite and ordered by precedence; when several reasons
apply, the highest-precedence one wins. All reasons are still returned.

| Verdict | Meaning |
|---|---|
| `invalid_payload` | The QR code is not a valid Lafiya card payload. |
| `untrusted_contract` | The payload's network or contract is not in the trust anchors. |
| `commitment_mismatch` | The disclosed record does not match the card's record hash. |
| `unavailable` | The attestation could not be checked (network or RPC failure). |
| `revoked` | The attestation was revoked by the registry admin. |
| `not_found` | No attestation exists for this record. |
| `superseded` | A newer attestation exists than the one on the card. |
| `attester_removed` | The attesting health worker is no longer on the allowlist. |
| `attester_suspended` | The attesting health worker is currently suspended. |
| `expired` | The attestation is older than `maxAgeDays`. |
| `verified` | Attested by a currently trusted health worker. |

Only `verified` should be shown to a user as a pass.

## Localized responder strings

Reason codes such as `attester_suspended` mean nothing to a nurse at 3 a.m.
`localizeVerdict(verdict, locale)` (and `localizeReason(reason, locale)`;
reason codes share the verdict keys) returns plain-language text for
responders in English (`en`), Hausa (`ha`), Yoruba (`yo`), Igbo (`ig`), and
Nigerian Pidgin (`pcm`):

```ts
const text = await localizeVerdict(result.verdict, "ha-NG");
// { title, guidance, action, severity: "ok" | "caution" | "stop",
//   locale, requested, fallback, provenance }
```

- **Lazy loading.** Each locale catalog is its own module under
  `dist/*/locales/`, imported on first use, so the core bundle (and its size
  budget) carries none of them.
- **Deterministic fallback.** An unsupported locale, a missing entry, or (by
  default) an entry without clinical review returns the English text with
  `fallback: true`, so a UI can say so. Pass `{ requireReviewed: false }` only
  for review tooling; never in production clinical screens.
- **Provenance.** Every entry records `status` (`reviewed` /
  `pending_review`), `author`, `reviewer`, and `date`.
- **Coverage lint.** `pnpm lint:i18n` (CI) fails unless every verdict has an
  entry in every locale or an explicit waiver in `i18n/waivers.json`
  (`{ "<locale>": { "<verdict>": "<why>" } }`), flags stale waivers, checks
  provenance, and rejects reason codes leaking into text.

### Review process

The Hausa, Yoruba, Igbo, and Pidgin catalogs ship as **drafts**
(`pending_review`) and are therefore not shown by default. To approve an
entry, a native speaker of the language with clinical experience (nurse,
CHW supervisor, or physician):

1. Checks the text against the English source *and* the verdict definition
   above, for meaning, not word-for-word, and for the action it implies.
2. Reads it aloud: it must be understood at first hearing.
3. Commits the change in `src/locales/<locale>.ts` with the entry's
   `provenance` set to `status: "reviewed"`, their name or handle as
   `reviewer`, and the review date. The lint rejects `reviewed` without a
   reviewer. Any later text change resets the entry to `pending_review`.

### Accessibility

- **Reading level.** Target CEFR A2 / US grade 5: short, common words, one
  idea per sentence, and the next action stated as a command. The lint
  enforces proxies on the English source (titles of at most 5 words,
  sentences of at most 15 words, words of at most 12 letters); translations
  follow the same rules in review.
- **Icon independence.** The text carries the whole meaning: never rely on a
  colour, icon, or sound alone. `severity` (`ok`, `caution`, `stop`) is there
  for screen readers, haptics, and monochrome displays. Only `verified` is
  `ok`. Always show `title` and `action` together.
- **No codes.** Do not show `verdict` or reason codes to responders; log them.

## Example app

`packages/verifier-sdk/example/index.html` is a minimal page that scans a QR
code with the camera (`BarcodeDetector`, with a text-box fallback) and shows
the verdict. Build the package, serve the **repository root** (the import map
resolves the bindings from `/bindings/`), and open
`/packages/verifier-sdk/example/`.

## Development

```sh
cd packages/verifier-sdk
pnpm install
pnpm typecheck && pnpm lint && pnpm test && pnpm build && pnpm size
pnpm lint:i18n       # catalog coverage, provenance, reading level (after build)
pnpm check:package   # publint + are-the-types-wrong on the packed tarball
pnpm smoke           # install the packed tarball; import from ESM, CJS, bundler, worker
```

Supported runtimes and minimum versions are in the package
[README](../packages/verifier-sdk/README.md#compatibility); `pnpm smoke`
fails if that table and the tested targets drift apart.

- Unit tests use a mocked chain reader; `test/verifier.test.ts` includes a
  truth table covering every verdict.
- `test/integration.test.ts` runs against a local quickstart with real
  contracts when `LAFIYA_IT_RPC_URL`, `LAFIYA_IT_ATTESTATION_REGISTRY`,
  `LAFIYA_IT_ATTESTER_REGISTRY`, and `LAFIYA_IT_RECORD_HASH` are set, and is
  skipped otherwise.
- `pnpm size` enforces the gzipped core bundle budget (12 KiB, locale
  catalogs excluded) in CI.
