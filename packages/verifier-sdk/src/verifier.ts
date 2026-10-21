import type { AttesterState, ChainReader, OnChainAttestation } from "./chain.js";
import { commitV1, type FieldValue } from "./commitment.js";
import { parseQrPayload, QrPayloadError, type QrPayload } from "./qr.js";
import { BindingsChainReader } from "./rpc.js";
import type { TrustAnchors } from "./trust.js";
import { VERDICTS, verdictOf, type Reason, type Verdict } from "./verdict.js";

/**
 * How old a snapshot-backed read may be. Applies only to readers that report
 * `snapshotAt`; live RPC reads are never stale.
 */
export interface StalenessPolicy {
  /** Maximum snapshot age in seconds when `riskClass` has no entry. */
  defaultMaxSeconds: number;
  /** Per-risk-class overrides, e.g. `{ emergency: 604800, routine: 86400 }`. */
  byRiskClass?: Record<string, number>;
  /**
   * `"fail"`: a stale snapshot yields `unavailable` whatever it says.
   * `"warn"`: negative verdicts are still reported (they err on the safe
   * side); only a would-be `verified` becomes `unavailable`.
   */
  onStale: "fail" | "warn";
}

/** One day, hard-fail: the default for snapshot-backed readers. */
export const DEFAULT_STALENESS: StalenessPolicy = { defaultMaxSeconds: 86_400, onStale: "fail" };

export interface VerifierOptions {
  /** Network this verifier accepts cards for, e.g. `"testnet"`. */
  network: string;
  trust: TrustAnchors;
  /** Defaults to reading over RPC with the generated bindings. */
  chain?: ChainReader;
  /** Clock override (tests, offline replays). */
  now?: () => Date;
  /** Snapshot staleness limits; defaults to {@link DEFAULT_STALENESS}. */
  staleness?: StalenessPolicy;
}

export interface VerifyOptions {
  /**
   * The disclosed record as LRC-1 fields, in schema order (salt included).
   * When given, the commitment is recomputed and must equal the card's
   * record hash.
   */
  disclosedFields?: readonly FieldValue[];
  /** Reject attestations older than this many days. */
  maxAgeDays?: number;
  /** Selects the {@link StalenessPolicy.byRiskClass} limit. */
  riskClass?: string;
}

export interface VerificationResult {
  verdict: Verdict;
  /** Every problem found (highest precedence first); `[verified]` on success. */
  reasons: Reason[];
  payload?: QrPayload;
  attestation?: OnChainAttestation & { attestedAt: Date };
  attester?: { address: string; status: "active" | "suspended" | "removed"; region?: string };
  checkedAt: Date;
  source: "rpc" | "offline";
  /** When the snapshot behind an offline verdict was captured. */
  staleAsOf?: Date;
}

const DAY_SECONDS = 86_400n;

export class LafiyaVerifier {
  private readonly chain: ChainReader;
  private readonly now: () => Date;

  constructor(private readonly options: VerifierOptions) {
    this.chain = options.chain ?? new BindingsChainReader();
    this.now = options.now ?? (() => new Date());
  }

  /** Verify a scanned QR payload. Never throws: failures are verdicts. */
  async verifyCard(qrPayload: string, opts: VerifyOptions = {}): Promise<VerificationResult> {
    const checkedAt = this.now();
    const reasons: Reason[] = [];
    const policy = this.options.staleness ?? DEFAULT_STALENESS;
    const snapshotAt = this.chain.snapshotAt;
    const maxSeconds =
      (opts.riskClass !== undefined ? policy.byRiskClass?.[opts.riskClass] : undefined) ??
      policy.defaultMaxSeconds;
    const age = snapshotAt === undefined ? 0 : Math.floor(checkedAt.getTime() / 1000) - snapshotAt;
    // A snapshot dated in the future is as untrustworthy as an old one.
    const stale = snapshotAt !== undefined && (age > maxSeconds || age < 0);
    const done = (extra: Partial<VerificationResult> = {}): VerificationResult => {
      if (stale && (policy.onStale === "fail" || verdictOf(reasons) === "verified")) {
        reasons.push({
          code: "unavailable",
          message: `offline snapshot from ${new Date(snapshotAt * 1000).toISOString()} is older than the ${maxSeconds}s limit`,
        });
      }
      const ordered = [...reasons].sort(
        (a, b) => VERDICTS.indexOf(a.code) - VERDICTS.indexOf(b.code),
      );
      const verdict = verdictOf(reasons);
      return {
        verdict,
        reasons:
          verdict === "verified"
            ? [{ code: "verified", message: "attested by a currently trusted attester" }]
            : ordered,
        checkedAt,
        source: this.chain.source,
        ...(snapshotAt !== undefined ? { staleAsOf: new Date(snapshotAt * 1000) } : {}),
        ...extra,
      };
    };

    // 1. Parse, and check the claimed network/contract against trust anchors.
    let payload: QrPayload;
    try {
      payload = parseQrPayload(qrPayload);
    } catch (err) {
      const message = err instanceof QrPayloadError ? err.message : String(err);
      reasons.push({ code: "invalid_payload", message });
      return done();
    }
    const trust = this.options.trust[this.options.network];
    if (payload.network !== this.options.network || !trust) {
      reasons.push({
        code: "untrusted_contract",
        message: `card is for network "${payload.network}", verifier trusts "${this.options.network}"`,
      });
      return done({ payload });
    }
    if (payload.contractId !== trust.attestationRegistry) {
      reasons.push({
        code: "untrusted_contract",
        message: `contract ${payload.contractId} is not the trusted attestation registry`,
      });
      return done({ payload });
    }

    // 2. Recompute the commitment from the disclosed data.
    if (opts.disclosedFields) {
      const commitment = await commitV1(opts.disclosedFields);
      if (commitment !== payload.recordHash) {
        reasons.push({
          code: "commitment_mismatch",
          message: "disclosed fields do not hash to the card's record hash",
        });
        return done({ payload });
      }
    }

    // 3-4. Read the attestation and the attester's *current* status.
    let history: OnChainAttestation[];
    let latest: OnChainAttestation | null;
    let revoked = false;
    let attesterState: AttesterState | null = null;
    try {
      [latest, history] = await Promise.all([
        this.chain.getAttestation(trust, payload.recordHash),
        this.chain.getAttestationHistory(trust, payload.recordHash),
      ]);
      if (!latest) {
        revoked = (await this.chain.isRevoked?.(trust, payload.recordHash)) ?? false;
      } else {
        attesterState = await this.chain.getAttesterStatus(trust, latest.attester);
      }
    } catch (err) {
      reasons.push({ code: "unavailable", message: `chain read failed: ${String(err)}` });
      return done({ payload });
    }

    if (!latest) {
      reasons.push(
        revoked
          ? { code: "revoked", message: "the attestation was revoked" }
          : { code: "not_found", message: "no attestation for this record" },
      );
      return done({ payload });
    }

    // 5. Supersession, attester status, and age.
    if (payload.attestedAt !== undefined && latest.timestamp > payload.attestedAt) {
      reasons.push({
        code: "superseded",
        message: `card shows the attestation from ${payload.attestedAt}, a newer one exists from ${latest.timestamp}`,
      });
    }
    if (!attesterState) {
      reasons.push({ code: "attester_removed", message: `${latest.attester} is not allowlisted` });
    } else if (attesterState.suspended) {
      reasons.push({ code: "attester_suspended", message: `${latest.attester} is suspended` });
    }
    if (opts.maxAgeDays !== undefined) {
      const nowSeconds = BigInt(Math.floor(checkedAt.getTime() / 1000));
      const maxAge = BigInt(Math.floor(opts.maxAgeDays)) * DAY_SECONDS;
      if (nowSeconds - latest.timestamp > maxAge) {
        reasons.push({
          code: "expired",
          message: `attestation is older than ${opts.maxAgeDays} days`,
        });
      }
    }

    // 6. UI-ready result.
    return done({
      payload,
      attestation: { ...latest, attestedAt: new Date(Number(latest.timestamp) * 1000) },
      attester: {
        address: latest.attester,
        status: !attesterState ? "removed" : attesterState.suspended ? "suspended" : "active",
        ...(attesterState?.region ? { region: attesterState.region } : {}),
      },
    });
  }
}
