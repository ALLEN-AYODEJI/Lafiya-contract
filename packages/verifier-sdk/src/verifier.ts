import type { AttesterState, ChainReader, OnChainAttestation } from "./chain.js";
import { commitV1, type FieldValue } from "./commitment.js";
import { parseQrPayload, QrPayloadError, type QrPayload } from "./qr.js";
import { BindingsChainReader } from "./rpc.js";
import {
  verifyForeignAttestation,
  type FederationTrustAnchors,
  type ForeignVerificationFailure,
} from "./trust.js";
import type { TrustAnchors } from "./trust.js";
import { VERDICTS, verdictOf, type Reason, type Verdict } from "./verdict.js";

export interface VerifierOptions {
  /** Network this verifier accepts cards for, e.g. `"testnet"`. */
  network: string;
  trust: TrustAnchors;
  /**
   * Trust anchors for other deployments, keyed by jurisdiction code. When a
   * card names a foreign jurisdiction, verification is delegated to
   * `verifyForeignAttestation` instead of the local chain reader. Omit to
   * behave exactly as a single-deployment verifier.
   */
  federation?: FederationTrustAnchors;
  /** Defaults to reading over RPC with the generated bindings. */
  chain?: ChainReader;
  /** Clock override (tests, offline replays). */
  now?: () => Date;
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
}

const DAY_SECONDS = 86_400n;

/** Map a federation failure onto the shared verdict vocabulary. */
function federationReason(failure: ForeignVerificationFailure): Reason {
  switch (failure.code) {
    case "unknown_jurisdiction":
      return { code: "untrusted_contract", message: failure.message };
    case "stale_anchor":
      return { code: "untrusted_contract", message: failure.message };
    case "signature_mismatch":
      return { code: "commitment_mismatch", message: failure.message };
    case "foreign_registry_unavailable":
      return { code: "unavailable", message: failure.message };
  }
}

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
    const done = (extra: Partial<VerificationResult> = {}): VerificationResult => {
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
    // 1a. Foreign jurisdiction: delegate to the federation trust-anchor check.
    if (payload.jurisdiction !== undefined && payload.jurisdiction !== this.options.network) {
      const federation = this.options.federation;
      if (!federation) {
        reasons.push({
          code: "untrusted_contract",
          message: `card is for jurisdiction "${payload.jurisdiction}", which this verifier does not federate with`,
        });
        return done({ payload });
      }
      const foreign = await verifyForeignAttestation(federation, payload, {
        now: checkedAt,
        ...(opts.disclosedFields ? { disclosedFields: opts.disclosedFields } : {}),
        ...(opts.maxAgeDays !== undefined ? { maxAgeDays: opts.maxAgeDays } : {}),
      });
      if (!foreign.ok) {
        reasons.push(federationReason(foreign.failure));
        return done({ payload });
      }
      return done({
        payload,
        attestation: foreign.attestation,
        attester: foreign.attester,
      });
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
